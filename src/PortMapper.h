//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
//

#ifndef PORTMAPPER_H
#define PORTMAPPER_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Self-contained automatic port-forwarding helper.
//
// Implements NAT-PMP (RFC 6886) and PCP MAP (RFC 6887) clients with no
// external library dependency, complementing aMule's optional UPnP IGD
// support. A single background thread performs the initial mapping and
// then renews the (finite) leases on schedule, re-detecting the default
// gateway each cycle so the mappings survive router reboots, lease
// expiry and network changes.
//
// PCP is attempted first; if the gateway does not answer PCP (no reply,
// ICMP port-unreachable, or an "unsupported version" result) the request
// falls back to NAT-PMP. The protocol that last succeeded is preferred on
// subsequent calls to avoid re-probing.
//
// This class deliberately depends only on the C++ standard library and
// the platform socket API (no wxWidgets / aMule headers) so it can be
// reasoned about and unit-compiled in isolation. Logging and the public
// IP notification are delivered through optional callbacks.
class CPortMapper
{
public:
	enum Protocol
	{
		PROTO_TCP,
		PROTO_UDP
	};

	CPortMapper();
	~CPortMapper();

	// Register a port to forward. Must be called before Start().
	void AddMapping(uint16_t internalPort, Protocol proto, const std::string &description);

	// Install a logging sink. Invoked from the worker thread, so the sink
	// must be thread-safe. Optional.
	void SetLogger(std::function<void(const std::string &)> logger);

	// Sink for the discovered external (public) IPv4 address in host byte
	// order. Invoked from the worker thread whenever a fresh value is
	// learned. Optional.
	void SetExternalIPCallback(std::function<void(uint32_t)> cb);

	// Launch the worker thread (no-op if already running or if no mappings
	// were registered).
	void Start();

	// Stop the worker thread and remove the mappings we created (best
	// effort). Safe to call multiple times and from the destructor.
	void Stop();

	// True if at least one mapping is currently believed to be active.
	bool IsActive() const { return m_active.load(); }

private:
	struct Mapping
	{
		uint16_t internalPort = 0;
		// Preferred / last-assigned external port. Seeded equal to the
		// internal port and updated if the gateway assigns a different one,
		// so renewals keep requesting the same external port.
		uint16_t externalPort = 0;
		Protocol proto = PROTO_TCP;
		std::string description;
		bool mapped = false; // last attempt succeeded
		bool usedPcp = false; // last success was via PCP (delete needs nonce)
		uint8_t pcpNonce[12] = {0};
	};

	enum Method
	{
		METHOD_PCP,
		METHOD_NATPMP
	};

	void ThreadEntry();
	void Log(const std::string &msg);

	// Returns the lease granted in seconds on success, 0 on failure.
	uint32_t MapOne(uint32_t gatewayHost, Mapping &m, uint32_t requestedLease);
	void UnmapOne(uint32_t gatewayHost, Mapping &m);

	std::vector<Mapping> m_mappings;
	std::function<void(const std::string &)> m_logger;
	std::function<void(uint32_t)> m_extIpCb;

	std::thread m_thread;
	std::mutex m_mutex;
	std::condition_variable m_cv;
	std::atomic<bool> m_stop;
	std::atomic<bool> m_active;
	bool m_started = false;
	Method m_preferred = METHOD_PCP;
};

#endif // PORTMAPPER_H
// File_checked_for_headers
