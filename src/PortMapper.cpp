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

#include "PortMapper.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <fstream>
#else // BSD / macOS routing-socket dump
#include <net/if.h>
#include <net/route.h>
#include <sys/sysctl.h>
#endif
#endif

namespace
{

// Both NAT-PMP and PCP listen on UDP port 5351 on the gateway.
const uint16_t kPmpPort = 5351;

// IANA protocol numbers used by PCP.
const uint8_t kIPProtoTCP = 6;
const uint8_t kIPProtoUDP = 17;

#ifdef _WIN32
typedef SOCKET pm_socket_t;
const pm_socket_t kBadSocket = INVALID_SOCKET;
#define PM_CLOSESOCK closesocket
#else
typedef int pm_socket_t;
const pm_socket_t kBadSocket = -1;
#define PM_CLOSESOCK ::close
#endif

bool LastErrorIsConnRefused()
{
#ifdef _WIN32
	return WSAGetLastError() == WSAECONNREFUSED;
#else
	return errno == ECONNREFUSED;
#endif
}

void Put16(uint8_t *p, uint16_t v)
{
	p[0] = static_cast<uint8_t>(v >> 8);
	p[1] = static_cast<uint8_t>(v & 0xff);
}

void Put32(uint8_t *p, uint32_t v)
{
	p[0] = static_cast<uint8_t>(v >> 24);
	p[1] = static_cast<uint8_t>(v >> 16);
	p[2] = static_cast<uint8_t>(v >> 8);
	p[3] = static_cast<uint8_t>(v & 0xff);
}

uint16_t Get16(const uint8_t *p)
{
	return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t Get32(const uint8_t *p)
{
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
	       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// Result of a single request/response exchange.
enum ExchangeResult
{
	EXCHANGE_OK = 0,    // got a reply (length returned via outLen)
	EXCHANGE_TIMEOUT,   // no reply within the retry budget
	EXCHANGE_UNSUPPORTED // ICMP port-unreachable -> protocol not served
};

// Send a datagram to gateway:5351 and wait for the reply, retransmitting
// with an exponentially growing timeout. Uses a connected UDP socket so
// that an ICMP port-unreachable surfaces as a recv/send error and lets us
// fail over to the other protocol quickly instead of waiting the full
// timeout.
ExchangeResult UdpExchange(uint32_t gatewayHost,
	const uint8_t *req,
	size_t reqLen,
	uint8_t *resp,
	size_t respCap,
	int initialTimeoutMs,
	int retries,
	int &outLen)
{
	outLen = 0;

	pm_socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == kBadSocket) {
		return EXCHANGE_TIMEOUT;
	}

	struct sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(kPmpPort);
	addr.sin_addr.s_addr = htonl(gatewayHost);

	if (connect(s, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
		PM_CLOSESOCK(s);
		return EXCHANGE_TIMEOUT;
	}

	int timeout = initialTimeoutMs;
	for (int attempt = 0; attempt <= retries; ++attempt) {
		int sent = static_cast<int>(send(s, reinterpret_cast<const char *>(req), reqLen, 0));
		if (sent < 0) {
			bool refused = LastErrorIsConnRefused();
			PM_CLOSESOCK(s);
			return refused ? EXCHANGE_UNSUPPORTED : EXCHANGE_TIMEOUT;
		}

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		struct timeval tv;
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		int r = select(static_cast<int>(s) + 1, &rfds, NULL, NULL, &tv);
		if (r > 0 && FD_ISSET(s, &rfds)) {
			int n = static_cast<int>(recv(s, reinterpret_cast<char *>(resp), respCap, 0));
			if (n <= 0) {
				bool refused = LastErrorIsConnRefused();
				PM_CLOSESOCK(s);
				return refused ? EXCHANGE_UNSUPPORTED : EXCHANGE_TIMEOUT;
			}
			outLen = n;
			PM_CLOSESOCK(s);
			return EXCHANGE_OK;
		}

		timeout *= 2;
	}

	PM_CLOSESOCK(s);
	return EXCHANGE_TIMEOUT;
}

// Discover the local source IPv4 address (host order) used to reach the
// gateway, for the PCP "client IP" field.
bool GetLocalIPForGateway(uint32_t gatewayHost, uint32_t &localHost)
{
	pm_socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == kBadSocket) {
		return false;
	}

	struct sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(kPmpPort);
	addr.sin_addr.s_addr = htonl(gatewayHost);

	if (connect(s, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
		PM_CLOSESOCK(s);
		return false;
	}

	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	if (getsockname(s, reinterpret_cast<struct sockaddr *>(&local), &len) != 0) {
		PM_CLOSESOCK(s);
		return false;
	}

	localHost = ntohl(local.sin_addr.s_addr);
	PM_CLOSESOCK(s);
	return true;
}

// ---- Default-gateway detection (platform specific) ----------------------

#if defined(_WIN32)

bool DetectGateway(uint32_t &gatewayHost)
{
	MIB_IPFORWARDROW row;
	std::memset(&row, 0, sizeof(row));
	// Route towards a public address; the next hop is our default gateway.
	DWORD dest = inet_addr("8.8.8.8");
	if (GetBestRoute(dest, 0, &row) != NO_ERROR) {
		return false;
	}
	if (row.dwForwardNextHop == 0) {
		return false;
	}
	gatewayHost = ntohl(row.dwForwardNextHop);
	return true;
}

#elif defined(__linux__)

bool DetectGateway(uint32_t &gatewayHost)
{
	std::ifstream f("/proc/net/route");
	if (!f.is_open()) {
		return false;
	}

	std::string line;
	std::getline(f, line); // skip header
	while (std::getline(f, line)) {
		char iface[64];
		unsigned long dest = 0;
		unsigned long gw = 0;
		unsigned long flags = 0;
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if (std::sscanf(line.c_str(), "%63s %lx %lx %lx", iface, &dest, &gw, &flags) >= 4) {
			const unsigned long RTF_GATEWAY = 0x0002;
			if (dest == 0 && (flags & RTF_GATEWAY)) {
				// The hex fields hold the in_addr exactly as stored
				// (network byte order), so they are already a valid
				// s_addr on this host's endianness.
				gatewayHost = ntohl(static_cast<uint32_t>(gw));
				return true;
			}
		}
	}
	return false;
}

#else // BSD / macOS: dump the routing table via sysctl(PF_ROUTE)

#if defined(__APPLE__)
#define PM_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#else
#define PM_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

bool DetectGateway(uint32_t &gatewayHost)
{
	int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
	size_t len = 0;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0 || len == 0) {
		return false;
	}

	std::vector<char> buf(len);
	if (sysctl(mib, 6, buf.data(), &len, NULL, 0) < 0) {
		return false;
	}

	char *lim = buf.data() + len;
	for (char *next = buf.data(); next < lim;) {
		struct rt_msghdr *rtm = reinterpret_cast<struct rt_msghdr *>(next);
		if (rtm->rtm_msglen == 0) {
			break;
		}
		next += rtm->rtm_msglen;

		if (!(rtm->rtm_flags & RTF_GATEWAY) || !(rtm->rtm_flags & RTF_UP)) {
			continue;
		}

		char *cp = reinterpret_cast<char *>(rtm + 1);
		struct sockaddr *dst = NULL;
		struct sockaddr *gw = NULL;
		for (int i = 0; i < RTAX_MAX; ++i) {
			if (rtm->rtm_addrs & (1 << i)) {
				struct sockaddr *sa = reinterpret_cast<struct sockaddr *>(cp);
				if (i == RTAX_DST) {
					dst = sa;
				} else if (i == RTAX_GATEWAY) {
					gw = sa;
				}
				cp += PM_ROUNDUP(sa->sa_len);
			}
		}

		if (dst && gw && dst->sa_family == AF_INET && gw->sa_family == AF_INET) {
			struct sockaddr_in *d = reinterpret_cast<struct sockaddr_in *>(dst);
			if (d->sin_addr.s_addr == 0) { // default route (0.0.0.0)
				struct sockaddr_in *g = reinterpret_cast<struct sockaddr_in *>(gw);
				gatewayHost = ntohl(g->sin_addr.s_addr);
				return true;
			}
		}
	}
	return false;
}

#endif // gateway detection

// ---- NAT-PMP (RFC 6886) -------------------------------------------------

struct MapOutcome
{
	bool ok = false;
	bool unsupported = false;
	uint16_t externalPort = 0;
	uint32_t lease = 0;
	bool haveExternalIP = false;
	uint32_t externalIPHost = 0;
};

MapOutcome NatPmpMap(uint32_t gatewayHost,
	uint16_t internalPort,
	uint16_t suggestedExternalPort,
	bool udp,
	uint32_t lease,
	int initialTimeoutMs,
	int retries)
{
	MapOutcome out;

	uint8_t req[12];
	std::memset(req, 0, sizeof(req));
	req[0] = 0;                    // version
	req[1] = udp ? 1 : 2;          // opcode: 1 = map UDP, 2 = map TCP
	Put16(req + 4, internalPort);
	Put16(req + 6, suggestedExternalPort);
	Put32(req + 8, lease);

	uint8_t resp[16];
	int n = 0;
	ExchangeResult er = UdpExchange(
		gatewayHost, req, sizeof(req), resp, sizeof(resp), initialTimeoutMs, retries, n);
	if (er == EXCHANGE_UNSUPPORTED) {
		out.unsupported = true;
		return out;
	}
	if (er != EXCHANGE_OK || n < 16) {
		return out;
	}
	if (resp[0] != 0 || resp[1] != static_cast<uint8_t>(128 + req[1])) {
		return out;
	}
	uint16_t result = Get16(resp + 2);
	if (result != 0) {
		// 5 == "unsupported opcode" -> treat as protocol unavailable.
		if (result == 5) {
			out.unsupported = true;
		}
		return out;
	}
	out.externalPort = Get16(resp + 10);
	out.lease = Get32(resp + 12);
	out.ok = true;
	return out;
}

// Optional: query the external address (NAT-PMP opcode 0).
bool NatPmpExternalAddress(uint32_t gatewayHost, uint32_t &externalIPHost)
{
	uint8_t req[2] = {0, 0};
	uint8_t resp[12];
	int n = 0;
	ExchangeResult er = UdpExchange(gatewayHost, req, sizeof(req), resp, sizeof(resp), 250, 2, n);
	if (er != EXCHANGE_OK || n < 12) {
		return false;
	}
	if (resp[0] != 0 || resp[1] != 128 || Get16(resp + 2) != 0) {
		return false;
	}
	externalIPHost = Get32(resp + 8);
	return true;
}

// ---- PCP MAP (RFC 6887) -------------------------------------------------

void WriteMappedV4(uint8_t *p16, uint32_t ipHost)
{
	std::memset(p16, 0, 16);
	if (ipHost != 0) {
		p16[10] = 0xff;
		p16[11] = 0xff;
		Put32(p16 + 12, ipHost);
	}
}

MapOutcome PcpMap(uint32_t gatewayHost,
	uint16_t internalPort,
	uint16_t suggestedExternalPort,
	bool udp,
	uint32_t lease,
	const uint8_t nonce[12],
	int initialTimeoutMs,
	int retries)
{
	MapOutcome out;

	uint32_t localHost = 0;
	if (!GetLocalIPForGateway(gatewayHost, localHost)) {
		return out;
	}

	uint8_t req[60];
	std::memset(req, 0, sizeof(req));
	// Common request header (24 bytes).
	req[0] = 2;    // version
	req[1] = 0x01; // R=0 (request), opcode=1 (MAP)
	Put32(req + 4, lease);
	WriteMappedV4(req + 8, localHost); // PCP client IP address
	// MAP opcode payload (36 bytes).
	std::memcpy(req + 24, nonce, 12);
	req[36] = udp ? kIPProtoUDP : kIPProtoTCP;
	Put16(req + 40, internalPort);
	Put16(req + 42, suggestedExternalPort);
	WriteMappedV4(req + 44, 0); // no preferred external address

	uint8_t resp[1100];
	int n = 0;
	ExchangeResult er = UdpExchange(
		gatewayHost, req, sizeof(req), resp, sizeof(resp), initialTimeoutMs, retries, n);
	if (er == EXCHANGE_UNSUPPORTED) {
		out.unsupported = true;
		return out;
	}
	if (er != EXCHANGE_OK || n < 60) {
		return out;
	}
	if (resp[0] != 2 || resp[1] != 0x81) { // response to MAP
		return out;
	}
	uint8_t resultCode = resp[3];
	if (resultCode != 0) {
		// 1 == UNSUPP_VERSION -> gateway is NAT-PMP only; fail over.
		if (resultCode == 1) {
			out.unsupported = true;
		}
		return out;
	}
	// Validate the mapping nonce echoes ours.
	if (std::memcmp(resp + 24, nonce, 12) != 0) {
		return out;
	}
	out.lease = Get32(resp + 4);
	out.externalPort = Get16(resp + 42);
	// Assigned external IP (IPv4-mapped) at resp+44..59.
	const uint8_t *eip = resp + 44;
	bool mappedV4 = eip[10] == 0xff && eip[11] == 0xff;
	if (mappedV4) {
		out.haveExternalIP = true;
		out.externalIPHost = Get32(eip + 12);
	}
	out.ok = true;
	return out;
}

void FillRandomNonce(uint8_t nonce[12])
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dist(0, 255);
	for (int i = 0; i < 12; ++i) {
		nonce[i] = static_cast<uint8_t>(dist(gen));
	}
}

} // namespace

// ---- CPortMapper --------------------------------------------------------

CPortMapper::CPortMapper()
: m_stop(false)
, m_active(false)
{
}

CPortMapper::~CPortMapper()
{
	Stop();
}

void CPortMapper::AddMapping(uint16_t internalPort, Protocol proto, const std::string &description)
{
	Mapping m;
	m.internalPort = internalPort;
	m.externalPort = internalPort;
	m.proto = proto;
	m.description = description;
	m_mappings.push_back(m);
}

void CPortMapper::SetLogger(std::function<void(const std::string &)> logger)
{
	m_logger = std::move(logger);
}

void CPortMapper::SetExternalIPCallback(std::function<void(uint32_t)> cb)
{
	m_extIpCb = std::move(cb);
}

void CPortMapper::Log(const std::string &msg)
{
	if (m_logger) {
		m_logger(msg);
	}
}

void CPortMapper::Start()
{
	if (m_started || m_mappings.empty()) {
		return;
	}
	m_started = true;
	m_stop.store(false);
	m_thread = std::thread(&CPortMapper::ThreadEntry, this);
}

void CPortMapper::Stop()
{
	if (!m_started) {
		return;
	}
	{
		std::lock_guard<std::mutex> lk(m_mutex);
		m_stop.store(true);
	}
	m_cv.notify_all();
	if (m_thread.joinable()) {
		m_thread.join();
	}
	m_started = false;
	m_active.store(false);
}

uint32_t CPortMapper::MapOne(uint32_t gatewayHost, Mapping &m, uint32_t requestedLease)
{
	const bool udp = m.proto == PROTO_UDP;

	// Try the last-working protocol first, then the other one.
	Method order[2];
	if (m_preferred == METHOD_NATPMP) {
		order[0] = METHOD_NATPMP;
		order[1] = METHOD_PCP;
	} else {
		order[0] = METHOD_PCP;
		order[1] = METHOD_NATPMP;
	}

	// Try the preferred protocol, then fall back to the other one on any
	// failure. The small cost of a second tiny UDP exchange is worth the
	// extra coverage across heterogeneous routers.
	for (int i = 0; i < 2; ++i) {
		if (order[i] == METHOD_PCP) {
			uint8_t nonce[12];
			FillRandomNonce(nonce);
			MapOutcome o = PcpMap(
				gatewayHost, m.internalPort, m.externalPort, udp, requestedLease, nonce, 250, 2);
			if (o.ok) {
				m_preferred = METHOD_PCP;
				m.externalPort = o.externalPort ? o.externalPort : m.externalPort;
				m.usedPcp = true;
				std::memcpy(m.pcpNonce, nonce, 12);
				if (o.haveExternalIP && o.externalIPHost && m_extIpCb) {
					m_extIpCb(o.externalIPHost);
				}
				return o.lease ? o.lease : requestedLease;
			}
		} else {
			MapOutcome o = NatPmpMap(
				gatewayHost, m.internalPort, m.externalPort, udp, requestedLease, 250, 2);
			if (o.ok) {
				m_preferred = METHOD_NATPMP;
				m.externalPort = o.externalPort ? o.externalPort : m.externalPort;
				m.usedPcp = false;
				if (m_extIpCb) {
					uint32_t extIp = 0;
					if (NatPmpExternalAddress(gatewayHost, extIp) && extIp) {
						m_extIpCb(extIp);
					}
				}
				return o.lease ? o.lease : requestedLease;
			}
		}
	}

	return 0;
}

void CPortMapper::UnmapOne(uint32_t gatewayHost, Mapping &m)
{
	const bool udp = m.proto == PROTO_UDP;
	// A lifetime of 0 removes the mapping. Single short attempt: shutdown
	// must stay snappy, and finite leases expire on their own anyway.
	if (m.usedPcp) {
		PcpMap(gatewayHost, m.internalPort, m.externalPort, udp, 0, m.pcpNonce, 250, 0);
	} else {
		// NAT-PMP delete: suggested external port 0, lifetime 0.
		NatPmpMap(gatewayHost, m.internalPort, 0, udp, 0, 250, 0);
	}
}

void CPortMapper::ThreadEntry()
{
#ifdef _WIN32
	WSADATA wsa;
	bool wsaOk = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#endif

	const uint32_t kLease = 3600; // seconds

	while (!m_stop.load()) {
		uint32_t gateway = 0;
		bool haveGateway = DetectGateway(gateway);

		bool anyOk = false;
		uint32_t minLease = kLease;

		if (haveGateway) {
			struct in_addr a;
			a.s_addr = htonl(gateway);
			char gwStr[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &a, gwStr, sizeof(gwStr));
			std::ostringstream gw;
			gw << "Automatic port mapping: using gateway " << gwStr;
			Log(gw.str());

			for (size_t i = 0; i < m_mappings.size(); ++i) {
				if (m_stop.load()) {
					break;
				}
				Mapping &m = m_mappings[i];
				uint32_t granted = MapOne(gateway, m, kLease);
				m.mapped = granted > 0;
				if (granted > 0) {
					anyOk = true;
					if (granted < minLease) {
						minLease = granted;
					}
					std::ostringstream msg;
					msg << "Automatic port mapping: " << (m.proto == PROTO_UDP ? "UDP " : "TCP ")
					    << m.externalPort << " -> local " << m.internalPort << " ("
					    << (m_preferred == METHOD_PCP ? "PCP" : "NAT-PMP") << ", lease " << granted
					    << "s) [" << m.description << "]";
					Log(msg.str());
				} else {
					std::ostringstream msg;
					msg << "Automatic port mapping: failed for "
					    << (m.proto == PROTO_UDP ? "UDP " : "TCP ") << m.internalPort << " ["
					    << m.description << "]";
					Log(msg.str());
				}
			}
		} else {
			Log("Automatic port mapping: could not determine the default gateway "
			    "(NAT-PMP/PCP unavailable)");
		}

		m_active.store(anyOk);

		// Renew at half the granted lease; retry sooner after a failure.
		uint32_t waitSeconds;
		if (anyOk) {
			waitSeconds = minLease / 2;
			if (waitSeconds < 60) {
				waitSeconds = 60;
			}
		} else {
			waitSeconds = 60;
		}

		std::unique_lock<std::mutex> lk(m_mutex);
		m_cv.wait_for(lk, std::chrono::seconds(waitSeconds), [this] { return m_stop.load(); });
	}

	// Best-effort removal of everything we installed.
	uint32_t gateway = 0;
	if (DetectGateway(gateway)) {
		for (size_t i = 0; i < m_mappings.size(); ++i) {
			if (m_mappings[i].mapped) {
				UnmapOne(gateway, m_mappings[i]);
			}
		}
	}

#ifdef _WIN32
	if (wsaOk) {
		WSACleanup();
	}
#endif
}

// File_checked_for_headers
