#include <filesystem>
#include <functional>
#include <algorithm>
#include <utility>
#include <fstream>
#include <cstring>
#include <cmath>

#include <netdb.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <unistd.h>

#include "throws.hpp"
#include "common.hpp"
#include "logger.hpp"
#include "netinfo.hpp"

std::map<unsigned long int, netinfo::flag> netinfo::flag::flags() {

	return {
		{ IFF_UP, { .active = false, .id = IFF_UP, .name = "UP" }},
		{ IFF_BROADCAST, { .active = false, .id = IFF_BROADCAST, .name = "BROADCAST" }},
		{ IFF_DEBUG, { .active = false, .id = IFF_DEBUG, .name = "DEBUG" }},
		{ IFF_LOOPBACK, { .active = false, .id = IFF_LOOPBACK, .name = "LOOPBACK" }},
		{ IFF_POINTOPOINT, { .active = false, .id = IFF_POINTOPOINT, .name = "POINTOPOINT" }},
		{ IFF_RUNNING, { .active = false, .id = IFF_RUNNING, .name = "RUNNING" }},
		{ IFF_NOARP, { .active = false, .id = IFF_NOARP, .name = "NOARP" }},
		{ IFF_PROMISC, { .active = false, .id = IFF_PROMISC, .name = "PROMISC" }},
		{ IFF_NOTRAILERS, { .active = false, .id = IFF_NOTRAILERS, .name = "NOTRAILERS" }},
		{ IFF_ALLMULTI, { .active = false, .id = IFF_ALLMULTI, .name = "ALLMULTI" }},
		{ IFF_MASTER, { .active = false, .id = IFF_MASTER, .name = "MASTER" }},
		{ IFF_SLAVE, { .active = false, .id = IFF_SLAVE, .name = "SLAVE" }},
		{ IFF_MULTICAST, { .active = false, .id = IFF_MULTICAST, .name = "MULTICAST" }},
		{ IFF_PORTSEL, { .active = false, .id = IFF_PORTSEL, .name = "PORTSEL" }},
		{ IFF_AUTOMEDIA, { .active = false, .id = IFF_AUTOMEDIA, .name = "AUTOMEDIA" }},
		{ IFF_DYNAMIC, { .active = false, .id = IFF_DYNAMIC, .name = "DYNAMIC" }},
		{ IFF_LOWER_UP, { .active = false, .id = IFF_LOWER_UP, .name = "LOWER_UP" }},
		{ IFF_DORMANT, { .active = false, .id = IFF_DORMANT, .name = "DORMANT" }},
		{ IFF_ECHO, { .active = false, .id = IFF_ECHO, .name = "ECHO" }},
		{ IFF_NO_CARRIER, { .active = false, .id = IFF_NO_CARRIER, .name = "NO_CARRIER" }},
	};
}

unsigned long int netinfo::flag::name_to_flag(const std::string& name) {

	for ( const auto& [k, v] : netinfo::flag::flags())
		if ( common::to_upper(std::as_const(name)) == common::to_upper(std::as_const(v.name)))
			return v.id;

	throws << "cannot convert " << name << " to flag, unknown flag name" << std::endl;
}

double netinfo::device::stats::KiB() const {

	return common::to_KiB(this -> bytes);
}

double netinfo::device::stats::MiB() const {

	return common::to_MiB(this -> bytes);
}

double netinfo::device::stats::GiB() const {

	return common::to_GiB(this -> bytes);
}

#if IPV6 != 0

bool netinfo::device::addr6::operator ==(const netinfo::device::addr6& other) const {

	return this -> addr == other.addr && this -> prefix == other.prefix && this -> scope == other.scope;
}

#endif

static std::string clean_up(const std::string& line) {

	std::string s = common::trim_ws(line);
	std::string r;

	for ( const std::string::value_type& c : s ) {

		std::string::value_type ch = c;
		if ( common::whitespace.find_first_of(ch) != std::string::npos )
			ch = ' ';

		if ( ch == ' ' && r.back() == ' ' )
			continue;

		r += ch;
	}

	return common::trim_ws(r);
}

static unsigned long int to_number(const std::string& s) {

	unsigned long int res = 0;

	if ( s.empty()) {

		logger::warning["netinfo"] << "cannot convert emptry string to number value" << std::endl;
	} else if ( s.find_first_not_of("1234567890") != std::string::npos ) {

		logger::warning["netinfo"] << "cannot convert '" << s << "' to number, all characters are not numbers" << std::endl;

	} else {

		try {
			res = std::stoul(s);
		} catch ( const std::exception& e ) {
			res = 0;
			logger::error["netinfo"] << "failed to converts to '" << s << "' to number value" << std::endl;
		}
	}

	return res;
}

#if IPV6 != 0

static std::string translate_scope(sockaddr_in6* sin) {

	if ( IN6_IS_ADDR_LINKLOCAL((unsigned char*)&(sin -> sin6_addr)))
		return "link-local";
	if ( IN6_IS_ADDR_SITELOCAL((unsigned char*)&(sin -> sin6_addr)))
		return "site-local";
	if ( IN6_IS_ADDR_V4MAPPED((unsigned char*)&(sin -> sin6_addr)))
		return "v4mapped";
	if ( IN6_IS_ADDR_V4COMPAT((unsigned char*)&(sin -> sin6_addr)))
		return "v4compat";
	if ( IN6_IS_ADDR_LOOPBACK((unsigned char*)&(sin -> sin6_addr)))
		return "host";
	if ( IN6_IS_ADDR_UNSPECIFIED((unsigned char*)&(sin -> sin6_addr)))
		return "unspecified";
	else return "global";
}

static std::string translate_prefix(sockaddr_in6* netmask) {

	unsigned char n = 0, *c = netmask -> sin6_addr.s6_addr;
	int i = 0, j = 0;

	while ( i < 16 ) {

		n = c[i++];
		while ( n > 0 ) {
			if ( n & 1 ) j++;
			n /= 2;
		}
	}

	return std::to_string(j);
}

#endif

bool flags_is_empty(const std::map<unsigned long int, netinfo::flag>& flags) {

	for ( const auto& [k, v] : flags )
		if ( v.active )
			return true;

	return false;
}

void clear_flags(netinfo::device *ifd) {

	for ( const auto& [k, v] : ifd -> flags )
		ifd -> flags[k] = false;
}

static void update_flags(short flags, netinfo::device* ifd) {

	if ( ifd -> operstate != "UP" ) {
		if ( flags & IFF_UP ) {
			ifd -> operstate = flags & IFF_RUNNING ? "UP" : "DOWN";
		}
	}

	if ( flags & IFF_UP ) ifd -> flags[IFF_UP] = true;
	if ( flags & IFF_BROADCAST ) ifd -> flags[IFF_BROADCAST] = true;
	if ( flags & IFF_DEBUG ) ifd -> flags[IFF_DEBUG] = true;
	if ( flags & IFF_LOOPBACK ) ifd -> flags[IFF_LOOPBACK] = true;
	if ( flags & IFF_POINTOPOINT ) ifd -> flags[IFF_POINTOPOINT] = true;
	if ( flags & IFF_RUNNING ) ifd -> flags[IFF_RUNNING] = true;
	if ( flags & IFF_NOARP ) ifd -> flags[IFF_NOARP] = true;
	if ( flags & IFF_PROMISC ) ifd -> flags[IFF_PROMISC] = true;
	if ( flags & IFF_NOTRAILERS ) ifd -> flags[IFF_NOTRAILERS] = true;
	if ( flags & IFF_ALLMULTI ) ifd -> flags[IFF_ALLMULTI] = true;
	if ( flags & IFF_MASTER ) ifd -> flags[IFF_MASTER] = true;
	if ( flags & IFF_SLAVE ) ifd -> flags[IFF_SLAVE] = true;
	if ( flags & IFF_MULTICAST ) ifd -> flags[IFF_MULTICAST] = true;
	if ( flags & IFF_PORTSEL ) ifd -> flags[IFF_PORTSEL] = true;
	if ( flags & IFF_AUTOMEDIA ) ifd -> flags[IFF_AUTOMEDIA] = true;
	if ( flags & IFF_DYNAMIC ) ifd -> flags[IFF_DYNAMIC] = true;
	if ( flags & IFF_LOWER_UP ) ifd -> flags[IFF_LOWER_UP] = true;
	if ( flags & IFF_DORMANT ) ifd -> flags[IFF_DORMANT] = true;
	if ( flags & IFF_ECHO ) ifd -> flags[IFF_ECHO] = true;
	if (( flags & IFF_UP ) && !( flags & IFF_RUNNING ))  ifd -> flags[IFF_NO_CARRIER] = true;
}

static void translate_flags(short flags, netinfo::device* ifd) {

	clear_flags(ifd);

	if ( flags & IFF_UP )
		ifd -> operstate = flags & IFF_RUNNING ? "UP" : "DOWN";
	else ifd -> operstate = "DOWN";

	update_flags(flags, ifd);
}

static std::string translate_encap(short e) { // if_arp.h

	switch ( e ) {
		case 0: return "netrom";
		case 1: return "ether";
		case 2: return "eether";
		case 3: return "ax25";
		case 4: return "pronet";
		case 5: return "chaos";
		case 6: return "ieee802";
		case 7: return "arcnet";
		case 8: return "appletalk";
		case 15: return "dlci";
		case 19: return "atm";
		case 23: return "metricom";
		case 24: return "ieee1394";
		case 27: return "eui64";
		case 32: return "infiniband";
		case 256: return "slip";
		case 257: return "cslip";
		case 258: return "slip6";
		case 259: return "cslip6";
		case 260: return "rsrvd";
		case 264: return "adapt";
		case 270: return "rose";
		case 271: return "x25";
		case 272: return "hwx25";
		case 280: return "can";
		case 512: return "ppp";
		case 513: return "cisco";
		case 516: return "lapb";
		case 517: return "ddcmp";
		case 518: return "rawhdlc";
		case 768: return "tunnel";
		case 769: return "tunnel6";
		case 770: return "frad";
		case 771: return "skip";
		case 772: return "loopback";
		case 773: return "localtlk";
		case 774: return "fddi";
		case 775: return "bif";
		case 776: return "sit";
		case 777: return "ipddp";
		case 778: return "ipgre";
		case 779: return "pimreg";
		case 780: return "hippi";
		case 781: return "ash";
		case 782: return "econet";
		case 783: return "irda";
		case 784: return "fcpp";
		case 785: return "fcal";
		case 786: return "fcpl";
		case 787: return "fcfabric";
		case 800: return "ieee802_tr";
		case 801: return "ieee80211";
		case 802: return "ieee80211_prism";
		case 803: return "ieee80211_radiotap";
		case 804: return "ieee802154";
		case 805: return "ieee802154_monitor";
		case 820: return "phonet";
		case 821: return "phonet_pipe";
		case 822: return "caif";
		case 823: return "ip6gre";
		default: return "unspec";
	}
}

static void proc_parse(std::map<std::string, netinfo::device>* devices) {

	for ( const auto& [k, v] : *devices ) {
		(*devices)[k].rx = { .bytes = 0, .packets = 0, .errors = 0, .dropped = 0 };
		(*devices)[k].tx = { .bytes = 0, .packets = 0, .errors = 0, .dropped = 0 };
	}

	if ( !std::filesystem::exists("/proc/net/dev")) {

		logger::error["netinfo"] << "failed to access /proc/net/dev" << std::endl;
		return;
	}

	std::fstream fd("/proc/net/dev", std::ios::in);

	if ( !fd.good()) {

		if ( fd.is_open())
			fd.close();

		logger::error["netinfo"] << "failed to read /proc/net/dev" << std::endl;
		return;
	}

	std::string line, name;

	while ( std::getline(fd, line)) {

		line = common::trim_ws(line);

		if ( common::has_prefix(line, "Inter-|") || common::has_prefix(line, "face |"))
			continue;

		size_t pos;
		if ( pos = line.find_first_of(':'); pos == std::string::npos )
			continue;

		name = line.substr(0, pos);

		#if __cplusplus >= 202002L
		if ( !devices -> contains(name))
			continue;
		#else
		if ( auto contains = devices -> find(name); contains == devices -> end())
			continue;
		#endif

		line.erase(0, pos + 1);
		line = clean_up(line);

		std::vector<std::string> vec;
		while (( pos = line.find_first_of(' ')) != std::string::npos ) {

			vec.push_back(line.substr(0, pos));
			line.erase(0, pos + 1);

			if ( line.empty())
				break;
		}

		if ( !line.empty()) {

			line = common::trim_ws(line);
			if ( !line.empty())
				vec.push_back(line);
		}

		if ( vec.size() != 16 ) continue;

		(*devices)[name].rx = { .bytes = to_number(vec[0]), .packets = to_number(vec[1]), .errors = to_number(vec[2]), .dropped = to_number(vec[3])};
		(*devices)[name].tx = { .bytes = to_number(vec[8]), .packets = to_number(vec[9]), .errors = to_number(vec[10]), .dropped = to_number(vec[11])};
	}

	fd.close();
}

std::map<std::string, netinfo::device> netinfo::get_devices() {

	ifaddrs *interfaces;
	if ( ::getifaddrs(&interfaces) == -1 )
		throws << "failed to retrieve interfaces" << std::endl;

	std::map<std::string, netinfo::device> devices;

	for ( ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa -> ifa_next ) {

		std::string name = ifa -> ifa_name;

#if IPV6 == 0
		if ( ifa -> ifa_addr == nullptr ||
			( ifa -> ifa_addr -> sa_family != AF_INET && ifa -> ifa_addr -> sa_family != AF_PACKET ))
			continue;
#else
		if ( ifa -> ifa_addr == nullptr || ( ifa -> ifa_addr -> sa_family != AF_PACKET &&
			ifa -> ifa_addr -> sa_family != AF_INET && ifa -> ifa_addr -> sa_family != AF_INET6 ))
			continue;
#endif

		netinfo::device ifd;
		netinfo::device::addr4 ipv4;
		int index4 = -1;

		if ( auto pos = name.find_first_of(':'); pos != std::string::npos ) {

			if ( name.size() > pos + 1 && std::isdigit(name[pos + 1])) {

				std::string idx = name.substr(pos + 1, sizeof(name) - pos);
				if ( idx.find_first_not_of("1234567890") != std::string::npos ) {

					logger::error["netinfo"] << "index parse failure from '" << name << "'" << std::endl;
					continue;

				} else {
					try {
						ipv4.index = std::stoi(idx);
					} catch ( const std::exception& e ) {
						logger::error["netinfo"] << "index parse failure from '" << name << "'" << std::endl;
						continue;
					}
				}
				name = name.substr(0, pos);
			} else {
				logger::error["netinfo"] << "index parse failure from '" << name << "'" << std::endl;
				continue;
			}

		} else ipv4.index = 0;

		#if __cplusplus >= 202002L
		if ( !devices.contains(name))
			ifd = devices[name];
		else ifd.name = name;
		#else
		if ( auto contains = devices.find(name); contains != devices.end())
			ifd = devices[name];
		else ifd.name = name;
		#endif

		if ( name.empty() || std::string(ifa -> ifa_name).empty()) {

			logger::warning["netinfo"] << "ignoring empty interface name, strange, this sould not be possible" << std::endl;
			continue;
		}

		if ( auto pos = std::find_if(ifd.ipv4.begin(), ifd.ipv4.end(),
			[&ipv4](const netinfo::device::addr4& addr) { return addr.index == ipv4.index; });
			pos != ifd.ipv4.end()) {

			index4 = pos - ifd.ipv4.begin();
			ipv4 = ifd.ipv4[index4];

		} else {
			index4 = -1;
			clear_flags(&ifd);
		}

		if ( ifa -> ifa_addr == nullptr ) {

			logger::error["netinfo"] << "failed to retrieve data for interface " << ifa -> ifa_name <<
							", ifa_addr is null" << std::endl;
			continue;
		}

		int sock;
		ifreq ifr;
		::strcpy(ifr.ifr_name, ifa -> ifa_name);

		if ( sock = ::socket(ifa -> ifa_addr -> sa_family == AF_PACKET ? AF_INET : ifa -> ifa_addr -> sa_family,
			SOCK_DGRAM, IPPROTO_IP); sock < 0 ) {

			logger::error["netinfo"] << "failed to open socket for " << ifa -> ifa_name << std::endl;
			continue;
		}

		if ( ifa -> ifa_addr -> sa_family == AF_INET ) {

			if ( ioctl(sock, SIOCGIFADDR, &ifr) < 0 ) {

				char host[NI_MAXHOST];

				if ( ::getnameinfo(ifa -> ifa_addr, sizeof(sockaddr_in), host,
						NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) != 0 ) {
					logger::error["netinfo"] << "failed to get ipv4 address for " << ifa -> ifa_name << std::endl;
				} else {
					logger::warning["netinfo"] << "failed to get ipv4 address for " << ifa -> ifa_name <<
						" with primary method" << std::endl;
					ipv4.addr = host;
				}

			} else ipv4.addr = inet_ntoa(((sockaddr_in*)&ifr.ifr_addr) -> sin_addr);

			if ( ipv4.addr.empty()) {

				::close(sock);
				continue;
			}

			if ( ioctl(sock, SIOCGIFMTU, &ifr) < 0 )
				logger::error["netinfo"] << "failed to get mtu for " << ifa -> ifa_name << std::endl;
			else ifd.mtu = ifr.ifr_mtu;

			if ( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 )
				logger::error["netinfo"] << "failed to get mac address for " << ifa -> ifa_name << std::endl;
			else {
				for ( size_t i = 0; i < 6; ++i )
					ipv4.hwaddr += ( ipv4.hwaddr.empty() ? "" : ":" ) + common::to_hex((unsigned char)ifr.ifr_addr.sa_data[i], 2);

				ifd.encap = translate_encap(ifr.ifr_hwaddr.sa_family);
                        }

			if ( ioctl(sock, SIOCGIFNETMASK, &ifr) < 0 )
				logger::error["netinfo"] << "failed to get netmask for " << ifa -> ifa_name << std::endl;
			else {
				ipv4.netmask = inet_ntoa(((sockaddr_in*)&ifr.ifr_netmask) -> sin_addr);
				long double logval = static_cast<long double>(((sockaddr_in*)&ifr.ifr_netmask) -> sin_addr.s_addr);
				int netlen = (int) std::rint(std::log2f(logval) / std::log2f(2.0));
				ipv4.cidrmask = std::to_string(netlen);
			}

			if ( ipv4.has_broadcast ) {

				if ( ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0 )
					logger::error["netinfo"] << "failed to get broadcast address for " << ifa -> ifa_name << std::endl;
				else
					ipv4.broadcast = inet_ntoa(((sockaddr_in*)&ifr.ifr_broadaddr) -> sin_addr);
			}

			if ( index4 == -1 )
				ifd.ipv4.push_back(ipv4);
			else ifd.ipv4[index4] = ipv4;

			std::sort(ifd.ipv4.begin(), ifd.ipv4.end(), [](auto& a, auto& b) {
				return a.index < b.index;
			});

			if ( !ifd.ipv4.empty())
				ifd.hwaddr = ifd.ipv4.front().hwaddr;

		} else if ( ifa -> ifa_addr -> sa_family == AF_PACKET && ifa -> ifa_data == nullptr ) {

			::close(sock);
			continue;

		} else if ( ifa -> ifa_addr -> sa_family == AF_PACKET ) {

			if ( ioctl(sock, SIOCGIFMTU, &ifr) < 0 )
				logger::error["netinfo"] << "failed to get mtu for " << ifa -> ifa_name << std::endl;
			else ifd.mtu = ifr.ifr_mtu;

			if ( ifd.hwaddr.empty()) {

				if ( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 )
					logger::error["netinfo"] << "failed to get mac address for " << ifa -> ifa_name << std::endl;
				else {
					for ( size_t i = 0; i < 6; ++i )
						ifd.hwaddr += ( ifd.hwaddr.empty() ? "" : ":" ) + common::to_hex((unsigned char)ifr.ifr_addr.sa_data[i], 2);

					if ( ifd.encap.empty())
						ifd.encap = translate_encap(ifr.ifr_hwaddr.sa_family);
				}
			}
#if IPV6 != 0
		} else if ( ifa -> ifa_addr -> sa_family == AF_INET6 ) {

			netinfo::device::addr6 ipv6;
			char a[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, (void*)&(((sockaddr_in6*)ifa -> ifa_addr) -> sin6_addr), a, sizeof(a));

			ipv6.addr = a;
			ipv6.prefix = translate_prefix(((sockaddr_in6*)ifa -> ifa_netmask));
			ipv6.scope = translate_scope(((sockaddr_in6*)ifa -> ifa_addr));

			if ( std::find_if(ifd.ipv6.begin(), ifd.ipv6.end(),
				[&ipv6](const netinfo::device::addr6& addr) { return addr == ipv6; }) == ifd.ipv6.end())
				ifd.ipv6.push_back(ipv6);
#endif
		}

		if ( ioctl(sock, SIOCGIFFLAGS, &ifr) < 0 )
			logger::error["netinfo"] << "failed to get flags for " << ifa -> ifa_name << std::endl;
		else {

			if ( flags_is_empty(ifd.flags))
				translate_flags(ifr.ifr_flags, &ifd);
			else
				update_flags(ifr.ifr_flags, &ifd);
		}

		::close(sock);

		devices[ifd.name] = ifd;

	}

	freeifaddrs(interfaces);

	proc_parse(&devices);

	return devices;
}


std::ostream& operator <<(std::ostream& os, const netinfo::device::addr4& a) {

	os << "inet " << a.addr << ( a.cidrmask.empty() ? "" : ( "/" + a.cidrmask ));

	if ( !a.netmask.empty())
		os << " netmask " << a.netmask;

	if ( a.has_broadcast && !a.broadcast.empty())
		os << " broadcast " << a.broadcast;

	if ( !a.hwaddr.empty())
		os << " hwaddr " << a.hwaddr;

	os << " index " << a.index;

	return os;
}

#if IPV6 != 0
std::ostream& operator <<(std::ostream& os, const netinfo::device::addr6& a) {

	os << "inet6 " << a.addr;
	if ( !a.prefix.empty())
		os << "/" << a.prefix;

	os << " scope " << a.scope;
	return os;
}
#endif

std::ostream& operator <<(std::ostream& os, const netinfo::device& d) {

	os << d.name << "\tlink/" << d.encap << " state " << d.operstate << " mtu " << d.mtu;

	if ( !d.hwaddr.empty())
		os << " hwaddr " << d.hwaddr;

	os << "\n  \tflags:";
	for ( const auto& f : d.flags )
		if ( f.second )
			os << " " << f.second.name;

	for ( const auto& a : d.ipv4 ) {

		if ( a.addr.empty())
			continue;

		os << "\n  \t" << a;
	}

#if IPV6 != 0
	for ( const auto& a : d.ipv6 ) {

		if ( a.addr.empty())
			continue;

		os << "\n  \t" << a;
	}
#endif

	os << "\n  \tRX packets: " << d.rx.packets << " errors: " << d.rx.errors << " dropped: " << d.rx.dropped;
	os << "\n  \tTX packets: " << d.tx.packets << " errors: " << d.tx.errors << " dropped: " << d.tx.dropped;

	os << "\n  \tRX bytes: " << d.rx.bytes;

	if ( double gib = d.rx.GiB(); gib > 0 ) os << " (" << std::setprecision(1) << std::fixed << gib << " GiB)";
	else if ( double mib = d.rx.MiB(); mib > 0 ) os << " (" << std::setprecision(1) << std::fixed << mib << " MiB)";
	else os << " (" << (unsigned long)d.rx.KiB() << " KiB)";

	os << "  TX bytes: " << d.tx.bytes;

	if ( double gib = d.tx.GiB(); gib > 0 ) os << " (" << std::setprecision(1) << std::fixed << gib << " GiB)";
	else if ( double mib = d.rx.MiB(); mib > 0 ) os << " (" << std::setprecision(1) << std::fixed << mib << " MiB)";
	else os << " (" << (unsigned long)d.rx.KiB() << " KiB)";

	return os;
}
