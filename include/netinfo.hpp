#pragma once

#include <ostream>
#include <string>
#include <vector>
#include <map>

#include <sys/ioctl.h>
#include <net/if.h>

#ifndef IFF_NO_CARRIER
#define IFF_NO_CARRIER 0x0040
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#ifndef IFF_DORMANT
#define IFF_DORMANT 0x20000
#endif

#ifndef IFF_ECHO
#define IFF_ECHO 0x40000
#endif

namespace netinfo {

	struct flag {

		bool active;
		unsigned long int id;
		std::string name;

		inline operator bool() const {
			return this -> active;
		}

		inline operator std::string() const {
			return this -> name;
		}

		inline flag& operator =(bool active) {
			this -> active = active;
			return *this;
		}

		inline bool operator ==(bool b) const {
			return this -> active == b;
		}

		static std::map<unsigned long int, flag> flags();
		static unsigned long int name_to_flag(const std::string& name);
	};

	struct device {

		struct stats {

			unsigned long int bytes;
			unsigned long int packets;
			unsigned long int errors;
			unsigned long int dropped;

			double KiB() const;
			double MiB() const;
			double GiB() const;
		};

		struct addr4 {
			int index;
			std::string addr;
			std::string netmask;
			std::string cidrmask;
			std::string broadcast;
			std::string hwaddr;

			bool has_broadcast = false;
		};

#if IPV6 != 0
		struct addr6 {
			std::string addr;
			std::string prefix;
			std::string scope;

			bool operator ==(const addr6& other) const;
		};
#endif

		std::string name;
		std::string encap;
		std::string operstate;
		std::string hwaddr;
		int mtu;
		std::map<unsigned long int, flag> flags = flag::flags();
		std::vector<addr4> ipv4;
#if IPV6 != 0
		std::vector<addr6> ipv6;
#endif

		stats rx;
		stats tx;
	};

	std::map<std::string, device> get_devices();

} // end of namespace netinfo

#if IPV6 != 0
std::ostream& operator <<(std::ostream& os, const netinfo::device::addr6& a);
#endif

std::ostream& operator <<(std::ostream& os, const netinfo::device::addr4& a);
std::ostream& operator <<(std::ostream& os, const netinfo::device& d);
