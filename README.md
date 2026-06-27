[![License:MIT](https://img.shields.io/badge/License-MIT-blue?style=plastic)](LICENSE)
[![C++ CI build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

### netinfo_cpp

Small C++ library for reading `ip` / `ifconfig` like information about the
network interfaces of a Linux system.

## <sub>Usage</sub>

`netinfo::get_devices()` returns a `std::map<std::string, netinfo::device>`
keyed by interface name. There are also helpers for a single interface:

```cpp
#include <iostream>
#include "netinfo.hpp"

int main() {

    // every interface
    for ( const auto& [name, dev] : netinfo::get_devices())
        std::cout << dev << "\n";              // ifconfig-like dump

    // one interface (throws if it does not exist)
    if ( netinfo::has_device("eth0")) {
        netinfo::device eth0 = netinfo::get_device("eth0");
        std::cout << "eth0 up: " << eth0.up()
                  << " running: " << eth0.has_flag("RUNNING") << "\n";
    }
    return 0;
}
```

Streaming a `device` (or an `addr4` / `addr6`) to an `std::ostream` gives an
ifconfig-like summary - a good way to see everything that is available.

### device

Fields: `name`, `encap`, `operstate`, `hwaddr`, `mtu`, `flags`
(`std::map<unsigned long int, flag>`), `ipv4` (`std::vector<addr4>`), `ipv6`
(`std::vector<addr6>`, only when IPv6 is enabled) and `rx` / `tx` (`stats`).

Convenience methods:
 - `up()` - is the interface operationally up (`operstate == "UP"`)
 - `has_flag("RUNNING")` / `has_flag(IFF_RUNNING)` - is a given flag set

`addr4` carries `addr`, `netmask`, `cidrmask`, `broadcast` (when the interface
has one), `hwaddr` and `index`; `addr6` carries `addr`, `prefix` and `scope`.
`stats` carries `bytes`, `packets`, `errors`, `dropped` plus `KiB()` / `MiB()` /
`GiB()` helpers.

## <sub>Functions</sub>

 - `netinfo::get_devices()` - all interfaces, as a map
 - `netinfo::get_device(name)` - a single interface (throws if not found)
 - `netinfo::has_device(name)` - does the interface exist

## <sub>IPv6</sub>

IPv6 is included by default; build with `IPV6=0 make` to leave it out (the
`ipv6` members and the `addr6` type are then compiled out). This also works for
projects that import the library.

## <sub>Dependencies</sub>

 - [throws_cpp](https://github.com/oskarirauta/throws_cpp.git)
 - [common_cpp](https://github.com/oskarirauta/common_cpp.git)
 - [logger_cpp](https://github.com/oskarirauta/logger_cpp.git)

## <sub>Importing</sub>

 - import the dependencies into `throws`, `common` and `logger` sub directories
 - import this library into a `netinfo` sub directory
 - include the `Makefile.inc` of all four libraries
 - create an `objs` directory at the root of your project
 - add `$(THROWS_OBJS)`, `$(COMMON_OBJS)`, `$(LOGGER_OBJS)` and `$(NETINFO_OBJS)`
   as requirements for your program

The paths are configurable - check each `Makefile.inc`. The provided example is
a good starting point. Requires Linux and a C++17 (or newer) compiler.

## <sub>Example</sub>

Runnable example code is in [`main.cpp`](main.cpp).
