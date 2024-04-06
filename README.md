[![License:MIT](https://img.shields.io/badge/License-MIT-blue?style=plastic)](LICENSE)
[![C++ CI build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

### netinfo_cpp
Library for querying ifconfig/ip like data from network interfaces on Linux

## <sub>Usage</sub>
There is only one function available that returns all available (all available for this, not all possibly available) details for every interface on system.
It outputs a map<string, device> where key is name of interface.

Inside that map, you find available details of interface cards, or like in example, you can output it to stream.
Stream output function actually gives a great starting point to see what information is available and how to get it,
if you find it difficult to read the structure from header.

You can omit IPv6 with make_var IPV6=0, like this:
```IPV6=0 make```

This works also when you have imported this library.

## <sub>Depencies</sub>

 - (throws_cpp)[https://github.com/oskarirauta/throws_cpp.git]
 - (common_cpp)[https://github.com/oskarirauta/common_cpp.git]
 - (logger_cpp)[https://github.com/oskarirauta/logger_cpp.git]

## <sub>Importing</sub>

It is relatively easy to import this library to your project; ofcourse it depends on your build system..

 - Import depencies, throws_cpp to throws, common_cpp got common and logger_cpp to logger directories.
 - Import this library to netinfo directory
 - Include Makefile.inc's for all 4 libraries
 - Build your objects or atleast make a empty directory objs, either to physical tree; or in Makefile
 - Add $(THROWS_OBJS), $(COMMON_OBJS), $(LOGGER_OBJS) and $(NETINFO_OBJS) as requirements for your program

Paths can also be changed, there's a variable for that. Check Makefile.inc for every imported library of mine.
Provided example gives a great starter point for this.

If your project uses something whole lot of different, like cmake, you are on your own.. Only build requirement
is that your host is Linux and relatively new compiler, as this uses rather new c++ standard (c++17).

## <sub>Example</sub>

Sample code is provided
