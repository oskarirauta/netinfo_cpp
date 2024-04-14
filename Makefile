all: world

CXX?=g++
CXXFLAGS?=--std=c++17 -Wall -fPIC -g

OBJS:= \
	objs/main.o

NETINFO_DIR:=.
include common/Makefile.inc
include throws/Makefile.inc
include logger/Makefile.inc
include ./Makefile.inc

world: example

$(shell mkdir -p objs)

objs/main.o: main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

example: $(COMMON_OBJS) $(THROWS_OBJS) $(LOGGER_OBJS) $(NETINFO_OBJS) $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

.PHONY: clean
clean:
	@rm -rf objs example
