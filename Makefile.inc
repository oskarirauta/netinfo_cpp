NETINFO_DIR?=netinfo
INCLUDES += -I./$(NETINFO_DIR)/include

IPV6?=1

CXXFLAGS+= \
	-DIPV6=$(IPV6)

NETINFO_OBJS:= \
	objs/netinfo.o

objs/netinfo.o: $(NETINFO_DIR)/src/netinfo.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;
