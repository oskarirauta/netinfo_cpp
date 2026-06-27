#include <iostream>
#include "netinfo.hpp"

int main() {

	std::cout << "netinfo test\n" <<
		"author: Oskari Rauta <oskari.rauta@gmail.com>\n" <<
		"license: MIT" << std::endl;

	std::map<std::string, netinfo::device> devices = netinfo::get_devices();

	// the whole picture: every interface streamed out
	for ( const auto& [name, dev] : devices )
		std::cout << "\n" << dev << std::endl;

	// convenience queries
	std::cout << "\n--- queries ---" << std::endl;
	for ( const auto& [name, dev] : devices )
		std::cout << name
			<< ": up=" << dev.up()
			<< " running=" << dev.has_flag("RUNNING")
			<< " loopback=" << dev.has_flag("LOOPBACK") << std::endl;

	// a single interface by name
	if ( !devices.empty()) {

		std::string first = devices.begin() -> first;
		std::cout << "\nhas_device(\"" << first << "\") = " << netinfo::has_device(first) << "\n"
			<< "get_device(\"" << first << "\").up() = " << netinfo::get_device(first).up() << std::endl;
	}

	std::cout << std::endl;
	return 0;
}
