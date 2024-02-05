#include <iostream>
#include "netinfo.hpp"

int main(int argc, char **argv) {

	std::cout << "netinfo test\n" <<
		"author: Oskari Rauta <oskari.rauta@gmail.com>\n" <<
		"license: MIT" << std::endl;

	for ( const auto& [k, v] : netinfo::get_devices())
		std::cout << "\n" << v << std::endl;

	std::cout << std::endl;
	return 0;
}
