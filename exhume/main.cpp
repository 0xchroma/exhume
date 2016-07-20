#include <windows.h>
#include <string>
#include <memory>
#include <iostream>

#include "exhume.h"


int main(int argc, char* argv[])
{
	auto example_parser = std::make_shared<exhume>("c:/temp/test32static.exe");

	std::vector<unsigned char> test_data(0x200, 0xFF);
	example_parser->AddSection(".test", test_data);

	example_parser->SerialiseImage("c:/temp/test32static_modified.exe");

	std::cin.ignore();
	return 0;
}