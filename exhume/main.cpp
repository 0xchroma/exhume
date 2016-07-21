




		#include "exhume.h"

		std::vector<unsigned char> section_data =
		{
			0xC8, 0x08, 0x00, 0x00,			// enter 0x8, 0x0
			0xb8, 0xBE, 0xBA, 0xFE, 0xCA,	// mov eax, 0xcafebabe (offset 0x5)
			0xFF, 0xE0,						// jmp eax
			0xC9,							// leave
			0xC3							// ret
		};

		int main(int argc, char* argv[])
		{
			exhume exhume_example("example.exe");

			// Get the original entrypoint and imagebase
			auto imagebase = exhume_example.Imagebase();
			auto entrypoint = imagebase + exhume_example.EntryPoint();

			// Write the entrypoint into the jmp buffer
			memcpy(&section_data[5], &entrypoint, sizeof(uint32_t));

			// Add a new section and set new entrypoint
			exhume_example.AddSection(".jump", section_data);
			exhume_example.EntryPoint(".jump");

			// Flush the modified image to disk and run :)
			exhume_example.SerialiseImage("example_modified.exe");

			return 0;
		}









