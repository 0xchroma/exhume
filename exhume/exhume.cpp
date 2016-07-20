#include "exhume.h"

#include <iostream>

exhume::exhume(std::string path)
{
	std::vector<unsigned char> data;

	if (!ReadFile(path, data))
	{
		std::cout << "ERROR: Failed to readfile. WIN32 error: " << ::GetLastError() << std::endl;
		return;
	}

	if (data.size() < sizeof(IMAGE_DOS_HEADER))
		return;

	if (std::string(data.begin(), data.end()).substr(0, 2).find("MZ") != 0)
	{
		std::cout << "ERROR: Invalid PE signature (MZ)." << std::endl;
		return;
	}

	// turns out std::copy is literally 'first = last;'
	m_OriginalImageData.resize(data.size());
	std::copy(data.begin(), data.end(), m_OriginalImageData.begin());

	if (!ParseHeaders())
		return;

	if (!ParseSections())
		return;

	if (!ParseImports())
		return;

	if (m_ImageType == ImageType::DLL)
		if (!ParseExports())
			return;

	m_Success = true;
}

exhume::~exhume()
{
}

bool exhume::ParseHeaders()
{
	memcpy(&m_Dosheader, &m_OriginalImageData[0], sizeof(IMAGE_DOS_HEADER));
	memcpy(&m_NtHeaders, &m_OriginalImageData[m_Dosheader.e_lfanew], sizeof(IMAGE_NT_HEADERS32));

	if (m_NtHeaders.Signature != 0x4550)
	{
		std::cout << "ERROR: Invalid NT header signature. Expected 0x4550. Actual: 0x" << std::hex << m_NtHeaders.Signature << std::endl;
		m_OriginalImageData.clear();
		return false;
	}

	if (m_NtHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		std::cout << "ERROR: Not a 32bit image." << std::endl;
		m_OriginalImageData.clear();
		return false;
	}

	if (m_NtHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL)
		m_ImageType = ImageType::DLL;
	else
		m_ImageType = ImageType::EXE;

	return true;
}

bool exhume::ParseSections()
{
	auto section_header_offset = m_Dosheader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);

	for (auto i = 0; i < m_NtHeaders.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER header = {};
		DirectoryMap directories;
		std::vector<unsigned char> data;

		memcpy(&header, &m_OriginalImageData[section_header_offset], sizeof(IMAGE_SECTION_HEADER));

		// some sections do not exist on file. (uninitialised data)
		if (header.SizeOfRawData > 0)
		{
			data.resize(header.SizeOfRawData);

			try
			{
				std::copy(
					m_OriginalImageData.begin() + header.PointerToRawData,
					m_OriginalImageData.begin() + header.PointerToRawData + header.SizeOfRawData,
					data.begin());
			} catch (const std::exception& e)
			{
				std::cout << "EXCEPTION: " << e.what() << std::endl;
				m_Success = false;
			}
		}

		for (auto j = 0; j < 15; j++)
		{
			auto directory = m_NtHeaders.OptionalHeader.DataDirectory[j];

			if (directory.VirtualAddress >= header.VirtualAddress &&
				directory.VirtualAddress + directory.Size <= header.VirtualAddress + header.Misc.VirtualSize)
			{
				directories[j].insert({ j, directory });
			}
		}

		m_Sections.push_back({ header, data, directories });

		section_header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	return true;
}

bool exhume::ParseImports()
{
	SectionRef import_section = nullptr;
	IMAGE_DATA_DIRECTORY import_directory = {};
	IMAGE_IMPORT_DESCRIPTOR import_descriptor = {};
	size_t section_va = 0;
	size_t descriptor_offset = 0;

	if ((import_section = GetSection(IMAGE_DIRECTORY_ENTRY_IMPORT)) == nullptr)
		return false;

	for (auto& directory : import_section->Directories())
	{
		if (directory.first == IMAGE_DIRECTORY_ENTRY_IMPORT)
			if ((import_directory = directory.second[IMAGE_DIRECTORY_ENTRY_IMPORT]).VirtualAddress == 0)
				return false;
	}

	section_va = import_section->Header().VirtualAddress;
	descriptor_offset = import_directory.VirtualAddress - section_va;
	memcpy(&import_descriptor, &import_section->Data()[descriptor_offset], sizeof(IMAGE_IMPORT_DESCRIPTOR));

	while (import_descriptor.Name)
	{
		size_t thunk_offset = 0;
		IMAGE_THUNK_DATA32 thunk = {};
		
		auto module_name = reinterpret_cast<const char*>(&import_section->Data()[import_descriptor.Name - section_va]);
		
		m_ImportModules[module_name] = Module(std::string(module_name));

		if (import_descriptor.OriginalFirstThunk)
			thunk_offset = import_descriptor.OriginalFirstThunk;
		else
			thunk_offset = import_descriptor.FirstThunk;

		memcpy(&thunk, &import_section->Data()[thunk_offset - section_va], sizeof(IMAGE_THUNK_DATA32));

		while (thunk.u1.AddressOfData)
		{
			if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32)
			{
				auto function_ordinal = IMAGE_ORDINAL32(thunk.u1.Ordinal);
				m_ImportModules[module_name].AddImport(function_ordinal);
			}
			else
			{
				auto function_name = reinterpret_cast<const char*>(&import_section->Data()[(thunk.u1.AddressOfData + 2) - section_va]);
				m_ImportModules[module_name].AddImport(std::string(function_name));
			}

			thunk_offset += sizeof(IMAGE_THUNK_DATA32);
			memcpy(&thunk, &import_section->Data()[thunk_offset - section_va], sizeof(IMAGE_THUNK_DATA32));
		}
		
		descriptor_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		memcpy(&import_descriptor, &import_section->Data()[descriptor_offset], sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return true;
}

bool exhume::ParseExports()
{
	SectionRef export_section = nullptr;

	if ((export_section = GetSection(IMAGE_DIRECTORY_ENTRY_EXPORT)) == nullptr)
		return false;
}


SectionRef exhume::GetSection(std::string name)
{
	for (auto& section : m_Sections)
	{
		if (name.find(reinterpret_cast<const char*>(section.Header().Name)) == 0)
		{
			return std::make_shared<Section>(section);
		}
	}

	return nullptr;
}

SectionRef exhume::GetSection(uint8_t directory)
{
	for (auto& section : m_Sections)
	{
		for (auto& dir : section.Directories())
		{
			if (dir.first == directory)
				return std::make_shared<Section>(section);
		}
	}

	return nullptr;
}

bool exhume::AddSection(std::string name, std::vector<unsigned char> data, uint32_t characteristics)
{
	SectionRef previous_section = nullptr;
	IMAGE_SECTION_HEADER new_header = {};

	if (!m_Success)
	{
		std::cout << "ERROR: Image was not parsed" << std::endl;
		return false;
	}
	
	auto section_header_offset = m_Dosheader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	auto section_count = m_Sections.size();
	
	auto section_alignment = m_NtHeaders.OptionalHeader.SectionAlignment;
	auto file_alignment = m_NtHeaders.OptionalHeader.FileAlignment;

	auto align = [](uint32_t size, uint32_t alignment, uint32_t address)->uint32_t
	{
		if (size % alignment == 0)
			return address + size;
		else
			return address + (size / alignment + 1) * alignment;
	};

	if ((previous_section = std::make_shared<Section>(m_Sections.at(section_count-1))) == nullptr)
	{
		// no previous section. align new section to alignment values in optional header

		memcpy(&new_header.Name[0], &name[0], (name.size() > 8) ? 8 : name.size());

		new_header.VirtualAddress = section_alignment;
		new_header.Misc.VirtualSize = align(data.size(), section_alignment, 0);
		new_header.PointerToRawData = section_header_offset + sizeof(IMAGE_SECTION_HEADER);
		new_header.SizeOfRawData = align(data.size(), file_alignment, 0);

		new_header.Characteristics = characteristics;

		m_NtHeaders.OptionalHeader.BaseOfCode = new_header.PointerToRawData;
	}
	else
	{
		// previous section exists. check header space
		if (section_header_offset + (sizeof(IMAGE_SECTION_HEADER) * (section_count + 1)) >= previous_section->Header().PointerToRawData)
		{
			std::cout << "ERROR: Not enough space for additional section header." << std::endl;
			return false;
		}

		auto previous_virtual_address = previous_section->Header().VirtualAddress;
		auto previous_virtual_size = previous_section->Header().Misc.VirtualSize;
		auto previous_raw_address = previous_section->Header().PointerToRawData;
		auto previous_raw_size = previous_section->Header().SizeOfRawData;

		memcpy(&new_header.Name[0], &name[0], (name.size() > 8) ? 8 : name.size());

		new_header.VirtualAddress = align(previous_virtual_size, section_alignment, previous_virtual_address);
		new_header.Misc.VirtualSize = align(data.size(), section_alignment, 0);
		
		new_header.PointerToRawData = align(previous_raw_size, file_alignment, previous_raw_address);
		new_header.SizeOfRawData = align(data.size(), file_alignment, 0);

		new_header.Characteristics = characteristics;
	}

	m_Sections.push_back({ new_header, data });

	m_NtHeaders.FileHeader.NumberOfSections = m_Sections.size();
	m_NtHeaders.OptionalHeader.SizeOfImage = new_header.VirtualAddress + new_header.Misc.VirtualSize;

	return true;
}

bool exhume::SerialiseImage(std::string path)
{
	std::vector<unsigned char> serialised_image;

	if (!m_Success)
	{
		std::cout << "ERROR: Image was not parsed" << std::endl;
		return false;
	}

	serialised_image.resize(m_NtHeaders.OptionalHeader.SizeOfImage);

	const auto dos_header_pointer = reinterpret_cast<unsigned char*>(&m_Dosheader);
	std::copy(&dos_header_pointer[0], &dos_header_pointer[sizeof(IMAGE_DOS_HEADER)], serialised_image.begin());
	
	auto nt_header_offset = m_Dosheader.e_lfanew;
	const auto nt_header_pointer = reinterpret_cast<unsigned char*>(&m_NtHeaders);
	std::copy(&nt_header_pointer[0], &nt_header_pointer[sizeof(IMAGE_NT_HEADERS32)], serialised_image.begin() + nt_header_offset);

	auto section_header_offset = m_Dosheader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	for (auto section : m_Sections)
	{
		auto header = section.Header();
		const auto section_header_pointer = reinterpret_cast<unsigned char*>(&header);
		std::copy(&section_header_pointer[0], &section_header_pointer[sizeof(IMAGE_SECTION_HEADER)], serialised_image.begin() + section_header_offset);
		
		try{
			std::copy(section.Data().begin(), section.Data().end(), serialised_image.begin() + header.PointerToRawData);
		} catch (const std::exception& e)
		{
			std::cout << "ERROR: " << e.what() << std::endl;
			return false;
		}

		section_header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	if (!WriteFile(path, serialised_image))
	{
		std::cout << "ERROR: Failed to write file. WIN32 ERROR: " << GetLastError() << std::endl;
		return false;
	}

	return true;
}

void exhume::DumpSections()
{
	if (!m_Success)
	{
		std::cout << "ERROR: Image was not parsed" << std::endl;
		return;
	}

	for (auto& section : m_Sections)
	{
		std::cout << "Name: " << section.Header().Name << std::endl;
		std::cout << "VirtualAddress: 0x" << std::hex << section.Header().VirtualAddress << std::endl;
		std::cout << "VirtualSize: 0x" << std::hex << section.Header().Misc.VirtualSize << std::endl;
		std::cout << "RawAddress: 0x" << std::hex << section.Header().PointerToRawData << std::endl;
		std::cout << "RawSize: 0x" << std::hex << section.Header().SizeOfRawData << std::endl;
		std::cout << "Characteristics 0x" << std::hex << section.Header().Characteristics << std::endl;

		if (section.Directories().empty())
			std::cout << "Section contains no directories." << std::endl;
		else
		{
			std::cout << "Section contains: " << std::endl;

			for (auto& directory : section.Directories())
				std::cout << "\t" << DIRECTORY_STRINGS[directory.first].c_str() << std::endl;
		}

		std::cout << std::endl;
	}
}

void exhume::DumpDirectories()
{
	SectionRef section = nullptr;
	IMAGE_DATA_DIRECTORY directory = {};

	if (!m_Success)
	{
		std::cout << "ERROR: Image was not parsed" << std::endl;
		return;
	}

	for (auto i = 0; i < 15; i++)
	{
		if ((section = GetSection(i)) != nullptr)
		{
			directory = section->Directories()[i].at(i);

			std::cout << DIRECTORY_STRINGS[i].c_str() << ":->";
			std::cout << std::endl << "VirtualAddress:\t0x" << std::hex << directory.VirtualAddress;
			std::cout << std::endl << "VirtualSize:\t0x" << std::hex << directory.Size;
			std::cout << std::endl << "Section: \t" << section->Header().Name;
			std::cout << std::endl << std::endl;
		}
		else
		{
			std::cout << DIRECTORY_STRINGS[i].c_str() << ":-> Empty directory" << std::endl;
		}
	}

	std::cout << std::endl;
}

void exhume::DumpImports()
{
	if (!m_Success)
	{
		std::cout << "ERROR: Image was not parsed" << std::endl;
		return;
	}

	for (auto module : m_ImportModules)
	{
		std::cout << module.first.c_str() << std::endl;

		for (auto import : module.second.Imports())
		{
			if (import.Ordinal() == 0)
				std::cout << "\t" << import.Name().c_str() << std::endl;
			else
				std::cout << "\tORDINAL: " << std::hex << import.Ordinal() << std::endl;
		}

		std::cout << std::endl;
	}
}

bool exhume::ReadFile(std::string path, std::vector<unsigned char>& data)
{
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	DWORD bytes_read = 0;

	if ((file_handle = CreateFileA(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) == nullptr)
		return false;

	data.resize(GetFileSize(file_handle, nullptr));

	if (!::ReadFile(file_handle, &data[0], data.size(), &bytes_read, nullptr))
	{
		data.clear();
		CloseHandle(file_handle);
		return false;
	}

	CloseHandle(file_handle);
	return true;
}

bool exhume::WriteFile(std::string path, std::vector<unsigned char> data)
{
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	DWORD bytes_written = 0;

	if ((file_handle = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)) == nullptr)
		return false;

	if (!::WriteFile(file_handle, &data[0], data.size(), &bytes_written, nullptr))
	{
		CloseHandle(file_handle);
		return false;
	}

	CloseHandle(file_handle);
	return true;
}