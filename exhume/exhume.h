#pragma once
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <memory>

static std::string DIRECTORY_STRINGS[] = {
	"IMAGE_DIRECTORY_ENTRY_EXPORT\0",
	"IMAGE_DIRECTORY_ENTRY_IMPORT\0",
	"IMAGE_DIRECTORY_ENTRY_RESOURCE\0",
	"IMAGE_DIRECTORY_ENTRY_EXCEPTION\0",
	"IMAGE_DIRECTORY_ENTRY_SECURITY\0",
	"IMAGE_DIRECTORY_ENTRY_BASERELOC\0",
	"IMAGE_DIRECTORY_ENTRY_DEBUG\0",
	//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
	"IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\0",
	"IMAGE_DIRECTORY_ENTRY_GLOBALPTR\0",
	"IMAGE_DIRECTORY_ENTRY_TLS\0",
	"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\0",
	"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\0",
	"IMAGE_DIRECTORY_ENTRY_IAT\0",
	"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\0",
	"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\0"
};

enum ImageType
{
	EXE,
	DLL
};

#define ImportRef			std::shared_ptr<Import>
#define ModuleRef			std::shared_ptr<Module>
#define SectionRef			std::shared_ptr<Section>

#define Directory			std::map<uint8_t, IMAGE_DATA_DIRECTORY>
#define DirectoryMap		std::map<uint8_t, Directory>

#define ModuleMap			std::map<std::string, Module>

class Import
{
public:
	Import(std::string name) : m_Name(name), m_Ordinal(0) {}
	Import(uint16_t ordinal) : m_Name(""), m_Ordinal(ordinal) {}

	std::string Name() const { return m_Name; }
	uint16_t Ordinal() const { return m_Ordinal; }

private:
	std::string m_Name;
	uint16_t m_Ordinal;
};

class Module
{
public:
	Module() : m_Name() {}
	Module(std::string name) : m_Name(name) {}

	const std::vector<Import>& Imports() const { return m_ImportEntries; }

	void AddImport(Import import) { m_ImportEntries.push_back(import); }

private:
	std::string m_Name;
	std::vector<Import> m_ImportEntries;
};

class Section
{
public:
	Section(IMAGE_SECTION_HEADER header, std::vector<unsigned char> data, 
		DirectoryMap directories = {}) : m_Header(header),
		m_Directories(directories), m_Data(data) {}

	const IMAGE_SECTION_HEADER& Header() const { return m_Header; }
	DirectoryMap Directories() const { return m_Directories; }
	const std::vector<unsigned char>& Data() const { return m_Data; }

private:
	IMAGE_SECTION_HEADER m_Header = {};
	std::map<uint8_t, std::map<uint8_t, IMAGE_DATA_DIRECTORY>> m_Directories;
	std::vector<unsigned char> m_Data;
};

class exhume
{
public:
	exhume(std::string path);
	~exhume();

	const IMAGE_DOS_HEADER& GetDosHeader() const { return m_Dosheader; }	
	const IMAGE_NT_HEADERS32& GetNtHeader() const { return m_NtHeaders; }

	bool Success() const { return m_Success; }

	SectionRef GetSection(std::string name);
	SectionRef GetSection(uint8_t directory);

	bool AddSection(std::string name, std::vector<unsigned char> data, 
		uint32_t characteristics = 0x60000020);

	bool SerialiseImage(std::string path);
	bool SerialiseImage(std::vector<unsigned char> data);

	void DumpSections();
	void DumpDirectories();
	void DumpImports();
	void DumpExports();
	void DumpResources();

private:
	bool ParseHeaders();
	bool ParseSections();
	bool ParseImports();
	bool ParseExports();

private:
	bool m_Success = false;

	std::vector<unsigned char> m_OriginalImageData;

	ImageType m_ImageType;
	IMAGE_DOS_HEADER m_Dosheader;
	IMAGE_NT_HEADERS32 m_NtHeaders;
	std::vector<Section> m_Sections;
	ModuleMap m_ImportModules;

private:
	static bool ReadFile(std::string path, std::vector<unsigned char>& data);
	static bool WriteFile(std::string path, std::vector<unsigned char> data);
};