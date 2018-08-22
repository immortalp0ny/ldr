#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <Windows.h>

#define ERROR_INVALID_TARGET_SIZE  0xfffffffc
#define ERROR_INVALID_PE_FORMAT  0xfffffffb
#define ERROR_ALLOCATE_IMAGE_FAILED  0xfffffffa
#define ERROR_SECTION_COPY 0xfffffff9
#define ERROR_UNKNOWN_RELOC_TYPE 0xfffffff8
#define ERROR_UNKNOWN_IMPORT_DLL 0xfffffff7
#define ERROR_UNKNOWN_IMPORT_FUNCTION 0xfffffff6
#define ERROR_CHANGE_SECTION_PROTECT 0xfffffff5

#define LOADER_FLAG_EXEC_MAIN 0x1
#define LOADER_FLAG_IGNORE_IMP_ERRORS 0x2
#define LOADER_FLAG_INFINITY_WAIT 0x04

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->pHeaders->OptionalHeader.DataDirectory[idx]

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
	// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
	#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
	#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
	#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
{ PAGE_READONLY, PAGE_READWRITE },
	},{
		// executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
	},
};

typedef HMODULE(__stdcall *pfnLoadLibrary)(LPCSTR dllName);
typedef BOOL(__stdcall *pfnFreeLibrary)(HMODULE dllName);
typedef FARPROC (__stdcall *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef struct 
{
	LPVOID pBeginAddress;
	LPVOID alignedAddress;
	size_t sectionSize;
	DWORD  characteristics;
	bool last;
} PESECTION;

typedef struct _LOADED_PE {
	PIMAGE_NT_HEADERS pHeaders;
	HMODULE imageBase;
	size_t imageSize;
	LPVOID pEntryPoint;
	std::vector<HMODULE> hLoadedLibs;
	DWORD pageSize;
	pfnLoadLibrary loadLibrary;
	pfnFreeLibrary freeLibrary;
	pfnGetProcAddress getProcAddress;
} LOADED_PE;


class PE
{
protected:
	bool copySections(void* data, size_t dataSize, void* codeBase, PIMAGE_NT_HEADERS oldHeader, std::string& errorMsg);
	unsigned int performBaseRelocation(LOADED_PE* module, ptrdiff_t delta, std::string& errorMsg);
	unsigned int buildImportTable(LOADED_PE* module, std::string& errorMsg);
	unsigned int finalizeSections(LOADED_PE *module, std::string& errormsg);
	unsigned int finalizeSection(LOADED_PE *module, PESECTION *sectionData);
public:
	PE();
	~PE();

	
	LOADED_PE* loadedPe;

	static uintptr_t alignValueDown(uintptr_t value, uintptr_t alignment);
	static LPVOID alignAddressDown(LPVOID address, uintptr_t alignment);
	static size_t alignValueUp(size_t value, size_t alignment);
	static void* offsetPointer(void* data, ptrdiff_t offset);
	static bool checkSize(size_t size, size_t expected);
	static size_t getRealSectionSize(LOADED_PE *module, PIMAGE_SECTION_HEADER section);

	unsigned int loadPE(void *data, size_t size, int flags, std::string& errorMessage);
	

};

