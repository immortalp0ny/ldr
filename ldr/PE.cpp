#include "stdafx.h"
#include "PE.h"

PE::PE()
{
}


PE::~PE()
{
}

bool PE::copySections(void * data, size_t dataSize, void* codeBase, PIMAGE_NT_HEADERS oldHeader, std::string& errorMsg)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(oldHeader);
	std::stringstream ss;
	std::string flMessage;

	for (int i = 0; i < oldHeader->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) {
		
			int section_size = oldHeader->OptionalHeader.SectionAlignment;
			if (section_size > 0) 
			{
				unsigned char *dest = (unsigned char *)VirtualAlloc((unsigned char*)codeBase + section->VirtualAddress, section_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (dest == NULL) 
				{
					ss.str(std::string());
					flMessage.clear();
					ss << "PE load failed! Allocate mememory for section " << section->Name << " failed!";
					flMessage = ss.str();
					errorMsg.insert(0, flMessage);
					return false;
				}

				dest = (unsigned char*)codeBase + section->VirtualAddress;
				
				section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
				memset(dest, 0, section_size);
			}
			
			continue;
		}

		if (!checkSize(dataSize, section->PointerToRawData + section->SizeOfRawData)) 
		{
			// Warning check section size
		}

		unsigned char* dest = (unsigned char *)VirtualAlloc((unsigned char*)codeBase + section->VirtualAddress, section->SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (dest == NULL) 
		{
			ss.str(std::string());
			flMessage.clear();
			ss << "PE load failed! Commit memory for section " << section->Name << " failed!";
			flMessage = ss.str();
			errorMsg.insert(0, flMessage);
			return false;
		}
		
		dest = (unsigned char*)codeBase + section->VirtualAddress;
		memcpy(dest, (unsigned char*)data + section->PointerToRawData, section->SizeOfRawData);
		
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
	}

	return true;
}

unsigned int PE::performBaseRelocation(LOADED_PE* module, ptrdiff_t delta, std::string& errorMsg)
{
	unsigned char *codeBase = (unsigned char*)(module->imageBase);
	PIMAGE_BASE_RELOCATION relocation;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (directory->Size == 0) {
		return (delta == 0);
	}

	relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
	for (; relocation->VirtualAddress > 0; ) {
		DWORD i;
		unsigned char *dest = codeBase + relocation->VirtualAddress;
		unsigned short *relInfo = (unsigned short*)offsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
		for (i = 0; i<((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
			// the upper 4 bits define the type of relocation
			int type = *relInfo >> 12;
			// the lower 12 bits define the offset
			int offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				// change complete 32 bit address
			{
				DWORD *patchAddrHL = (DWORD *)(dest + offset);
				*patchAddrHL += (DWORD)delta;
			}
			break;

#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64:
			{
				ULONGLONG *patchAddr64 = (ULONGLONG *)(dest + offset);
				*patchAddr64 += (ULONGLONG)delta;
			}
			break;
#endif

			default:
			{
				break;

			}
			}
		}

		// advance to next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)offsetPointer(relocation, relocation->SizeOfBlock);
	}
	return ERROR_SUCCESS;
}

unsigned int PE::buildImportTable(LOADED_PE* module, std::string& errorMsg)
{
	unsigned char *codeBase = (unsigned char*)(module->imageBase);
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	unsigned int result = ERROR_SUCCESS;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0) {
		return ERROR_SUCCESS;
	}

	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + directory->VirtualAddress);
	for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
		uintptr_t *thunkRef;
		FARPROC *funcRef;

		HMODULE handle = module->loadLibrary((LPCSTR)(codeBase + importDesc->Name));
		if (handle == NULL) 
		{
			std::stringstream ss;
			ss << "PE Load failed: Unknown import dll: " << importDesc->Name;
			errorMsg.insert(0, ss.str());
			return ERROR_UNKNOWN_IMPORT_DLL;
		}

		loadedPe->hLoadedLibs.push_back(handle);
		
		if (importDesc->OriginalFirstThunk) {
			thunkRef = (uintptr_t *)(codeBase + importDesc->OriginalFirstThunk);
			funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
		}
		else 
		{
			thunkRef = (uintptr_t *)(codeBase + importDesc->FirstThunk);
			funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
		}
		for (; *thunkRef; thunkRef++, funcRef++) 
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
				*funcRef = module->getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else {
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
				*funcRef = module->getProcAddress(handle, (LPCSTR)&thunkData->Name);
			}
			if (*funcRef == 0) 
			{
				std::stringstream ss;
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
				ss << "PE Load failed: Unknown import function: " << (LPCSTR)&thunkData->Name;
				errorMsg.insert(0, ss.str());
				return ERROR_UNKNOWN_IMPORT_FUNCTION;
			}
		}

	}

	return ERROR_SUCCESS;
}

unsigned int PE::finalizeSection(LOADED_PE *module, PESECTION *sectionData) 
{
	DWORD protect, oldProtect;
	BOOL executable;
	BOOL readable;
	BOOL writeable;

	if (sectionData->sectionSize == 0) {
		return ERROR_SUCCESS;
	}

	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) 
	{
		if (sectionData->pBeginAddress == sectionData->alignedAddress &&
			(sectionData->last ||
				module->pHeaders->OptionalHeader.SectionAlignment == module->pageSize ||
				(sectionData->sectionSize % module->pageSize) == 0)
			) 
		{
	
			VirtualFree(sectionData->pBeginAddress, sectionData->sectionSize, MEM_DECOMMIT);
		}
		return ERROR_SUCCESS;
	}

	// determine protection flags based on characteristics
	executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
	writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
	protect = ProtectionFlags[executable][readable][writeable];
	if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
		protect |= PAGE_NOCACHE;
	}

	// change memory access flags
	if (VirtualProtect(sectionData->pBeginAddress, sectionData->sectionSize, protect, &oldProtect) == 0) 
	{
		
		return ERROR_CHANGE_SECTION_PROTECT;
	}

	return ERROR_SUCCESS;
}

unsigned int PE::finalizeSections(LOADED_PE *module, std::string& errormsg)
{
	int i;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->pHeaders);
#ifdef _WIN64

	uintptr_t imageOffset = ((uintptr_t)module->pHeaders->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
	static const uintptr_t imageOffset = 0;
#endif
	PESECTION sectionData;
	sectionData.pBeginAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
	sectionData.alignedAddress = alignAddressDown(sectionData.pBeginAddress, module->pageSize);
	sectionData.sectionSize = getRealSectionSize(module, section);
	sectionData.characteristics = section->Characteristics;
	sectionData.last = false;
	section++;

	// loop through all sections and change access flags
	for (i = 1; i < module->pHeaders->FileHeader.NumberOfSections; 
														i++, section++) 
	{
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = alignAddressDown(sectionAddress, module->pageSize);
		SIZE_T sectionSize = getRealSectionSize(module, section);
		
		if (sectionData.alignedAddress == alignedAddress || 
			(uintptr_t)sectionData.pBeginAddress + sectionData.sectionSize >(uintptr_t) alignedAddress) 
		{
			// Section shares page with previous
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				sectionData.characteristics |= section->Characteristics;
			}
			sectionData.sectionSize = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.pBeginAddress;
			continue;
		}

		unsigned int status = finalizeSection(module, &sectionData);
		if (status != ERROR_SUCCESS) 
		{
			errormsg.insert(0, "PE Load failed: Failed finalize section");
			return status;
		}

		sectionData.pBeginAddress = sectionAddress;
		sectionData.alignedAddress = alignedAddress;
		sectionData.sectionSize = sectionSize;
		sectionData.characteristics = section->Characteristics;
	}
	sectionData.last = true;
	unsigned int status = finalizeSection(module, &sectionData);
	if (status != ERROR_SUCCESS)
	{
		errormsg.insert(0, "PE Load failed: Failed finalize section");
		return status;
	}
	return ERROR_SUCCESS;
}

size_t PE::getRealSectionSize(LOADED_PE *module, PIMAGE_SECTION_HEADER section) {
	DWORD size = section->SizeOfRawData;
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = module->pHeaders->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = module->pHeaders->OptionalHeader.SizeOfUninitializedData;
		}
	}
	return (SIZE_T)size;
}

uintptr_t PE::alignValueDown(uintptr_t value, uintptr_t alignment)
{
	return value & ~(alignment - 1);
}

LPVOID PE::alignAddressDown(LPVOID address, uintptr_t alignment)
{
	return (LPVOID)alignValueDown((uintptr_t)address, alignment);
}

size_t PE::alignValueUp(size_t value, size_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

void * PE::offsetPointer(void * data, ptrdiff_t offset)
{
	return (void*)((uintptr_t)data + offset);
}

bool PE::checkSize(size_t size, size_t expected)
{
	if (size < expected) {
		return false;
	}
	return true;
}



unsigned int PE::loadPE(void * data, size_t size, int flags, std::string& errorMessage)
{

	std::stringstream ss;
	std::string flMessage;

	if (!checkSize(size, sizeof(IMAGE_DOS_HEADER))) 
	{
		errorMessage.insert(0, "PE load failed! Target size less than IMAGE_DOS_HEADER size");
		return ERROR_INVALID_TARGET_SIZE;
	}

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		errorMessage.insert(0, "PE load failed! Bad DOS_SIGNATURE !");
		return ERROR_INVALID_PE_FORMAT;
	}

	if (!checkSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) {
		errorMessage.insert(0, "PE load failed! Check IMAGE_NT_HEADERS size failed !");
		return ERROR_INVALID_TARGET_SIZE;
	}

	PIMAGE_NT_HEADERS old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
	if (old_header->Signature != IMAGE_NT_SIGNATURE) {
		errorMessage.insert(0, "PE load failed! Check IMAGE_NT_SIGNATURE  failed !");
		return ERROR_INVALID_PE_FORMAT;
	}

	if (old_header->FileHeader.Machine != HOST_MACHINE) {
		errorMessage.insert(0, "PE load failed! Check MACHINE failed !");
		return ERROR_INVALID_PE_FORMAT;
	}

	if (old_header->OptionalHeader.SectionAlignment & 1) {
		errorMessage.insert(0, "PE load failed! Check section alignment  failed !");
		// Only support section alignments that are a multiple of 2
		return ERROR_INVALID_PE_FORMAT;
	}

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(old_header);
	size_t optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
	size_t lastSectionEnd = 0;

	for (int i = 0; i<old_header->FileHeader.NumberOfSections; i++, section++) 
	{
		size_t endOfSection;
		if (section->SizeOfRawData == 0) 
		{
			endOfSection = section->VirtualAddress + optionalSectionSize;
		}
		else 
		{
			endOfSection = section->VirtualAddress + section->SizeOfRawData;
		}

		if (endOfSection > lastSectionEnd) 
		{
			lastSectionEnd = endOfSection;
		}
	}

	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);
	size_t alignedImageSize = alignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != alignValueUp(lastSectionEnd, sysInfo.dwPageSize)) 
	{
		ss.str(std::string());
		flMessage.clear();
		ss << "PE load failed! Check Align failed ! Aligned ImageSize: " << std::hex << alignedImageSize 
			<< "Last section align: " << std::hex << alignValueUp(lastSectionEnd, sysInfo.dwPageSize);
		flMessage = ss.str();
		errorMessage.insert(0, flMessage);
		return ERROR_INVALID_PE_FORMAT;
	}

	unsigned char* code = (unsigned char *)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase), alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (code == NULL) 
	{
		code = (unsigned char *)VirtualAlloc(NULL, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (code == NULL) 
		{
			errorMessage.insert(0, "PE load failed! Allocate memory for image failed !");
			return ERROR_ALLOCATE_IMAGE_FAILED;
		}
	}

	if (!checkSize(size, old_header->OptionalHeader.SizeOfHeaders)) {
		errorMessage.insert(0, "PE load failed! Size less SizeOfHeaders !");
		VirtualFree(code, alignedImageSize, MEM_DECOMMIT);
		return ERROR_INVALID_PE_FORMAT;
	}

	unsigned char* headers = (unsigned char *)VirtualAlloc(code, old_header->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);

	loadedPe = new LOADED_PE();
	loadedPe->imageBase = (HMODULE)code;
	loadedPe->imageSize = alignedImageSize;
	loadedPe->pHeaders = (PIMAGE_NT_HEADERS)(headers + dos_header->e_lfanew);

	loadedPe->pHeaders->OptionalHeader.ImageBase = (uintptr_t)code;
	loadedPe->pEntryPoint = code + loadedPe->pHeaders->OptionalHeader.AddressOfEntryPoint;
	//Plugins imports here
	loadedPe->loadLibrary = &LoadLibraryA;
	loadedPe->freeLibrary = &FreeLibrary;
	loadedPe->getProcAddress = &GetProcAddress;
	loadedPe->pageSize = sysInfo.dwPageSize;

	std::string errormsg;
	if (!copySections((void*) data, size, code, old_header, errormsg))
	{
		errorMessage.insert(0, errormsg);
		VirtualFree(headers, old_header->OptionalHeader.SizeOfHeaders, MEM_DECOMMIT);
		VirtualFree(code, alignedImageSize, MEM_DECOMMIT);
		delete loadedPe;
	}


	ptrdiff_t locationDelta = (ptrdiff_t)(loadedPe->pHeaders->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase);
	unsigned int status = ERROR_SUCCESS;
	if (locationDelta != 0) 
	{
		std::string errorMsg;
		status = performBaseRelocation(loadedPe, locationDelta, errorMsg);
		if (status != ERROR_SUCCESS)
		{
			errorMessage.insert(0, errorMsg);
			VirtualFree(headers, old_header->OptionalHeader.SizeOfHeaders, MEM_DECOMMIT);
			VirtualFree(code, alignedImageSize, MEM_DECOMMIT);
			delete loadedPe;
			return status;
		}
	}

	errormsg.clear();
	status = buildImportTable(loadedPe, errormsg);
	if ( status != ERROR_SUCCESS) 
	{
		if (!(flags & LOADER_FLAG_IGNORE_IMP_ERRORS))
		{
			errorMessage.insert(0, errormsg);
			VirtualFree(headers, old_header->OptionalHeader.SizeOfHeaders, MEM_DECOMMIT);
			VirtualFree(code, alignedImageSize, MEM_DECOMMIT);
			delete loadedPe;
			return status;
		}
	}
	
	errormsg.clear();
	status = finalizeSections(loadedPe, errormsg);
	if (!finalizeSections(loadedPe, errormsg)) {
		errorMessage.insert(0, errormsg);
		VirtualFree(headers, old_header->OptionalHeader.SizeOfHeaders, MEM_DECOMMIT);
		VirtualFree(code, alignedImageSize, MEM_DECOMMIT);
		delete loadedPe;
		return status;
	}

	return ERROR_SUCCESS;

}
