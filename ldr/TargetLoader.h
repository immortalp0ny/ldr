#pragma once

#include <iostream>
#include <vector>
#include <string>

#include "plugin.h"

#define ERROR_SUCCESS 0
#define ERROR_INVALID_TARGET_TYPE 0xffffffff
#define ERROR_INVALID_TARGET_PATH 0xfffffffe
#define ERROR_FAILED_READ_TARGET  0xfffffffd

enum TargetType
{
	TARGETTYPE_MIN = 0,
	TARGETTYPE_SHELLCODE,
	TARGETTYPE_DLL,
	TARGETTYPE_EXE,
	TARGETTYPE_MAX,
};

typedef unsigned int LoadFlags;

class TargetLoader {
protected:
	void *pTargetImage = NULL;
	size_t cbTargetImage = 0;
	
	std::string targetPath;

	TargetType targetType = TARGETTYPE_MIN;
	LoadFlags loadFlags = 0;

	unsigned int startRva = 0;
	unsigned int startRawOffset = 0;
	unsigned int startExportOrdinal = 0;
	char* startExportName = 0;
	
public:

	virtual unsigned int setTargetType(TargetType lt) = 0;
	virtual unsigned int setLoadFlags(LoadFlags flags) = 0;
	virtual unsigned int setAdditionalLibs(std::vector<std::string>& libs) = 0;
	virtual unsigned int setTarget(std::string& path) = 0;
	virtual unsigned int setStartRva(unsigned int rva) = 0;
	virtual unsigned int setStartRawOffset(unsigned int offset) = 0;
	virtual unsigned int setStartExportOrdinal(unsigned short ordinal) = 0;
	virtual unsigned int setStartExportNameA(char* exportName) = 0;

	virtual unsigned int load() = 0;
	virtual unsigned int run() = 0;


};