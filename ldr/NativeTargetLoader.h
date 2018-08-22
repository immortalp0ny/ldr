#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <Windows.h>
#include "TargetLoader.h"
#include "PE.h"
#include "Logger.h"
#include "helper.h"


#define INVALID_VALUE 0xDEADC0DE
#define INVALID_ORDINAL_VALUE 0xc0de
#define ERROR_INVALID_RUN_START 0xfffffff4
#define ERROR_PLUGIN_LOAD 0xfffffff3

typedef void (__stdcall* pfnShellcodeMain)();
typedef BOOL (__stdcall *pfnDllMain)(HINSTANCE hInstDll, unsigned int fdwReason, LPVOID lpReserved);

class NativeTargetLoader : public TargetLoader
{
protected:
	bool verbose = false;
	Logger* logger;
	PE* peLoader;
	unsigned int fdwReason = 1; 

	PluginDescriptor* pd = NULL;
public:

	NativeTargetLoader(bool verbose);
	~NativeTargetLoader();

	virtual unsigned int setTargetType(TargetType lt);
	virtual unsigned int setLoadFlags(LoadFlags flags);
	virtual unsigned int setAdditionalLibs(std::vector<std::string>& libs);
	virtual unsigned int setTarget(std::string& path);
	virtual unsigned int setStartRva(unsigned int rva);
	virtual unsigned int setStartRawOffset(unsigned int offset);
	virtual unsigned int setStartExportOrdinal(unsigned short ordinal);
	virtual unsigned int setStartExportNameA(char* exportName);
	
	unsigned int setFdwReason(unsigned int fdwReason);
	unsigned int setPlugin(std::string& pluginPath, std::string& pluginCl);

	virtual unsigned int load();
	virtual unsigned int run();
};

