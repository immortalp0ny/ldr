#include "stdafx.h"
#include "NativeTargetLoader.h"


NativeTargetLoader::NativeTargetLoader(bool verbose)
{
	this->verbose = verbose;

	logger = new Logger();
	std::string loggerName = "NTL";
	logger->setLoggerName(loggerName);
	peLoader = new PE();
}

NativeTargetLoader::~NativeTargetLoader()
{
	if (logger)
		delete logger;
	if (peLoader)
		delete peLoader;
	if (pd)
		delete pd;
}

unsigned int NativeTargetLoader::setTargetType(TargetType lt)
{
	if (lt >= TARGETTYPE_MAX || lt <= TARGETTYPE_MIN)
		return ERROR_INVALID_TARGET_TYPE;
	targetType = lt;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setLoadFlags(LoadFlags flags)
{
	loadFlags = flags;
	return 0;
}

unsigned int NativeTargetLoader::setAdditionalLibs(std::vector<std::string>& libs)
{
	for (std::string &libName : libs)
	{
		HMODULE hLib = LoadLibraryA(libName.c_str());

		std::stringstream ls;
		ls << "Lib: " << libName << std::hex << " HMODULE: " << hLib;
		std::string lss = ls.str();
		logger->logMessage(lss);
	}
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setTarget(std::string &path)
{
	targetPath = path;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setStartRva(unsigned int rva)
{
	startRva = rva;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setStartRawOffset(unsigned int offset)
{
	startRawOffset = offset;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setStartExportOrdinal(unsigned short ordinal)
{
	startExportOrdinal = ordinal;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setStartExportNameA(char * exportName)
{
	startExportName = exportName;
	return ERROR_SUCCESS;
}

unsigned int NativeTargetLoader::setFdwReason(unsigned int fdwReason)
{
	this->fdwReason = fdwReason;
	return 0;
}

unsigned int NativeTargetLoader::setPlugin(std::string & pluginPath, std::string & pluginCl)
{
	HMODULE pluginBase = LoadLibraryA(pluginPath.c_str());
	if (pluginBase == NULL)
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Can't load dll plugin. Path: " << pluginPath;
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);
		return ERROR_PLUGIN_LOAD;
	}
	pd = new PluginDescriptor();
	memset(pd, 0, sizeof(PluginDescriptor));

	pd->pluginBase = pluginBase;


	ANSI_STRING ansiPluginCl;
	if (!wrpRtlInitAnsiString(&ansiPluginCl, pluginCl.c_str()))
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Error initialize ANSI_STRING for Plugin CL";
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);

		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;

		return ERROR_PLUGIN_LOAD;
	}

	UNICODE_STRING unicodePluginCl;
	if (!ansiStringToUnicodeString(&ansiPluginCl, &unicodePluginCl) )
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Error convert plugin ansi cl to unicode cl";
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);

		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;

		return ERROR_PLUGIN_LOAD;
	}
	
	unsigned int argc = NULL;
	wchar_t ** wargv = CommandLineToArgvW(unicodePluginCl.Buffer, (int*)&argc);
	if (wargv == NULL)
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Error convert plugin cl to argv";
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);

		wrpRtlFreeUnicodeString(&unicodePluginCl);
		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;

		return ERROR_PLUGIN_LOAD;
	}
	
	wrpRtlFreeUnicodeString(&unicodePluginCl);

	char moduleFilePath[MAX_PATH];
	memset(moduleFilePath, 0, MAX_PATH);

	unsigned int lengthPath = GetModuleFileNameA(pluginBase, moduleFilePath, MAX_PATH);
	if (lengthPath == 0)
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Error can't get plugin module path for argv[0]";
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);

		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;

		return ERROR_PLUGIN_LOAD;
	}

	char** argv = new char*[argc + 1];
	argv[0] = new char[lengthPath + 1];

	memcpy(argv[0], moduleFilePath, lengthPath + 1);

	int j = 1;
	for (unsigned int i = 0; i <= argc; i++)
	{
		UNICODE_STRING uArg;
		if (!wrpRtlInitUnicodeString(&uArg, wargv[i]))
		{
			std::string flMessage;
			std::stringstream ss;
			ss << "Error convert plugin arg by index: " << i;
			flMessage = ss.str();
			logger->logWarningMessage(flMessage);
			
			delete [] argv[0];
			delete [] argv;

			FreeLibrary(pluginBase);
			delete pd;
			pd = NULL;

			return ERROR_PLUGIN_LOAD;
		}

		ANSI_STRING aArg;
		if (!unicodeStringToAnsiString(&uArg, &aArg))
		{
			std::string flMessage;
			std::stringstream ss;
			ss << "Error convert plugin arg by index to ansi: " << i;
			flMessage = ss.str();
			logger->logWarningMessage(flMessage);

			delete[] argv[0];
			delete[] argv;

			FreeLibrary(pluginBase);
			delete pd;
			pd = NULL;

			return ERROR_PLUGIN_LOAD;
		}

		argv[j] = new char[aArg.Length + 1];
		memset(argv[j], 0, aArg.Length + 1);
		memcpy(argv[j], aArg.Buffer, aArg.Length + 1);
		wrpRtlFreeAnsiString(&aArg);
		j++;
	}
	
	t_plugin_Init pfnPlugin_Init = (t_plugin_Init)GetProcAddress(pluginBase, PLDREFunctionName__plugin_Init);
	if (pfnPlugin_Init == NULL)
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Plugin invalid. Can't find export: " << PLDREFunctionName__plugin_Init;
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);
		for (unsigned int i = 1; i < argc + 1; i++)
			delete[] argv[i];
		delete[] argv;

		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;
		return ERROR_PLUGIN_LOAD;
	}

	int status = pfnPlugin_Init(pd, argc + 1, argv);
	if (status != PLDRR_SUCCESS)
	{
		std::string flMessage;
		std::stringstream ss;
		ss << "Plugin init failed";
		flMessage = ss.str();
		logger->logWarningMessage(flMessage);
		for (unsigned int i = 1; i < argc + 1; i++)
			delete[] argv[i];
		delete[] argv;

		FreeLibrary(pluginBase);
		delete pd;
		pd = NULL;
		return ERROR_PLUGIN_LOAD;
	}

	std::string flMessage;
	std::stringstream ss;
	ss << "Plugin success load !";
	flMessage = ss.str();
	logger->logMessage(flMessage);
	ss.str(std::string());
	ss << "Plugin name: " << pd->pluginName << " Plugin Version: " << pd->pluginVersion;
	flMessage = ss.str();
	logger->logMessage(flMessage);
	
	for (unsigned int i = 1; i < argc + 1; i++)
		delete[] argv[i];
	delete[] argv;
	
	return ERROR_SUCCESS;

}

unsigned int NativeTargetLoader::load()
{
	if (targetPath.empty())
		return ERROR_INVALID_TARGET_PATH;

	if (targetType == TARGETTYPE_MIN)
		return ERROR_INVALID_TARGET_TYPE;
	
	char* targetData = NULL;
	unsigned int cbTargetData = NULL;

	std::string flMessage;
	std::stringstream ss;
	ss << "Read target from path: " << targetPath;
	flMessage = ss.str();
	logger->logMessage(flMessage);

	std::string errorMessage;
	if (!readall(targetPath, &targetData, &cbTargetData, errorMessage))
	{
		logger->logErrorMessage(errorMessage);
		return ERROR_FAILED_READ_TARGET;
	}

	ss.str(std::string());
	ss << "Target read into memory: " << std::hex << static_cast<void*>(targetData);
	flMessage = ss.str();
	logger->logMessage(flMessage);
	unsigned int status = ERROR_SUCCESS;
	switch (targetType)
	{
		case TARGETTYPE_SHELLCODE:	
		{
			pTargetImage = targetData;
			cbTargetImage = cbTargetData;
			break; 
		}
		case TARGETTYPE_EXE:
		case TARGETTYPE_DLL:
		{
			ss.str(std::string());
			ss << "Target type is PE. Load target as PE";
			flMessage = ss.str();
			logger->logMessage(flMessage);
			std::string peLoadErrorMessage;
			status = peLoader->loadPE(targetData, cbTargetData, loadFlags, peLoadErrorMessage);
			if (status != ERROR_SUCCESS)
				logger->logErrorMessage(peLoadErrorMessage);
			pTargetImage = peLoader->loadedPe->imageBase;
			cbTargetImage = peLoader->loadedPe->imageSize;
			break; 
		}
	}

	return status;
}

unsigned int NativeTargetLoader::run()
{
	int o = 0;
	if (startRva != INVALID_VALUE && (targetType == TARGETTYPE_DLL || targetType == TARGETTYPE_EXE))
		o = startRva;
	
	if (startRawOffset != INVALID_VALUE && !o)
		o = startRawOffset;

	if (startExportOrdinal != INVALID_ORDINAL_VALUE && !o && (targetType == TARGETTYPE_DLL || targetType == TARGETTYPE_EXE))
	{
		std::string s = "Run by export ordinal does not implemented :(";
		logger->logErrorMessage(s);
		return ERROR_INVALID_RUN_START;
	}
	
	if (startExportName[0] != 0 && !o && (targetType == TARGETTYPE_DLL || targetType == TARGETTYPE_EXE))
	{
		std::string s = "Run by export name does not implemented :(";
		logger->logErrorMessage(s);
		return ERROR_INVALID_RUN_START;
	}
	
	std::stringstream ss;
	unsigned int s = (unsigned int)pTargetImage + o;
	std::string strMessage;

	ss << "Image base: " << std::hex << static_cast<void*>(pTargetImage);
	strMessage = ss.str();

	logger->logImportantMessage(strMessage);

	

	if (targetType == TARGETTYPE_DLL || targetType == TARGETTYPE_EXE)
	{
		if (loadFlags & LOADER_FLAG_EXEC_MAIN)
		{
			pfnDllMain pDM = (pfnDllMain)peLoader->loadedPe->pEntryPoint;
			ss.str(std::string());
			ss << "Set breakpoint on (DllMain) " << std::hex << static_cast<void*>(pDM);
			strMessage = ss.str();
			logger->logImportantMessage(strMessage);

			void *lpReserved = NULL;
			if (pd != NULL && pd->pfnGetLpReserved)
			{
				t_plugin_GetLpReserved pfnGetLpReserved = (t_plugin_GetLpReserved)pd->pfnGetLpReserved;
				int status = pfnGetLpReserved(&lpReserved, (LDRP_LOADED_PE*)peLoader->loadedPe);
				if (status != PLDRR_SUCCESS)
				{
					lpReserved = NULL;
					ss.str(std::string());
					ss << "Plugin function " << PLDREFunctionName__plugin_GetLpReserved << "failed with code: " << std::hex << status;
					strMessage = ss.str();
					logger->logWarningMessage(strMessage);
				}
			}

			system("pause");
			pDM((HINSTANCE)pTargetImage, fdwReason, lpReserved);
		}
		else if (!o)
		{
			s = (unsigned int)peLoader->loadedPe->pEntryPoint;
		}
		
	}
	if (o != INVALID_VALUE)
	{
		pfnShellcodeMain pSM = (pfnShellcodeMain)s;
		ss.str(std::string());
		ss << "Set breakpoint on " << std::hex << static_cast<void*>(pSM);
		strMessage = ss.str();
		logger->logImportantMessage(strMessage);
		system("pause");
		if (pd != NULL && pd->pfnExportCallLogicModify)
		{
			t_plugin_ExportCallLogicModify pfnExportCallLogicModify = (t_plugin_ExportCallLogicModify)pd->pfnExportCallLogicModify;
			int status = pfnExportCallLogicModify((LDRP_LOADED_PE*)peLoader->loadedPe, static_cast<void*>(pSM));
			if (status != PLDRR_SUCCESS)
			{

			}
		}
		else
		{
			pSM();
		}
	}

	if (loadFlags & LOADER_FLAG_INFINITY_WAIT)
	{
		Sleep(0xFFFFFFFF);
	}

	return 0;
}
