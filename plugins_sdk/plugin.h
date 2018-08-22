#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <Windows.h>

#define PLDREFunctionName__pluginExportCallLogicModify "plugin_ExportCallLogicModify"
#define PLDREFunctionName__plugin_GetLpReserved "plugin_GetLpReserved"
#define PLDREFunctionName__plugin_Init          "plugin_Init"
#define PLDREFunctionName__plugin_Release       "plugin_Release"

#define PLDR_EXPORT extern "C" __declspec(dllexport) int __cdecl

#define PLDRT_DllPlugin 1
#define PLDRT_RawCodePlugin 2

#define PLDRR_SUCCESS 0
#define PLDRR_ERROR -2
#define PLDRR_IGNORE -1

#define PLDR_LpReserved__inType void**

typedef HMODULE(__stdcall *pfnLoadLibrary)(LPCSTR dllName);
typedef BOOL(__stdcall *pfnFreeLibrary)(HMODULE dllName);
typedef FARPROC(__stdcall *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef struct _LDRP_LOADED_PE {
	PIMAGE_NT_HEADERS pHeaders;
	HMODULE imageBase;
	size_t imageSize;
	LPVOID pEntryPoint;
	std::vector<HMODULE> hLoadedLibs;
	DWORD pageSize;
	pfnLoadLibrary loadLibrary;
	pfnFreeLibrary freeLibrary;
	pfnGetProcAddress getProcAddress;
} LDRP_LOADED_PE;

typedef struct _PluginDescriptor {
	HMODULE pluginBase;
	unsigned short pluginType;
	char* pluginName;
	char* pluginVersion;
	void* pfnGetLpReserved;
	void* pfnExportCallLogicModify;
} PluginDescriptor;


typedef int (__cdecl* t_plugin_Init)          (PluginDescriptor* pPlugin, unsigned int argc, char** argv);
typedef int (__cdecl* t_plugin_Release)       (PluginDescriptor* pPlugin);
typedef int (__cdecl* t_plugin_GetLpReserved) (PLDR_LpReserved__inType pReserved, LDRP_LOADED_PE* pLoadedPe);
typedef int (__cdecl* t_plugin_ExportCallLogicModify)(LDRP_LOADED_PE* pLoadedPe, void* targetExport);



#ifndef LDRServer
	
	#define LGC_GREEN 2
	#define LGC_LIGHT_GREEN 10

	#define LGC_BLUE 1
	#define LGC_LIGHT_BLUE 9

	#define LGC_CYAN 3
	#define LGC_LIGHT_CYAN 11

	#define LGC_RED 4
	#define LGC_LIGHT_RED 12

	#define LGC_YELLOW 6
	#define LGC_LIGHT_YELLOW 14

	#define LGC_RESET 15

	class Logger
	{
	protected:
		HANDLE hLog;
		bool isCustomLog = false;
		std::string loggerName;
	public:
		Logger();
		Logger(HANDLE hLog);
		~Logger();

		void setLoggerName(std::string& loggerName);

		void log(std::string& message, char code, unsigned int color);

		void logMessage(std::string& message);
		void logErrorMessage(std::string& message);
		void logWarningMessage(std::string& message);
		void logInfoMessage(std::string& message);
		void logImportantMessage(std::string& message);
	};

	Logger::Logger()
	{
		hLog = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	Logger::Logger(HANDLE logHandle)
	{
		HANDLE hDefaultLog = GetStdHandle(STD_OUTPUT_HANDLE);
		this->hLog = hLog ? hLog : hDefaultLog;

		isCustomLog = this->hLog != hDefaultLog;
	}


	Logger::~Logger()
	{
	}

	void Logger::setLoggerName(std::string & loggerName)
	{
		this->loggerName.insert(0, loggerName);
	}

	void Logger::log(std::string & message, char code, unsigned int color)
	{
		if (!isCustomLog)
			SetConsoleTextAttribute(hLog, color);

		auto t = std::time(nullptr);
		auto tm = *std::localtime(&t);

		std::ostringstream oss;
		oss << std::put_time(&tm, "%d-%m-%Y %H-%M-%S");
		std::string timstampStr = oss.str();


		std::stringstream ss;
		ss << "[" << code << "]-[" << timstampStr << "]";

		if (!loggerName.empty())
			ss << "-[" << loggerName << "]";

		ss << " " << message << std::endl;

		std::string logLine = ss.str();

		DWORD cbWrited = 0;

		if (!isCustomLog)
		{
			FlushConsoleInputBuffer(hLog);
			SetConsoleTextAttribute(hLog, color);
		}

		WriteFile(hLog, logLine.c_str(), logLine.length(), &cbWrited, NULL);

		if (!isCustomLog)
		{
			SetConsoleTextAttribute(hLog, LGC_RESET);
		}
	}

	void Logger::logMessage(std::string & message)
	{
		log(message, '+', LGC_GREEN);
	}

	void Logger::logErrorMessage(std::string & message)
	{
		log(message, '~', LGC_RED);
	}

	void Logger::logWarningMessage(std::string & message)
	{
		log(message, '!', LGC_YELLOW);
	}

	void Logger::logInfoMessage(std::string & message)
	{
		log(message, '?', LGC_BLUE);
	}

	void Logger::logImportantMessage(std::string & message)
	{
		log(message, '$', LGC_CYAN);
	}

	PLDR_EXPORT plugin_Init(PluginDescriptor* pPlugin, unsigned int argc, char** argv);
	PLDR_EXPORT plugin_Release(PluginDescriptor* pPlugin);

	PLDR_EXPORT plugin_GetLpReserved(PLDR_LpReserved__inType pReserved, LDRP_LOADED_PE* pLoadedPe);

	typedef Logger PluginLogger;

	static PluginLogger pluginMainLogger;

	PluginLogger* getLogger(std::string name)
	{
		pluginMainLogger.setLoggerName(name);
		return &pluginMainLogger;
	}

#endif 





