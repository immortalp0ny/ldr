// ldr.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "args/args.hxx"

#include "NativeTargetLoader.h"
#include "Logger.h"
#include "helper.h"

#define ERROR_PARSING_CLI 0xfffffff4
#define ERROR_LOAD_FAILED 0xfffffff3


int main(int argc, char**argv)
{
	args::ArgumentParser parser("LDR (C) immortalp0ny 2017-2018", "Load code to monitoring/debuging/analyzing");
	args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });

	args::Group arguments(parser, "Arguments", args::Group::Validators::DontCare, args::Options::Global);
	args::Positional<std::string> targetPath(arguments, "Path", "Path to target file");

	args::Group commands(parser, "Commands");
	args::Command loadAsShellcode(commands, "raw", "Load as raw code");
	args::Command loadAsDll(commands, "dll", "Load as dll");
	
	args::Group flags(parser, "Flags", args::Group::Validators::DontCare, args::Options::Global);
	args::ValueFlag<unsigned int> rva(flags, "Rva", "Start rva", { 'r', "rva" });
	args::ValueFlag<unsigned int> rawOffset(flags, "RawOffset", "Start raw offset", { 'o', "offset" });
	args::ValueFlag<unsigned int> exportOrdinal(flags, "ExportOrdinal", "Start export ordinal", { 'e', "ordinal" });
	args::ValueFlag<unsigned int> fdwReason(flags, "FdwReason", "Value of fdwReason for DllMain", { 'f', "fdwReason" });
	args::ValueFlag<std::string> exportName(flags, "ExportName", "Start export name", { 'n', "exname" });
	
	args::ValueFlagList<std::string> libs(flags, "Libs", "List of libs for loading in process", { 'l', "lib" });
	
	args::Flag execMain(flags, "IsExecMain", "Execute main before jump to start", { 'm', "main" });
	args::Flag ignoreResolveImports(flags, "IgnoreImportsError ", "If this flags set loader will ignore error in imports resolving", {"ig-imp-err" });
	args::Flag infwait(flags, "IsInfinityWaitAdterCall", "Set this flag for infinity waiting after last call", { 'w', "infwait" });

	args::Group tricks(parser, "Tricks", args::Group::Validators::DontCare, args::Options::Global);
	args::ValueFlag<std::string> changeLocation(tricks, "Change location", "Change image location", { "location" });
	args::ValueFlagList<std::string> fileObjects(tricks, "FileObjects", "Append file objects to process context", { "fileobj" });


	args::Group plugins(parser, "Plugins", args::Group::Validators::DontCare, args::Options::Global);
	args::ValueFlag<std::string> pluginPathA(plugins, "Plugin", "Set plugin path for use", { "plugin" });
	args::ValueFlag<std::string> pluginCommandLine(plugins, "PluginCommandLine", "Set plugin command line", { "plugin-cl" });

	try
	{
		parser.ParseCLI(argc, argv);
	}
	catch (args::Help)
	{
		std::cout << parser;
		return ERROR_PARSING_CLI;
	}
	catch (args::ParseError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return ERROR_PARSING_CLI;
	}
	catch (args::ValidationError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return 1;
	}
	catch (args::Error& e)
	{
		std::cerr << e.what() << std::endl << parser;
		return 1;
	}

	Logger cliLogger;
	std::string loggerName = "CLI";
	cliLogger.setLoggerName(loggerName);

	unsigned int startRva = rva ? args::get(rva) : INVALID_VALUE;
	unsigned int startOffset = rawOffset ? args::get(rawOffset) : INVALID_VALUE;
	unsigned int startExportOrdinal = exportOrdinal ? args::get(exportOrdinal) : INVALID_ORDINAL_VALUE;
	unsigned int afdwReason = fdwReason ? args::get(fdwReason) : 1;
	std::string startExportName = exportName ? args::get(exportName) : "";
	
	std::vector<std::string> loadingLibs;
	if (libs) 
		loadingLibs = args::get(libs);

	LoadFlags lflags = 0;
	if (execMain)
		lflags |= LOADER_FLAG_EXEC_MAIN;

	if (ignoreResolveImports)
		lflags |= LOADER_FLAG_IGNORE_IMP_ERRORS;

	if (infwait)
		lflags |= LOADER_FLAG_INFINITY_WAIT;

	std::string path = targetPath ? args::get(targetPath) : "";

	if (path.empty())
		return ERROR_PARSING_CLI;

	if (pluginCommandLine && pluginPathA)
	{
		std::string pluginCl = args::get(pluginCommandLine);
		std::string pluginPath = args::get(pluginPathA);
	}

	NativeTargetLoader ntl(true);
	ntl.setTarget(path);
	ntl.setStartRva(startRva);
	ntl.setStartRawOffset(startOffset);
	ntl.setStartExportOrdinal(startExportOrdinal);
	ntl.setStartExportNameA((char*)startExportName.c_str());
	ntl.setLoadFlags(lflags);
	ntl.setAdditionalLibs(loadingLibs);
	ntl.setFdwReason(afdwReason);

	if (pluginCommandLine && pluginPathA)
	{
		std::string pluginCl = args::get(pluginCommandLine);
		std::string pluginPath = args::get(pluginPathA);
		ntl.setPlugin(pluginPath, pluginCl);
	}

	if (loadAsDll)
		ntl.setTargetType(TARGETTYPE_DLL);
	else
		ntl.setTargetType(TARGETTYPE_SHELLCODE);

	if (ntl.load() != ERROR_SUCCESS)
		return ERROR_LOAD_FAILED;

	//--- Perform tricks

	std::string flMessage;
	std::stringstream ss;

	if (changeLocation)
	{
		std::string newLocation = args::get(changeLocation);
		if (!newLocation.empty())
		{
			std::string clErrorMsg = "";
			if (!changeLocationInPeb(newLocation, clErrorMsg))
				cliLogger.logWarningMessage(clErrorMsg);
			else
				cliLogger.logImportantMessage(std::string("Tricks: Location change success"));
		}
		else 
		{
			cliLogger.logWarningMessage(std::string("Tricks: Empty change location string. Ignore"));
		}
	}

	std::vector<std::string> fileObjectsList;
	std::vector<HANDLE> openedHandles;
	if (fileObjects)
	{
		fileObjectsList = args::get(fileObjects);

		for (std::string& fileObjectPath : fileObjectsList)
		{
			HANDLE hFileObject;
			if (!openFileObject(fileObjectPath, &hFileObject))
			{
				ss << "Tricks: Can't open file object by path: " << fileObjectPath;
				flMessage = ss.str();
				cliLogger.logWarningMessage(flMessage);
				continue;
			}

			openedHandles.push_back(hFileObject);
		}

	}
	
	//--- Go
	ntl.run();

	//--CLI cleanup
	for (HANDLE hFileObject : openedHandles)
	{
		wrp_NtClose(hFileObject);
	}

	return 0;
}

