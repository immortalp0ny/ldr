// dllmain.cpp: определяет точку входа для приложения DLL.

#include "plugin.h"

#include "args.hxx"

#include <sstream>
#include <iostream>
#include <string>
#include <tuple>

#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{

	return TRUE;
}

std::string getLastErrorString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

bool readall(std::string& path, char ** pFileData, unsigned int* cbFileData, std::string& errorMessage)
{
	std::stringstream ss;
	HANDLE hTarget = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hTarget == INVALID_HANDLE_VALUE)
	{

		ss << "Failed open file! Error " << getLastErrorString();
		errorMessage.insert(0, ss.str());
		return false;
	}
	*cbFileData = GetFileSize(hTarget, NULL);
	if (!*cbFileData)
	{
		ss << "Failed get filesize! Error " << getLastErrorString();
		errorMessage.insert(0, ss.str());
		return false;
	}
	*pFileData = (char*)VirtualAllocEx(GetCurrentProcess(), NULL, *cbFileData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!*pFileData)
	{
		ss << "Failed allocate memory for target! Error" << getLastErrorString();
		errorMessage.insert(0, ss.str());
		return false;
	}

	DWORD readCount = 0;
	if (!ReadFile(hTarget, *pFileData, *cbFileData, &readCount, NULL))
	{
		ss << "Failed read file!Error " << getLastErrorString();
		errorMessage.insert(0, ss.str());
		return false;
	}
	CloseHandle(hTarget);
	return true;
}

static char* pluginName = "Export Caller @immortalp0ny";
static char* pluginVersion = "1.0";

PluginLogger* excalLogger = getLogger("EXCAL");

static PluginDescriptor* plgd;
static void* callargs_memory;
static size_t szArgsMemory = 0;

extern "C"
{
	void x86call(void* target, void* targetMem, size_t szArgs);
}

int to_int(int c) {
	if (!isxdigit(c)) 
		return -1; // error: non-hexadecimal digit found
	if (isdigit(c)) 
		return c - '0';
	if (isupper(c)) 
		c = tolower(c);
	return c - 'a' + 10;
}

template<class InputIterator, class OutputIterator> int
unhexlify(InputIterator first, InputIterator last, OutputIterator ascii) {
	while (first != last) {
		int top = to_int(*first++);
		int bot = to_int(*first++);
		if (top == -1 || bot == -1)
			return -1; // error
		*ascii++ = (top << 4) + bot;
	}
	return 0;
}

struct CallParametersReader
{
	void operator()(const std::string &name, const std::string &value, std::tuple<std::string, std::string> &destination)
	{
		std::istringstream f(value);
		size_t commapos = 0;
		std::string s;

		std::getline(f, s, ';');
		std::get<0>(destination) = s;
		
		std::getline(f, s, ';');
		std::get<1>(destination) = s;
	}
};

PLDR_EXPORT plugin_ExportCallLogicModify(LDRP_LOADED_PE* pLoadedPe, void* targetExport)
{
	x86call(targetExport, callargs_memory, szArgsMemory);
	return PLDRR_SUCCESS;
}


PLDR_EXPORT plugin_Init(PluginDescriptor* pPlugin, unsigned int argc, char** argv)
{
	plgd = pPlugin;
	pPlugin->pluginType = PLDRT_DllPlugin;
	pPlugin->pluginName = pluginName;
	pPlugin->pluginVersion = pluginVersion;
	pPlugin->pfnExportCallLogicModify = plugin_ExportCallLogicModify;

	args::ArgumentParser parser("Export Caller", "Parse plugin command line");
	args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });
	args::Group arguments(parser, "Arguments", args::Group::Validators::DontCare, args::Options::Global);

	args::PositionalList<std::tuple<std::string, std::string>, std::vector, CallParametersReader> callargs(arguments, 
		"MemoryPontersFileContent", "Set path to file and pass his content to calling fucntion");

	try
	{
		parser.ParseCLI(argc, argv);
	}
	catch (args::Help)
	{
		std::cout << parser;
		return PLDRR_ERROR;
	}
	catch (args::ParseError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return PLDRR_ERROR;
	}
	catch (args::ValidationError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return PLDRR_ERROR;
	}
	catch (args::Error& e)
	{
		std::cerr << e.what() << std::endl << parser;
		return PLDRR_ERROR;
	}

	std::vector<std::tuple<std::string, std::string>> callargsParsed = args::get(callargs);

	size_t maxArgsMemory = callargsParsed.size();
	callargs_memory = new char[maxArgsMemory * 4];
	unsigned int iter = 0;
	std::stringstream ss;
	std::string strMessage;

	for (std::tuple<std::string, std::string> &callarg : callargsParsed)
	{
		std::string type = std::get<0>(callarg);
		std::string value = std::get<1>(callarg);

		if (type == "db")
		{
			((char*)callargs_memory)[iter] = (char)std::stoi(value);
			iter += 1;
		}
		else if (type == "dw")
		{
			unsigned short *to = (unsigned short*)&((char*)callargs_memory)[iter];
			*to = (unsigned short)std::stoi(value);
			iter += 2;
		}
		else if (type == "dd")
		{
			DWORD *to = (DWORD*)&((char*)callargs_memory)[iter];
			*to = (DWORD)std::stoi(value);
			iter += 4;
		}
		else if (type[0] == 'o' && type[1] == 'p')
		{
			size_t szMemoryOutPoints  = std::stoi(std::string(type, 2));
			char* outptr = new char[szMemoryOutPoints];

			if (!value.empty())
			{
				if (value.length() % 2 != 0)
				{
					excalLogger->logErrorMessage(std::string("Invalid out ptr data size. Must be multiple 2"));
					delete outptr;
					delete callargs_memory;
					return PLDRR_ERROR;
				}

				if (unhexlify(value.begin(), value.end(), outptr) < 0)
				{
					excalLogger->logErrorMessage(std::string("Can't convert output ptr data from hex"));
					delete outptr;
					delete callargs_memory;
					return PLDRR_ERROR;
				}
			}

			size_t *to = (size_t*)&((char*)callargs_memory)[iter];
			*to = (size_t)outptr;

			iter += sizeof(size_t);
		}
		else if (type == "f")
		{
			char* pFileData = NULL;
			size_t fileSize = NULL;
			std::string errorMessage;
			if (!readall(value, &pFileData, &fileSize, errorMessage))
			{
				ss.str(std::string());
				ss << "Can't read file: " << value << "; Reader error: " << errorMessage;
				strMessage = ss.str();
				excalLogger->logErrorMessage(strMessage);
				delete callargs_memory;
				return PLDRR_ERROR;
			}

			size_t *to = (size_t*)&((char*)callargs_memory)[iter];
			*to = (size_t)pFileData;

			iter += sizeof(size_t);
		}
		else 
		{
			ss.str(std::string());
			ss << "Invalid argument type:1 " << type;
			strMessage = ss.str();
			excalLogger->logErrorMessage(strMessage);
			delete callargs_memory;
			return PLDRR_ERROR;
		}
	}
	szArgsMemory = iter;
	return PLDRR_SUCCESS;
}


PLDR_EXPORT plugin_Release(PluginDescriptor* pPlugin)
{
	return PLDRR_SUCCESS;
}





