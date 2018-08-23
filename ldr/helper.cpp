#include "stdafx.h"
#include "helper.h"

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

bool changeLocationInPeb(std::string & newLocation, std::string& errorMsg)
{
#ifdef MODE64
	PEB* pPeb = (PEB*)__readgsqword(0x60);
#else
	PEB* pPeb = (PEB*)__readfsdword(0x30);
#endif
	char* pacsLocation = (char*)newLocation.c_str();

	PUNICODE_STRING pFullDllName = &CONTAINING_RECORD(pPeb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)->FullDllName;
	
	int cchWideChar = MultiByteToWideChar(CP_ACP, 0, pacsLocation, newLocation.length(), NULL, NULL);
	if (!cchWideChar)
	{
		errorMsg.insert(0, "Location change error: Error get size of wide char string");
		return false;
	}

	if (cchWideChar > MAX_PATH)
	{
		errorMsg.insert(0, "Location change error: Location string too big");
		return false;
	}

	wchar_t* pwcsLocation = new wchar_t [cchWideChar + 1];

	memset(pwcsLocation, 0, cchWideChar * sizeof(wchar_t) + sizeof(wchar_t));

	if (!MultiByteToWideChar(CP_UTF8, 0, pacsLocation, newLocation.length(), pwcsLocation, cchWideChar))
	{
		errorMsg.insert(0, "Location change error: Error convert to wide string");
		delete pwcsLocation;
		return false;
	}

	pFullDllName->Buffer = pwcsLocation;
	pFullDllName->Length = cchWideChar * sizeof(wchar_t);
	pFullDllName->MaximumLength = cchWideChar * sizeof(wchar_t) + sizeof(wchar_t);
	return true;
}

bool unicodeStringToAnsiString(PUNICODE_STRING src, PANSI_STRING dst)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_RtlUnicodeStringToAnsiString pfnRtlUnicodeStringToAnsiString = (ft_RtlUnicodeStringToAnsiString)GetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
	if (!pfnRtlUnicodeStringToAnsiString)
		return false;
	if (!NT_SUCCESS(pfnRtlUnicodeStringToAnsiString(dst, src, true)))
		return false;
	return true;
}

bool ansiStringToUnicodeString(PANSI_STRING src, PUNICODE_STRING dst)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_tRtlAnsiStringToUnicodeString pfnRtlAnsiStringToUnicodeString = (ft_tRtlAnsiStringToUnicodeString)GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
	if (!pfnRtlAnsiStringToUnicodeString)
		return false;
	if (!NT_SUCCESS(pfnRtlAnsiStringToUnicodeString(dst, src, true)))
		return false;
	return true;
}

unsigned int getUnixTimestamp()
{
	time_t t = std::time(0);
	unsigned int now = static_cast<unsigned int> (t);
	return now;
}

bool openFileObject(std::string& path, PHANDLE phFileObject)
{
	UNICODE_STRING us_Path;
	ANSI_STRING as_Path;
	wrpRtlInitAnsiString(&as_Path, path.c_str());
	ansiStringToUnicodeString(&as_Path, &us_Path);

	OBJECT_ATTRIBUTES objattr;
	objattr.Length = sizeof(OBJECT_ATTRIBUTES);
	objattr.Attributes = OBJ_CASE_INSENSITIVE;
	objattr.SecurityDescriptor = NULL;
	objattr.SecurityQualityOfService = NULL;
	objattr.RootDirectory = NULL;
	objattr.ObjectName = &us_Path;

	IO_STATUS_BLOCK isb;

	if (!NT_SUCCESS(wrp_NtCreateFile(phFileObject, GENERIC_ALL, &objattr, &isb, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, NULL, NULL, NULL)))
	{
		*phFileObject = INVALID_HANDLE_VALUE;
		return false;
	}

	return true;
}

bool wrpRtlInitAnsiString(PANSI_STRING  dst, PCSZ src)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_RtlInitAnsiString pfnRtlInitAnsiString = (ft_RtlInitAnsiString)GetProcAddress(hNtdll, "RtlInitAnsiString");
	if (!pfnRtlInitAnsiString)
		return false;
	pfnRtlInitAnsiString(dst, src);
	return true;
}

bool wrpRtlInitUnicodeString(PUNICODE_STRING dst, PCWSTR src)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_RtlInitUnicodeString pfnRtlInitUnicodeString = (ft_RtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	if (!pfnRtlInitUnicodeString)
		return false;
	pfnRtlInitUnicodeString(dst, src);
	return true;
}

bool wrpRtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_RtlFreeUnicodeString pfnRtlFreeUnicodeString = (ft_RtlFreeUnicodeString)GetProcAddress(hNtdll, "RtlFreeUnicodeString");
	if (!pfnRtlFreeUnicodeString)
		return false;
	pfnRtlFreeUnicodeString(UnicodeString);
	return true;
}

bool wrpRtlFreeAnsiString(PANSI_STRING AnsiString)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll)
		return false;
	ft_RtlFreeAnsiString pfnRtlFreeAnsiString = (ft_RtlFreeAnsiString)GetProcAddress(hNtdll, "RtlFreeAnsiString");
	if (!pfnRtlFreeAnsiString)
		return false;
	pfnRtlFreeAnsiString(AnsiString);
	return true;
}

NTSTATUS wrp_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	if (!g_hNtdll)
		g_hNtdll = GetModuleHandle(L"ntdll.dll");

	if (!g_pfnNtCreateFile)
		g_pfnNtCreateFile = (ft_NtCreateFile)GetProcAddress(g_hNtdll, "NtCreateFile");

	if (!g_pfnNtCreateFile)
		return -1;

	return g_pfnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, \
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS wrp_NtClose(HANDLE Handle)
{
	if (!g_hNtdll)
		g_hNtdll = GetModuleHandle(L"ntdll.dll");

	if (!g_pfnNtClose)
		g_pfnNtClose = (ft_NtClose)GetProcAddress(g_hNtdll, "NtClose");

	if (!g_pfnNtClose)
		return -1;

	return g_pfnNtClose(Handle);
}

