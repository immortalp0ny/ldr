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
