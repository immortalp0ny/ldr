#pragma once
#include <iostream>
#include <ctime>
#include <string>
#include <sstream>
#include <Windows.h>
#include <Winternl.h>

typedef NTSTATUS (__stdcall* tRtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS (__stdcall* tRtlUnicodeStringToAnsiString)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID(__stdcall* tRtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef VOID(__stdcall* tRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef VOID(__stdcall* tRtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID(__stdcall* tRtlFreeAnsiString)(PANSI_STRING AnsiString);

bool readall(std::string& path, char** pFileData, unsigned int* cbFileData, std::string& errorMessage);

// From https://stackoverflow.com/questions/1387064/how-to-get-the-error-message-from-the-error-code-returned-by-getlasterror 
std::string getLastErrorString();

bool changeLocationInPeb(std::string& newLocation, std::string& errorMsg);

bool unicodeStringToAnsiString(PUNICODE_STRING src, PANSI_STRING dst);
bool ansiStringToUnicodeString(PANSI_STRING src, PUNICODE_STRING dst);

unsigned int getUnixTimestamp();

bool wrpRtlInitAnsiString(PANSI_STRING dst, PCSZ src);
bool wrpRtlInitUnicodeString(PUNICODE_STRING dst, PCWSTR src);
bool wrpRtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
bool wrpRtlFreeAnsiString(PANSI_STRING AnsiString);
