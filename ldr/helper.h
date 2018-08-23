#pragma once
#include <iostream>
#include <ctime>
#include <string>
#include <sstream>
#include <Windows.h>
#include <Winternl.h>

typedef NTSTATUS (__stdcall* ft_tRtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS (__stdcall* ft_RtlUnicodeStringToAnsiString)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID(__stdcall* ft_RtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef VOID(__stdcall* ft_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef VOID(__stdcall* ft_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID(__stdcall* ft_RtlFreeAnsiString)(PANSI_STRING AnsiString);

typedef NTSTATUS(__stdcall *ft_NtCreateFile)(
	PHANDLE                      FileHandle,
	ACCESS_MASK                   DesiredAccess,
	OBJECT_ATTRIBUTES*            ObjectAttributes,
	PIO_STATUS_BLOCK             IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG                         FileAttributes,
	ULONG                         ShareAccess,
	ULONG                         CreateDisposition,
	ULONG                         CreateOptions,
	PVOID EaBuffer,
	ULONG                         EaLength
	);

typedef NTSTATUS(__stdcall *ft_NtClose)(
	HANDLE Handle
	);

static HMODULE g_hNtdll = NULL;
static ft_NtCreateFile g_pfnNtCreateFile = NULL;
static ft_NtClose g_pfnNtClose = NULL;


NTSTATUS wrp_NtCreateFile(
	PHANDLE                      FileHandle,
	ACCESS_MASK                   DesiredAccess,
	OBJECT_ATTRIBUTES*            ObjectAttributes,
	PIO_STATUS_BLOCK             IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG                         FileAttributes,
	ULONG                         ShareAccess,
	ULONG                         CreateDisposition,
	ULONG                         CreateOptions,
	PVOID EaBuffer,
	ULONG                         EaLength
);

bool readall(std::string& path, char** pFileData, unsigned int* cbFileData, std::string& errorMessage);

// From https://stackoverflow.com/questions/1387064/how-to-get-the-error-message-from-the-error-code-returned-by-getlasterror 
std::string getLastErrorString();

bool changeLocationInPeb(std::string& newLocation, std::string& errorMsg);

bool unicodeStringToAnsiString(PUNICODE_STRING src, PANSI_STRING dst);
bool ansiStringToUnicodeString(PANSI_STRING src, PUNICODE_STRING dst);
bool openFileObject(std::string& path, PHANDLE phFileObject);

unsigned int getUnixTimestamp();

bool wrpRtlInitAnsiString(PANSI_STRING dst, PCSZ src);
bool wrpRtlInitUnicodeString(PUNICODE_STRING dst, PCWSTR src);
bool wrpRtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
bool wrpRtlFreeAnsiString(PANSI_STRING AnsiString);
NTSTATUS wrp_NtCreateFile (PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS wrp_NtClose(HANDLE Handle);
