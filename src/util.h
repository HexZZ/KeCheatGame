#pragma once


#ifndef __UTIL__
#define __UTIL__


#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <intrin.h>
#define NF_DEVICE_NAME		L"\\Device\\changgedata"
#define NF_SYMBOLIC_LINK	L"\\DosDevices\\changgedata"
#define NT_DEBUG_NAME "changgedata"

#define IOCTL_WALLHACK_START 0x100006
#define IOCTL_WALLHACK_OFF 0x100007
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64	InLoadOrderLinks;
	LIST_ENTRY64	InMemoryOrderLinks;
	LIST_ENTRY64	InInitializationOrderLinks;
	PVOID			DllBase;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	USHORT			LoadCount;
	USHORT			TlsIndex;
	PVOID			SectionPointer;
	ULONG			CheckSum;
	PVOID			LoadedImports;
	PVOID			EntryPointActivationContext;
	PVOID			PatchInformation;
	LIST_ENTRY64	ForwarderLinks;
	LIST_ENTRY64	ServiceTagLinks;
	LIST_ENTRY64	StaticLinks;
	PVOID			ContextInformation;
	ULONG64			OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


VOID MyEnumModule(char* ProcessName);

//ÉùÃ÷API
VOID EnumThread(PEPROCESS Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
void DriverUnload(IN PDRIVER_OBJECT DriverObject);

NTSTATUS PsResumeProcess(PEPROCESS eProcess);
NTSTATUS PsSuspendProcess(PEPROCESS eProcess);


NTSTATUS (*NtResumeThread)(IN HANDLE	ThreadHandle,OUT PULONG	PreviousSuspendCount OPTIONAL);
NTSTATUS(*NtSuspendThread)(IN HANDLE	ThreadHandle, OUT PULONG	PreviousSuspendCount OPTIONAL);

NTSTATUS ZwOpenThread(
	_Out_  PHANDLE ThreadHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_In_   PCLIENT_ID ClientId
);
__kernel_entry NTSTATUS NtQueryInformationThread(HANDLE	ThreadHandle,THREADINFOCLASS ThreadInformationClass,PVOID	ThreadInformation,ULONG	ThreadInformationLength,PULONG	ReturnLength);

VOID CreateProcessNotifyRoutine(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
);
VOID LoadImageNotifyRoutine
(
	__in_opt PUNICODE_STRING  FullImageName,
	__in HANDLE  ProcessId,
	__in PIMAGE_INFO  ImageInfo
);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	ULONG UnKnow;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _SYSINFO {
	ULONG U;
	PVOID X[2];
	PVOID BaseAddress;
	PVOID Size;
} SYSINFO, * PSYSINFO;
KIRQL  WPOFFx64();
void  WPONx64(KIRQL  irql);
BOOLEAN MDLWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize);
BOOLEAN MDLReadMemory(PVOID pBaseAddress, PVOID pData, SIZE_T writeDataSize);
BOOLEAN MDLWriteMemory2(PEPROCESS eProcess, ULONG pBaseAddress, PVOID pWriteData, ULONG writeDataSize);
BOOLEAN MDLreadMemory2(PEPROCESS eProcess, ULONG pBaseAddress, ULONG writeDataSize, PVOID Buffer);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
#endif // !___UTIL__

