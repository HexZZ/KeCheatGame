#pragma once
#include "util.h"


ULONG64 LdrInPebOffset = 0x018;		//peb.ldr
ULONG64 ModListInPebOffset = 0x010;	//peb.ldr.InLoadOrderModuleList
//根据进程ID返回进程EPROCESS，失败返回NULL
ULONGLONG exebase = 0;
ULONGLONG dllbase = 0;
ULONGLONG dllbase2 = 0,dllbase2size = 0;
PEPROCESS GameProcess = NULL;
HANDLE checkTid = NULL;
HANDLE GamePid = NULL;
PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}

//枚举指定进程的模块



VOID EnumThread(PEPROCESS Process)
{
	PETHREAD Thread = NULL;
	NTSTATUS status;
	for (int i = 4; i < 100000; i += 4)
	{
		status = PsLookupThreadByThreadId((HANDLE)i, &Thread);
		if (NT_SUCCESS(status))
		{
			if (IoThreadToProcess(Thread) == Process)
			{
				ULONGLONG taddress = 0;
				ULONG retlen = 0;


				HANDLE hThread;
				OBJECT_ATTRIBUTES   ObjectAttributes;
				CLIENT_ID ClientID;

				ULONGLONG taddress2 = 0;
				InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
				ClientID.UniqueProcess = 0;
				ClientID.UniqueThread = (HANDLE)i; // TID  
				ZwOpenThread(&hThread, MAXIMUM_ALLOWED, &ObjectAttributes, &ClientID);
				
				NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &taddress, sizeof(ULONGLONG), &retlen);
				ULONGLONG base = dllbase2 + 0x5CA90;

				if (taddress== base)
				{
					DbgPrint(NT_DEBUG_NAME "检测线程 %d %p", i,taddress);
					checkTid = hThread;
					
				}
				else
				{
					ZwClose(hThread);
				}


				
				
				/*
				KAPC_STATE ApcState;
				KeStackAttachProcess(Process, &ApcState);

				if (MmIsAddressValid(taddress+1))
				{
					MDLReadMemory(taddress + 1, &taddress2, 4);
				}
				KeUnstackDetachProcess(&ApcState);
				
				DbgPrint("线程Id: %d   address:%p\n", i, taddress);
				DbgPrint("内存:%p", taddress2);
				*/
	
			}
		}
	}

}
VOID EnumModule(PEPROCESS Process)
{
	SIZE_T Peb = 0;
	SIZE_T Ldr = 0;
	PLIST_ENTRY ModListHead = 0;
	PLIST_ENTRY Module = 0;
	ANSI_STRING AnsiString;
	KAPC_STATE ks;
	//EPROCESS地址无效则退出
	if (!MmIsAddressValid(Process))
		return;
	//获取PEB地址
	Peb = (SIZE_T)PsGetProcessPeb(Process);
	//PEB地址无效则退出
	if (!Peb)
		return;
	//依附进程
	KeStackAttachProcess(Process, &ks);
	__try
	{
		//获得LDR地址
		Ldr = Peb + (SIZE_T)LdrInPebOffset;
		//测试是否可读，不可读则抛出异常退出
		ProbeForRead((CONST PVOID)Ldr, 8, 8);
		//获得链表头
		ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + ModListInPebOffset);
		//再次测试可读性
		ProbeForRead((CONST PVOID)ModListHead, 8, 8);
		//获得第一个模块的信息
		Module = ModListHead->Flink;
		while (ModListHead != Module)
		{
			//打印信息：基址、大小、DLL路径
			//DbgPrint("模块基址=%p 大小=%ld 路径=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase),\
				(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
			UNICODE_STRING exesz,dllsz,dllsz2;
			RtlInitUnicodeString(&dllsz, L"cshell_x64.dll");
			RtlInitUnicodeString(&dllsz2, L"ace-ats64.dll");
			RtlInitUnicodeString(&exesz, L"crossfire.exe");

			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &exesz, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "模块基址=%p 大小=%ld 路径=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				exebase = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);

				//UCHAR sz[2] = { 0x90,0x90 };
				//MDLWriteMemory(dllbase + 0x1088A1F, sz, 2);
				//DbgPrint(NT_DRIVER_NAME "人名透视修改 %p", dllbase + 0x1088A1F);
			}
			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &dllsz, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "模块基址=%p 大小=%ld 路径=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				dllbase = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
				
				//UCHAR sz[2] = { 0x90,0x90 };
				//MDLWriteMemory(dllbase + 0x1088A1F, sz, 2);
				//DbgPrint(NT_DRIVER_NAME "人名透视修改 %p", dllbase + 0x1088A1F);

			}

			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &dllsz2, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "模块基址=%p 大小=%ld 路径=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				dllbase2 = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
				dllbase2size = (ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage);


			}
			Module = Module->Flink;
			//测试下一个模块信息的可读性
			ProbeForRead((CONST PVOID)Module, 80, 8);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }
	//取消依附进程
	KeUnstackDetachProcess(&ks);
}

// 通过枚举的方式定位到指定的进程，这里传递一个进程名称
VOID MyEnumModule(char* ProcessName)
{
	ULONG i = 0;
	PEPROCESS eproc = NULL;
	for (i = 4; i < 100000; i = i + 4)
	{
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL)
		{
			ObDereferenceObject(eproc);
			if (strstr(PsGetProcessImageFileName(eproc), ProcessName) != NULL)
			{
				GameProcess = eproc;
				GamePid = i;
				EnumModule(eproc);  // 相等则说明是我们想要的进程，直接枚举其中的线程
				//EnumThread(eproc);
			}
		}
	}
}


BOOLEAN MDLWriteMemory2(PEPROCESS eProcess, ULONG pBaseAddress, PVOID pWriteData, ULONG writeDataSize)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	KAPC_STATE apcstate;
	NTSTATUS status;
	PEPROCESS EP;
	EP = eProcess;
	status = STATUS_SUCCESS;
	KeStackAttachProcess(EP, &apcstate);
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	_try{
		ProbeForWrite(pBaseAddress, writeDataSize, sizeof(ULONG));
		RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	}
		except(1)
	{
		MmUnmapLockedPages(pNewAddress, pMdl);
		IoFreeMdl(pMdl);
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	KeUnstackDetachProcess(&apcstate);
	ObDereferenceObject(EP);
	return TRUE;
}
BOOLEAN MDLreadMemory2(PEPROCESS eProcess, ULONG pBaseAddress, ULONG writeDataSize, PVOID Buffer)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	KAPC_STATE apcstate;
	NTSTATUS status;
	PEPROCESS EP;
	EP = eProcess;
	status = STATUS_SUCCESS;
	KeStackAttachProcess(EP, &apcstate);
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	_try{
		ProbeForRead(pBaseAddress, writeDataSize, sizeof(ULONG));
		RtlCopyMemory(Buffer, pNewAddress, writeDataSize);
	}
		except(1)
	{
		MmUnmapLockedPages(pNewAddress, pMdl);
		IoFreeMdl(pMdl);
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	KeUnstackDetachProcess(&apcstate);
	ObDereferenceObject(EP);
	return TRUE;
}


BOOLEAN MDLWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize)
{

	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	// 创建 MDL
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{

		return FALSE;
	}
	// 更新 MDL 对物理内存的描述
	MmBuildMdlForNonPagedPool(pMdl);
	// 映射到虚拟内存中
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{

		IoFreeMdl(pMdl);
		return FALSE;
	}
	// 写入数据

	RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);

	// 释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}
KIRQL  WPOFFx64()
{
	/*
	KIRQL  irql = NULL;
	irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
		*/
	UINT64  cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return  NULL;
}

void  WPONx64(KIRQL  irql)
{
	UINT64  cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	/*
	if (irql < DISPATCH_LEVEL)
		KeLowerIrql(irql);
		*/
}
BOOLEAN MDLReadMemory(PVOID pBaseAddress, PVOID pData, SIZE_T writeDataSize)
{

	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	// 创建 MDL
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{

		return FALSE;
	}
	// 更新 MDL 对物理内存的描述
	MmBuildMdlForNonPagedPool(pMdl);
	// 映射到虚拟内存中
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{

		IoFreeMdl(pMdl);
		return FALSE;
	}
	// 写入数据
	RtlCopyMemory(pData, pNewAddress, writeDataSize);
	// 释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

VOID UnicodeToChar(PUNICODE_STRING dst, char* src)
{
	ANSI_STRING string;
	RtlUnicodeStringToAnsiString(&string, dst, TRUE);
	strcpy(src, string.Buffer);
	RtlFreeAnsiString(&string);
}
VOID LoadImageNotifyRoutine
(
	__in_opt PUNICODE_STRING  FullImageName,
	__in HANDLE  ProcessId,
	__in PIMAGE_INFO  ImageInfo
)
{
	PVOID pDrvEntry;
	char szFullImageName[260] = { 0 };
	if (FullImageName != NULL && MmIsAddressValid(FullImageName))
	{
		if (ProcessId != 0)
		{
			
			
			UnicodeToChar(FullImageName, szFullImageName);
			
			if (strstr(_strlwr(szFullImageName), "ace-ats64.dll"))
			{
				MyEnumModule("crossfire.exe");
			}
			if (strstr(_strlwr(szFullImageName), "cshell_x64.dll"))
			{
				DbgPrint("模块找到");
				MyEnumModule("crossfire.exe");
				
	
			}
		}
	}
}

