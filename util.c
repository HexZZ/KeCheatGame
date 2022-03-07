#pragma once
#include "util.h"


ULONG64 LdrInPebOffset = 0x018;		//peb.ldr
ULONG64 ModListInPebOffset = 0x010;	//peb.ldr.InLoadOrderModuleList
//���ݽ���ID���ؽ���EPROCESS��ʧ�ܷ���NULL
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

//ö��ָ�����̵�ģ��



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
					DbgPrint(NT_DEBUG_NAME "����߳� %d %p", i,taddress);
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
				
				DbgPrint("�߳�Id: %d   address:%p\n", i, taddress);
				DbgPrint("�ڴ�:%p", taddress2);
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
	//EPROCESS��ַ��Ч���˳�
	if (!MmIsAddressValid(Process))
		return;
	//��ȡPEB��ַ
	Peb = (SIZE_T)PsGetProcessPeb(Process);
	//PEB��ַ��Ч���˳�
	if (!Peb)
		return;
	//��������
	KeStackAttachProcess(Process, &ks);
	__try
	{
		//���LDR��ַ
		Ldr = Peb + (SIZE_T)LdrInPebOffset;
		//�����Ƿ�ɶ������ɶ����׳��쳣�˳�
		ProbeForRead((CONST PVOID)Ldr, 8, 8);
		//�������ͷ
		ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + ModListInPebOffset);
		//�ٴβ��Կɶ���
		ProbeForRead((CONST PVOID)ModListHead, 8, 8);
		//��õ�һ��ģ�����Ϣ
		Module = ModListHead->Flink;
		while (ModListHead != Module)
		{
			//��ӡ��Ϣ����ַ����С��DLL·��
			//DbgPrint("ģ���ַ=%p ��С=%ld ·��=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase),\
				(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
			UNICODE_STRING exesz,dllsz,dllsz2;
			RtlInitUnicodeString(&dllsz, L"cshell_x64.dll");
			RtlInitUnicodeString(&dllsz2, L"ace-ats64.dll");
			RtlInitUnicodeString(&exesz, L"crossfire.exe");

			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &exesz, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "ģ���ַ=%p ��С=%ld ·��=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				exebase = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);

				//UCHAR sz[2] = { 0x90,0x90 };
				//MDLWriteMemory(dllbase + 0x1088A1F, sz, 2);
				//DbgPrint(NT_DRIVER_NAME "����͸���޸� %p", dllbase + 0x1088A1F);
			}
			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &dllsz, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "ģ���ַ=%p ��С=%ld ·��=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				dllbase = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
				
				//UCHAR sz[2] = { 0x90,0x90 };
				//MDLWriteMemory(dllbase + 0x1088A1F, sz, 2);
				//DbgPrint(NT_DRIVER_NAME "����͸���޸� %p", dllbase + 0x1088A1F);

			}

			if (RtlEqualUnicodeString(&(((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName), &dllsz2, TRUE))
			{
				DbgPrint(NT_DEBUG_NAME "ģ���ַ=%p ��С=%ld ·��=%wZ\n", (PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase), \
					(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage), &(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
				dllbase2 = (ULONGLONG)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
				dllbase2size = (ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage);


			}
			Module = Module->Flink;
			//������һ��ģ����Ϣ�Ŀɶ���
			ProbeForRead((CONST PVOID)Module, 80, 8);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }
	//ȡ����������
	KeUnstackDetachProcess(&ks);
}

// ͨ��ö�ٵķ�ʽ��λ��ָ���Ľ��̣����ﴫ��һ����������
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
				EnumModule(eproc);  // �����˵����������Ҫ�Ľ��̣�ֱ��ö�����е��߳�
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
	// ���� MDL
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{

		return FALSE;
	}
	// ���� MDL �������ڴ������
	MmBuildMdlForNonPagedPool(pMdl);
	// ӳ�䵽�����ڴ���
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{

		IoFreeMdl(pMdl);
		return FALSE;
	}
	// д������

	RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);

	// �ͷ�
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
	// ���� MDL
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{

		return FALSE;
	}
	// ���� MDL �������ڴ������
	MmBuildMdlForNonPagedPool(pMdl);
	// ӳ�䵽�����ڴ���
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{

		IoFreeMdl(pMdl);
		return FALSE;
	}
	// д������
	RtlCopyMemory(pData, pNewAddress, writeDataSize);
	// �ͷ�
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
				DbgPrint("ģ���ҵ�");
				MyEnumModule("crossfire.exe");
				
	
			}
		}
	}
}

