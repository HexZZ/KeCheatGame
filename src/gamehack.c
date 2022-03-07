#include "gamehack.h"


extern ULONGLONG dllbase;
extern ULONGLONG dllbase2;
extern PEPROCESS GameProcess;
extern HANDLE checkTid;
extern HANDLE GamePid;
extern ULONGLONG exebase;

VOID WallHack()
{

	/*
	if (checkTid)
	{

		if (!NT_SUCCESS(NtSuspendThread(checkTid, 0)))
		{
			DbgPrint(NT_DEBUG_NAME "暂停失败");
		}
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}

	*/
	if (dllbase && GameProcess)
	{
		KAPC_STATE ApcState;
		KeStackAttachProcess(GameProcess, &ApcState);
		__try
		{
			ULONG num = 1;
			ULONGLONG Oneoffset = NULL;
			MDLReadMemory(dllbase+ 0x2530CA0, &Oneoffset, 8);
			if (Oneoffset)
			{
				MDLWriteMemory(Oneoffset+0x4C638, &num, 4);
				DbgPrint(NT_DEBUG_NAME "基地址%p", Oneoffset + 0x4C638);
			}
			else
			{
				DbgPrint(NT_DEBUG_NAME "找不到偏移");
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "人名透视开始 %p", dllbase + 0x1088A1F);
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}


}



VOID WallHackOff()
{
	if (dllbase && GameProcess)
	{
		KAPC_STATE ApcState;

		KeStackAttachProcess(GameProcess, &ApcState);
		__try
		{
			ULONG num = 0;
			ULONGLONG Oneoffset = NULL;
			MDLReadMemory(dllbase + 0x2530CA0, &Oneoffset, 8);
			if (Oneoffset)
			{
				MDLWriteMemory(Oneoffset + 0x4C638, &num, 4);
			}
			else
			{
				DbgPrint(NT_DEBUG_NAME "找不到偏移");
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "人名透视恢复 %p", dllbase + 0x1088A1F);

	}
	else {
		MyEnumModule("crossfire.exe");
	}

	/*
	if (checkTid)
	{


		if (!NT_SUCCESS(NtResumeThread(checkTid, 0)))
		{
			DbgPrint(NT_DEBUG_NAME "恢复失败");
		}

	}
	else
	{

		MyEnumModule("crossfire.exe");
	}

	*/
}

VOID flyHackOn()
{
	if (dllbase && GameProcess)
	{
		KAPC_STATE ApcState;
		KeStackAttachProcess(GameProcess, &ApcState);
		__try
		{
			UCHAR sz[1] = { 0x1 };
			//PsSuspendProcess(GameProcess);
			MDLWriteMemory((PVOID)(dllbase + 0x113382F), sz, 1);
			//PsResumeProcess(GameProcess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "飞天开始 %p", dllbase + 0x113382F);
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}

}

VOID flyHackOff()
{
	if (dllbase && GameProcess)
	{
		KAPC_STATE ApcState;
		KeStackAttachProcess(GameProcess, &ApcState);
		__try
		{
			UCHAR sz[1] = { 0x0 };
			//PsSuspendProcess(GameProcess);
			MDLWriteMemory((PVOID)(dllbase + 0x113382F), sz, 1);
			//PsResumeProcess(GameProcess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "飞天结束 %p", dllbase + 0x113382F);
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}

}


VOID NotLandingOn()
{
	if (exebase && GameProcess)
	{
		ULONGLONG hackaddress = NULL;
		KAPC_STATE ApcState;
		KeStackAttachProcess(GameProcess, &ApcState);
		//KIRQL kirql = WPOFFx64();
		__writecr0(__readcr0() & 0xfffffffffffeffff);
		__try
		{
			
			
			//PsSuspendProcess(GameProcess);
			
			UCHAR sz[7] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
			hackaddress = exebase + 0x11B557;
			for (int i = 0; i < 7; i++)
			{
				((PUCHAR)hackaddress)[i] = sz[i];

			}
			//RtlCopyMemory(hackaddress, sz, 7);
			DbgPrint(NT_DEBUG_NAME"修改成功");
			/*
			if (!MDLWriteMemory(hackaddress, sz, 7))
			{
				DbgPrint("修改失败");
			}
			*/
			
			
			//PsResumeProcess(GameProcess);
			
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
		__writecr0(__readcr0() | (1 << 16));
		//WPONx64(kirql);
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "NotLandingOn %p", hackaddress);
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}

}


VOID NotLandingOff()
{
	if (exebase && GameProcess)
	{
		ULONGLONG hackaddress = NULL;
		KAPC_STATE ApcState;


		KeStackAttachProcess(GameProcess, &ApcState);
		//KIRQL kirql = WPOFFx64();
		
		__writecr0(__readcr0() & 0xfffffffffffeffff);
		
			//PsSuspendProcess(GameProcess);
		__try
		{
			
			UCHAR sz[7] = { 0x4D,0x89,0x91,0xF8,0x01,0x00,0x00 };
			hackaddress = exebase + 0x11B557;


			for (int i = 0; i < 7; i++)
			{
				((PUCHAR)hackaddress)[i] = sz[i];

			}

			//RtlCopyMemory(hackaddress, sz, 7);
			DbgPrint(NT_DEBUG_NAME"修改成功");

			/*
			if (!MDLWriteMemory(hackaddress, sz, 7))
			{
				DbgPrint("修改失败");
			} 
			*/
			
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ; }
			//PsResumeProcess(GameProcess);
		//WPONx64(kirql);
		__writecr0(__readcr0() | (1 << 16));
		KeUnstackDetachProcess(&ApcState);
		DbgPrint(NT_DEBUG_NAME "NotLandingOff %p", hackaddress);
	}
	else
	{
		MyEnumModule("crossfire.exe");
	}

}