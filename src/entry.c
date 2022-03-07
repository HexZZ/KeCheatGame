#include "util.h"
#include "gamehack.h"
extern ULONGLONG dllbase;
extern ULONGLONG dllbase2;
extern PEPROCESS GameProcess;
extern HANDLE checkTid;



NTSTATUS CreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION	 irpStack;
	ULONG				 ioControlCode;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	switch (ioControlCode)
	{
	case IOCTL_WALLHACK_START:
		WallHack();
		break;
	case IOCTL_WALLHACK_OFF:
		WallHackOff();
		break;


	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS NotDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	/*
	if (DeviceObject == g_objDevice || DeviceObject == g_objDeviceTcp)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(g_objDeviceTcp, Irp);
	}
	else
	{
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	*/
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	PULONG64 ntaddr = 0;
	ULONG NeededSize;
	PSYSINFO SysInfo = (PSYSINFO)&SysInfo;
	ZwQuerySystemInformation(11, NULL, 0, &NeededSize);
	SysInfo = (PSYSINFO)ExAllocatePool(PagedPool, NeededSize);
	ZwQuerySystemInformation(11, SysInfo, NeededSize, NULL);
	NtResumeThread = (ULONG64)SysInfo->BaseAddress + 0x6C5100;
	NtSuspendThread = (ULONG64)SysInfo->BaseAddress + 0x6DBC40;
	ExFreePool(SysInfo);
	//DbgPrint(NT_DRIVER_NAME "%p", NtSuspendThread);

	DriverObject->DriverUnload = DriverUnload;
	/*
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING     DeviceName, Win32Device;
	DEVICE_OBJECT DeviceObject;

	UNICODE_STRING			TargetDeviceString;
	RtlInitUnicodeString(&DeviceName, NF_DEVICE_NAME);
	RtlInitUnicodeString(&Win32Device, NF_SYMBOLIC_LINK);
	DriverObject->DriverUnload = DriverUnload;


	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = NotDispatch;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;

	DriverObject->DriverUnload = DriverUnload;


	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		&DeviceObject);
	//DriverObject->Flags |= DO_BUFFERED_IO;
	if (!NT_SUCCESS(status))
	{
		DbgPrint(NT_DEBUG_NAME ": create device failure:  0x%08lx\n", status);
		return status;
	}

	//(&DeviceObject)->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(NT_DEBUG_NAME ": create Symbolic failure: 0x%08lx\n", status);
		IoDeleteDevice(&DeviceObject);
		return status;
	}
	*/
	MyEnumModule("crossfire.exe");
	//WallHack();
	NotLandingOn();
	//DbgPrint(NT_DEBUG_NAME "人名透视开始 %p", dllbase + 0x1088A1F);


		//KeWriteProcessMemory(GameProcess, (PVOID)dllbase, 2, sz);
		//KeWriteProcessMemory2(GameProcess, (PVOID)dllbase, 2, sz);
		
	

	//PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	//PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
	return STATUS_SUCCESS;
}


void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	//DbgPrint("Unload");
	/*
	UNICODE_STRING Win32Device;
	RtlInitUnicodeString(&Win32Device, NF_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
	*/

	//flyHackOff();
	//WallHackOff();
	NotLandingOff();
	if(checkTid)
		ZwClose(checkTid);
	//PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	//PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);


}