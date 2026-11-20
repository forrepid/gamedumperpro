// ============================================================================
//  UnrealDumperX - driver/udxdrv.c
//  Module 8 - kernel-assisted read bridge (reference implementation).
//
//  IOCTL contract (mirrors src/driver.h):
//    IOCTL_UDX_READ  METHOD_BUFFERED, input/output struct UdxReadReq
//      { UINT64 Pid; UINT64 Src; UINT64 Dst; UINT32 Size; UINT32 Status; }
//      -> copies `Size` bytes from process Pid at Src into the user buffer.
//    IOCTL_UDX_BASE  METHOD_BUFFERED, struct UdxBaseReq
//      { UINT64 Pid; UINT64 ImageBase; UINT32 ImageSize; UINT32 Status; }
//      -> main image base/size of the target process.
//
//  Build with the WDK (driver project). Loading requires:
//      bcdedit /set testsigning on      (+ reboot)
//      sc create UnrealDumperX binPath= UnrealDumperX.sys type= kernel
//      sc start UnrealDumperX
//  or use the user-mode loader: UnrealDumperX.exe --driver-load <path.sys>
//
//  This bridge exists purely for READ STABILITY during very large scans:
//  KeStackAttachProcess + direct copy keeps working on pages that
//  ReadProcessMemory rejects from a separate process context.
// ============================================================================
#include <ntifs.h>

#define UDX_DEVICE_NAME L"\\Device\\UnrealDumperX"
#define UDX_SYMLINK     L"\\DosDevices\\UnrealDumperX"

#define IOCTL_UDX_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UDX_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _UDX_READ_REQ {
    UINT64 Pid;
    UINT64 Src;
    UINT64 Dst;      // user-mode destination pointer
    UINT32 Size;
    UINT32 Status;
} UDX_READ_REQ, *PUDX_READ_REQ;

typedef struct _UDX_BASE_REQ {
    UINT64 Pid;
    UINT64 ImageBase;
    UINT32 ImageSize;
    UINT32 Status;
} UDX_BASE_REQ, *PUDX_BASE_REQ;

// ---------------------------------------------------------------------------
// Safe copy: attach to the target, copy, detach. Falls back to MmCopyMemory
// when direct access faults.
// ---------------------------------------------------------------------------
static BOOLEAN UdxSafeRead(UINT64 pid, UINT64 src, PVOID dst, UINT32 size) {
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process)))
        return FALSE;

    KAPC_STATE apc;
    BOOLEAN ok = FALSE;
    KeStackAttachProcess(process, &apc);

    __try {
        if (MmIsAddressValid((PVOID)(ULONG_PTR)src)) {
            RtlCopyMemory(dst, (PVOID)(ULONG_PTR)src, size);
            ok = TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    KeUnstackDetachProcess(&apc);

    if (!ok) {
        // Fallback: MDL-based copy that survives more page states.
        SIZE_T copied = 0;
        MM_COPY_ADDRESS addr;
        addr.VirtualAddress = (PVOID)(ULONG_PTR)src;
        __try {
            NTSTATUS st = MmCopyMemory(dst, addr, size, MM_COPY_MEMORY_PHYSICAL,
                                       &copied);
            ok = NT_SUCCESS(st) && copied == size;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = FALSE;
        }
    }
    ObDereferenceObject(process);
    return ok;
}

static NTSTATUS UdxDispatch(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;

    const ULONG ctl = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    const PVOID inBuf = stack->Parameters.DeviceIoControl.Type3InputBuffer;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (ctl == IOCTL_UDX_READ) {
        PUDX_READ_REQ req = (PUDX_READ_REQ)irp->AssociatedIrp.SystemBuffer;
        if (!req || inLen < sizeof(UDX_READ_REQ)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            req->Status = UdxSafeRead(req->Pid, req->Src, (PVOID)req->Dst,
                                      req->Size)
                              ? 1
                              : 0;
            bytes = sizeof(UDX_READ_REQ);
        }
    } else if (ctl == IOCTL_UDX_BASE) {
        PUDX_BASE_REQ req = (PUDX_BASE_REQ)irp->AssociatedIrp.SystemBuffer;
        if (!req || inLen < sizeof(UDX_BASE_REQ)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            PEPROCESS p = NULL;
            req->Status = 0;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->Pid, &p))) {
                // Image base comes from the loader entries; a full walk is
                // left to the host - report EPROCESS SectionBaseAddress.
                req->ImageBase = (UINT64)PsGetProcessSectionBaseAddress(p);
                req->ImageSize = 0;
                req->Status = req->ImageBase ? 1 : 0;
                ObDereferenceObject(p);
            }
            bytes = sizeof(UDX_BASE_REQ);
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    UNREFERENCED_PARAMETER(outLen);
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static VOID UdxUnload(PDRIVER_OBJECT driver) {
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(UDX_SYMLINK);
    IoDeleteSymbolicLink(&symlink);
    if (driver->DeviceObject) IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(UDX_DEVICE_NAME);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(UDX_SYMLINK);
    PDEVICE_OBJECT device = NULL;

    NTSTATUS st = IoCreateDevice(driver, 0, &devName, FILE_DEVICE_UNKNOWN, 0,
                                 FALSE, &device);
    if (!NT_SUCCESS(st)) return st;

    st = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(device);
        return st;
    }

    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UdxDispatch;
    driver->DriverUnload = UdxUnload;
    device->Flags |= DO_BUFFERED_IO;
    return STATUS_SUCCESS;
}
