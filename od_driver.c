/*
 * od_driver.c - OpenDriver: a minimal, legitimate WDM kernel driver whose
 * dispatch architecture is modeled on nvlddmkm.sys, recovered by static
 * analysis of the shipped binary (REA + Ghidra). It reproduces the *shape* of
 * the real driver, not NVIDIA's logic, and touches no hardware.
 *
 * Mirrored structure (observed addresses in parentheses):
 *  - DriverEntry (FUN_1461e50b0) installs ONE dispatcher (FUN_14198ca90) into
 *    every DriverObject->MajorFunction slot and creates several device objects,
 *    each tagged with a kind at DeviceObject+0x48.
 *  - The shared dispatcher routes by that kind: the per-GPU device (0x90DE,
 *    from PCI vendor 0x10DE) goes through a per-MajorFunction table; the admin
 *    device (0x4A6E) has its own control handler (FUN_14198c1f0) and is gated by
 *    a global enable flag (DAT_1413bccb8).
 *  - The GPU DEVICE_CONTROL handler (FUN_14198dcf0) takes a remove lock,
 *    validates method and lengths, and switches on the control code. The
 *    0x8DE0014 path (FUN_140e20ff0) is the Resource-Manager control call whose
 *    input is OD_CONTROL_PARAMETERS.
 */

#include <ntddk.h>
#include "od_ioctl.h"

#define OD_POOL_TAG 'nepO' /* "Open" - appears in pool/lock diagnostics. */

/* Device-kind tags mirrored from nvlddmkm (DeviceObject+0x48). */
#define OD_DEVICE_KIND_GPU   0x90DEu
#define OD_DEVICE_KIND_ADMIN 0x4A6Eu

typedef struct _OD_DEVICE_EXTENSION {
    ULONG Kind;
    PCUNICODE_STRING SymbolicLink; /* so unload can remove the right link */
    IO_REMOVE_LOCK RemoveLock;
} OD_DEVICE_EXTENSION, *POD_DEVICE_EXTENSION;

static const UNICODE_STRING kGpuDeviceName =
    RTL_CONSTANT_STRING(L"\\Device\\OpenDriver");
static const UNICODE_STRING kGpuSymbolicLink =
    RTL_CONSTANT_STRING(L"\\DosDevices\\OpenDriver");
static const UNICODE_STRING kAdminDeviceName =
    RTL_CONSTANT_STRING(L"\\Device\\OpenDriverAdmin");
static const UNICODE_STRING kAdminSymbolicLink =
    RTL_CONSTANT_STRING(L"\\DosDevices\\OpenDriverAdmin");

/* Mirrors nvlddmkm's global enable flag for the admin device (DAT_1413bccb8). */
static BOOLEAN OdAdminEnabled = TRUE;

/* How many GPU devices this driver owns. Real driver tracks an adapter list. */
static ULONG OdGpuDeviceCount = 0;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD OdUnload;
static DRIVER_DISPATCH OdDispatchCommon;
static DRIVER_DISPATCH OdDispatchCreateClose;
static DRIVER_DISPATCH OdDispatchGpuControl;
static DRIVER_DISPATCH OdDispatchAdminControl;
static DRIVER_DISPATCH OdDispatchNotSupported;

/* Per-MajorFunction table for the GPU device, mirroring nvlddmkm's table. */
static PDRIVER_DISPATCH OdMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];

/* ---------------------------------------------------------------------------
 * Request handlers (policy): buffers and lengths only, no IRP knowledge.
 * ------------------------------------------------------------------------- */

/* Mirror of 0x8DE0040: write a 4-byte capability word. */
static NTSTATUS OdHandleGetCaps(
    _Out_writes_bytes_(outputLength) PVOID outputBuffer,
    _In_ ULONG outputLength,
    _Out_ PULONG bytesWritten)
{
    *bytesWritten = 0;

    if (outputLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *(ULONG UNALIGNED *)outputBuffer = OD_CAPS_VALUE;
    *bytesWritten = sizeof(ULONG);
    return STATUS_SUCCESS;
}

/*
 * Mirror of the 0x8DE0014 Resource-Manager control call (FUN_140e20ff0).
 * Validates the header and the embedded parameter block exactly as the real
 * driver does, then (as a safe stand-in) accepts the request.
 */
static NTSTATUS OdHandleControl(
    _In_reads_bytes_(inputLength) PVOID inputBuffer,
    _In_ ULONG inputLength,
    _In_ ULONG outputLength,
    _Out_ PULONG bytesWritten)
{
    const OD_CONTROL_PARAMETERS *params = inputBuffer;

    *bytesWritten = 0;

    /* Dispatcher-level checks from FUN_14198dcf0: minimum size, output fits. */
    if (inputLength < OD_CONTROL_MIN_INPUT) {
        return STATUS_INVALID_PARAMETER;
    }
    if (inputLength > OD_CONTROL_MAX_INPUT) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (outputLength < inputLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Handler-level checks from FUN_140e20ff0. */
    if (params->Handle0 == 0) {
        return STATUS_INVALID_HANDLE;
    }
    if ((LONG)params->Command < 0) {          /* high bit rejected in real code */
        return STATUS_ACCESS_DENIED;
    }
    if (inputLength - sizeof(OD_CONTROL_PARAMETERS) < params->ParamsSize) {
        return STATUS_INFO_LENGTH_MISMATCH; /* real returns 0xC0000023 here */
    }

    /* A real driver would route (Handle0, Object, Command, Params) to the
     * Resource Manager here. The skeleton accepts and reports outLen bytes. */
    *bytesWritten = outputLength;
    return STATUS_SUCCESS;
}

/* Mirror of the admin enumerate path (device 0x4A6E): report the GPU count. */
static NTSTATUS OdHandleAdminEnumerate(
    _Out_writes_bytes_(outputLength) PVOID outputBuffer,
    _In_ ULONG outputLength,
    _Out_ PULONG bytesWritten)
{
    OD_ADMIN_ENUMERATE_REPLY reply;

    *bytesWritten = 0;

    if (outputLength < sizeof(reply)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    reply.GpuCount = OdGpuDeviceCount;
    RtlCopyMemory(outputBuffer, &reply, sizeof(reply));
    *bytesWritten = sizeof(reply);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * IRP dispatch (adapter).
 * ------------------------------------------------------------------------- */

static NTSTATUS OdCompleteRequest(
    _Inout_ PIRP irp,
    _In_ NTSTATUS status,
    _In_ ULONG_PTR information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/*
 * The single routine registered for every MajorFunction (mirrors FUN_14198ca90):
 * route by device-kind tag, then by major function.
 */
static NTSTATUS OdDispatchCommon(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp)
{
    POD_DEVICE_EXTENSION extension = deviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    switch (extension->Kind) {
    case OD_DEVICE_KIND_GPU:
        return OdMajorFunctionTable[stack->MajorFunction](deviceObject, irp);

    case OD_DEVICE_KIND_ADMIN:
        if (!OdAdminEnabled) {
            return OdCompleteRequest(irp, STATUS_NOT_IMPLEMENTED, 0);
        }
        if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            return OdDispatchAdminControl(deviceObject, irp);
        }
        return OdMajorFunctionTable[stack->MajorFunction](deviceObject, irp);

    default:
        return OdCompleteRequest(irp, STATUS_NOT_IMPLEMENTED, 0);
    }
}

static NTSTATUS OdDispatchCreateClose(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    return OdCompleteRequest(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS OdDispatchNotSupported(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    return OdCompleteRequest(irp, STATUS_NOT_SUPPORTED, 0);
}

static NTSTATUS OdDispatchGpuControl(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp)
{
    POD_DEVICE_EXTENSION extension = deviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PVOID systemBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG bytesWritten = 0;
    NTSTATUS status;

    status = IoAcquireRemoveLock(&extension->RemoveLock, irp);
    if (!NT_SUCCESS(status)) {
        return OdCompleteRequest(irp, status, 0);
    }

    switch (controlCode) {
    case IOCTL_OD_GET_CAPS:
        status = OdHandleGetCaps(systemBuffer, outputLength, &bytesWritten);
        break;

    case IOCTL_OD_CONTROL:
        status = OdHandleControl(
            systemBuffer, inputLength, outputLength, &bytesWritten);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    IoReleaseRemoveLock(&extension->RemoveLock, irp);
    return OdCompleteRequest(irp, status, bytesWritten);
}

static NTSTATUS OdDispatchAdminControl(
    _In_ PDEVICE_OBJECT deviceObject,
    _Inout_ PIRP irp)
{
    POD_DEVICE_EXTENSION extension = deviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PVOID systemBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG bytesWritten = 0;
    NTSTATUS status;

    status = IoAcquireRemoveLock(&extension->RemoveLock, irp);
    if (!NT_SUCCESS(status)) {
        return OdCompleteRequest(irp, status, 0);
    }

    switch (controlCode) {
    case IOCTL_OD_ADMIN_ENUMERATE:
        status = OdHandleAdminEnumerate(systemBuffer, outputLength, &bytesWritten);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    IoReleaseRemoveLock(&extension->RemoveLock, irp);
    return OdCompleteRequest(irp, status, bytesWritten);
}

/* ---------------------------------------------------------------------------
 * Lifecycle.
 * ------------------------------------------------------------------------- */

static VOID OdUnload(_In_ PDRIVER_OBJECT driverObject)
{
    PDEVICE_OBJECT device;

    while ((device = driverObject->DeviceObject) != NULL) {
        POD_DEVICE_EXTENSION extension = device->DeviceExtension;
        IoDeleteSymbolicLink((PUNICODE_STRING)extension->SymbolicLink);
        IoDeleteDevice(device);
    }
}

static NTSTATUS OdCreateDevice(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PCUNICODE_STRING deviceName,
    _In_ PCUNICODE_STRING symbolicLink,
    _In_ ULONG kind)
{
    PDEVICE_OBJECT deviceObject = NULL;
    POD_DEVICE_EXTENSION extension;
    NTSTATUS status;

    status = IoCreateDevice(
        driverObject,
        sizeof(OD_DEVICE_EXTENSION),
        (PUNICODE_STRING)deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    extension = deviceObject->DeviceExtension;
    extension->Kind = kind;
    extension->SymbolicLink = symbolicLink;
    IoInitializeRemoveLock(&extension->RemoveLock, OD_POOL_TAG, 0, 0);

    status = IoCreateSymbolicLink(
        (PUNICODE_STRING)symbolicLink, (PUNICODE_STRING)deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static VOID OdInitMajorFunctionTable(void)
{
    ULONG i;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        OdMajorFunctionTable[i] = OdDispatchNotSupported;
    }

    OdMajorFunctionTable[IRP_MJ_CREATE] = OdDispatchCreateClose;
    OdMajorFunctionTable[IRP_MJ_CLOSE] = OdDispatchCreateClose;
    OdMajorFunctionTable[IRP_MJ_DEVICE_CONTROL] = OdDispatchGpuControl;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(registryPath);

    OdInitMajorFunctionTable();

    status = OdCreateDevice(
        driverObject, &kGpuDeviceName, &kGpuSymbolicLink, OD_DEVICE_KIND_GPU);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    OdGpuDeviceCount = 1;

    status = OdCreateDevice(
        driverObject, &kAdminDeviceName, &kAdminSymbolicLink, OD_DEVICE_KIND_ADMIN);
    if (!NT_SUCCESS(status)) {
        OdUnload(driverObject); /* removes the GPU device created above */
        return status;
    }

    driverObject->DriverUnload = OdUnload;

    /* One dispatcher for every major function, as nvlddmkm does. */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driverObject->MajorFunction[i] = OdDispatchCommon;
    }

    return STATUS_SUCCESS;
}
