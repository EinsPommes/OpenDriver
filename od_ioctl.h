/*
 * od_ioctl.h - Shared control interface for OpenDriver.
 *
 * OpenDriver is a study reconstruction of the *structure* of nvlddmkm.sys
 * (recovered with REA + Ghidra). The IOCTL layout and the control-parameter
 * struct below mirror what was observed in the real driver's DEVICE_CONTROL
 * handler (FUN_14198dcf0) and its 0x8DE0014 Resource-Manager control path
 * (FUN_140e20ff0). It drives no hardware.
 */

#ifndef OD_IOCTL_H
#define OD_IOCTL_H

#include <winioctl.h>

/* User-mode open paths. Names are original; they drive nothing real. */
#define OD_GPU_PATH   L"\\\\.\\OpenDriver"
#define OD_ADMIN_PATH L"\\\\.\\OpenDriverAdmin"

/* Device type 0x8DE mirrors nvlddmkm's observed control codes (0x8DExxxx). */
#define OD_DEVICE_TYPE 0x8DE

/* GPU device: mirror of nvlddmkm's 0x8DE0040 (short capability query). */
#define IOCTL_OD_GET_CAPS \
    CTL_CODE(OD_DEVICE_TYPE, 0x10, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* GPU device: mirror of nvlddmkm's 0x8DE0014 (Resource-Manager control call). */
#define IOCTL_OD_CONTROL \
    CTL_CODE(OD_DEVICE_TYPE, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Admin device: mirror of the global adapter-enumeration path (device 0x4A6E). */
#define IOCTL_OD_ADMIN_ENUMERATE \
    CTL_CODE(OD_DEVICE_TYPE, 0x80, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Capability word nvlddmkm returns on the mirrored 0x8DE0040 path. */
#define OD_CAPS_VALUE 0x10000u

/* Minimum input length nvlddmkm enforces on the 0x8DE0014 path. */
#define OD_CONTROL_MIN_INPUT 0x58u

/* Upper bound so a caller cannot force an unbounded kernel copy. */
#define OD_CONTROL_MAX_INPUT 0x1000u

/*
 * Reconstructed input of the 0x8DE0014 control call (NVIDIA's RM control
 * shape): a client/object handle pair, a command word, an optional secondary
 * handle, and a variable-size parameter block that follows the header.
 *
 * Offsets are fixed by the field accesses observed in FUN_140e20ff0, so they
 * are asserted below.
 */
typedef struct _OD_CONTROL_PARAMETERS {
    ULONG     Handle0;      /* 0x00 client/root handle (resolved to an object) */
    ULONG     Reserved04;   /* 0x04 */
    ULONGLONG Object;       /* 0x08 object handle */
    ULONG     Command;      /* 0x10 command / flags (high bit rejected) */
    ULONG     Reserved14;   /* 0x14 */
    ULONGLONG Subobject;    /* 0x18 secondary handle, looked up when non-zero */
    ULONG     ParamsSize;   /* 0x20 size of Params that follow at 0x28 */
    ULONG     Reserved24;   /* 0x24 */
    /* ULONG  Params[];      0x28 embedded command parameters */
} OD_CONTROL_PARAMETERS;

C_ASSERT(FIELD_OFFSET(OD_CONTROL_PARAMETERS, Object) == 0x08);
C_ASSERT(FIELD_OFFSET(OD_CONTROL_PARAMETERS, Command) == 0x10);
C_ASSERT(FIELD_OFFSET(OD_CONTROL_PARAMETERS, Subobject) == 0x18);
C_ASSERT(FIELD_OFFSET(OD_CONTROL_PARAMETERS, ParamsSize) == 0x20);
C_ASSERT(sizeof(OD_CONTROL_PARAMETERS) == 0x28);

/* Reply for IOCTL_OD_ADMIN_ENUMERATE: how many GPU devices the driver owns. */
typedef struct _OD_ADMIN_ENUMERATE_REPLY {
    ULONG GpuCount;
} OD_ADMIN_ENUMERATE_REPLY;

#endif /* OD_IOCTL_H */
