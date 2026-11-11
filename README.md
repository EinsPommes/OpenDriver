# OpenDriver

A minimal, legitimate Windows kernel-mode (WDM) driver whose **dispatch
architecture is reconstructed from the real `nvlddmkm.sys`** (NVIDIA RTX 3060
driver, v621.14), recovered by static analysis with REA + Ghidra. It reproduces
the *shape* of the driver, not NVIDIA's logic, and touches no hardware.

## What this is — and is not

- **Is:** a clean, inspectable model of how `nvlddmkm` is wired on the Windows
  side — one shared dispatcher for all IRPs, multiple device objects
  distinguished by a kind tag, a per-MajorFunction table, a length-validated
  IOCTL handler, and the reconstructed Resource-Manager control struct.
- **Is not:** a GPU driver. Driving the RTX 3060 needs undocumented hardware
  register specs and signed GPU firmware that are not available. This is a hard
  limit, not a shortcut.

The real `nvlddmkm.sys` is ~97 MB with **51,216 functions** (a 71 MB block is
NVIDIA's Resource Manager / firmware). OpenDriver is the honest, buildable
subset: the interface shape, not the content.

## Architecture reconstructed from nvlddmkm

| Observed in nvlddmkm | Address | In OpenDriver |
|---|---|---|
| DriverEntry installs one dispatcher in all MajorFunction slots, creates devices | `FUN_1461e50b0` | `DriverEntry` + `OdCreateDevice` |
| Shared dispatcher routes by device-kind tag, then major function | `FUN_14198ca90` | `OdDispatchCommon` + `OdMajorFunctionTable` |
| Per-GPU device, tag `0x90DE` | `DeviceObject+0x48` | `OD_DEVICE_KIND_GPU` |
| Admin/global device, tag `0x4A6E`, own handler, gated by enable flag | `FUN_14198c1f0`, `DAT_1413bccb8` | `OD_DEVICE_KIND_ADMIN`, `OdAdminEnabled` |
| GPU DEVICE_CONTROL: remove lock, validate, switch on code | `FUN_14198dcf0` | `OdDispatchGpuControl` |
| 0x8DE0014 Resource-Manager control call | `FUN_140e20ff0` | `IOCTL_OD_CONTROL` + `OD_CONTROL_PARAMETERS` |

### Device-kind tags (DeviceObject+0x48)

| Tag | Role |
|---|---|
| `0x90DE` | per-GPU device (IOCTL interface) |
| `0x4A6E` | admin / global device (enumerates all adapters) |
| `0xA0DE` | further escape path (`FUN_141904a60`) — not modeled |
| `0xA033` | reserved; returns `STATUS_NOT_IMPLEMENTED` |

### GPU IOCTL codes (device type `0x8DE`, METHOD_BUFFERED)

| IoControlCode | Min length check | Modeled as |
|---|---|---|
| `0x8DE0004` | outLen ≥ 0x88 | — |
| `0x8DE0008` | inLen ≥ 0x3C, outLen ≥ inLen | — |
| `0x8DE000C` | inLen ≥ 8 | — |
| `0x8DE0010` | inLen ≥ 0x3C, outLen ≥ inLen | — |
| `0x8DE0014` | inLen ≥ 0x58, outLen ≥ inLen | `IOCTL_OD_CONTROL` |
| `0x8DE0040` | outLen ≥ 4 → returns `0x10000` | `IOCTL_OD_GET_CAPS` |
| `0x8DE0100/0104/0108` | 0x38 / 0x20 / 8 | — |

### Reconstructed input of `0x8DE0014` (`OD_CONTROL_PARAMETERS`)

NVIDIA's Resource-Manager control shape, from the field accesses in
`FUN_140e20ff0`:

| Offset | Field | Meaning |
|---|---|---|
| `0x00` | `Handle0` | client/root handle (resolved to an object) |
| `0x08` | `Object` | object handle |
| `0x10` | `Command` | command / flags (high bit rejected) |
| `0x18` | `Subobject` | secondary handle, looked up when non-zero |
| `0x20` | `ParamsSize` | size of params that follow at `0x28` |
| `0x28` | `Params[]` | embedded command parameters |

Validation mirrored: `inLen ≥ 0x58`, `outLen ≥ inLen`, `Handle0 ≠ 0`,
`Command` high bit clear, and `ParamsSize` fits in `inLen − 0x28`.

## Files

| File | Purpose |
|------|---------|
| `od_driver.c` | The kernel driver (WDM). |
| `od_ioctl.h`  | Shared IOCTL contract + control struct. |
| `od_test.c`   | User-mode program exercising both devices. |

## Build

A kernel driver needs the **Windows Driver Kit (WDK)** matching your Visual
Studio; kernel code cannot be built with a plain compiler.

1. Install **Visual Studio** + **Windows SDK** + **WDK** (same version).
2. New Project → **Empty WDM Driver**.
3. Remove the generated `.c` and add `od_driver.c` and `od_ioctl.h`.
4. Build for **x64 / Release**. Output: `OpenDriver.sys`.

The test app builds without the WDK, from a *Developer Command Prompt*:

```
cl od_test.c
```

## Load it (test machine only)

A self-built driver is **not** signed by Microsoft. Use a spare/VM test machine,
never a production system:

```powershell
bcdedit /set testsigning on          # reboot required; weakens a security boundary

sc create OpenDriver type= kernel binPath= C:\path\to\OpenDriver.sys
sc start  OpenDriver

od_test.exe

sc stop   OpenDriver
sc delete OpenDriver
bcdedit /set testsigning off         # reboot to restore normal signing
```

Expected output:

```
Caps: 0x10000 (4 bytes)
Control accepted, 88 bytes returned
Admin reports 1 GPU device(s)
```

## Safety

Kernel bugs crash the whole machine (BSOD). Test in a VM with a snapshot.
`testsigning on` lowers a Windows security protection; turn it off when done.

## Provenance

Findings come from the shipped `nvlddmkm.sys`
(SHA-256 `447c10f368d19db5f9dae9cceb690918d761f0d361d98017b7a68a54d99c6ba5`).
Ghidra pseudocode is decompiler output, not original source; addresses and
offsets are from that analysis and may shift between driver versions.
