/*
 * od_test.c - User-mode client for OpenDriver.
 *
 * Exercises the GPU device (caps + RM-style control) and the admin device
 * (enumerate), mirroring how user-mode components reach the real driver.
 * Build as a normal console app: cl od_test.c
 */

#include <windows.h>
#include <stdio.h>
#include "od_ioctl.h"

static int GpuGetCaps(HANDLE device)
{
    unsigned long caps = 0;
    DWORD returned = 0;

    if (!DeviceIoControl(device, IOCTL_OD_GET_CAPS,
                         NULL, 0, &caps, sizeof(caps), &returned, NULL)) {
        printf("GET_CAPS failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Caps: 0x%lx (%lu bytes)\n", caps, returned);
    return 0;
}

static int GpuControl(HANDLE device)
{
    unsigned char request[OD_CONTROL_MIN_INPUT] = {0};
    unsigned char reply[OD_CONTROL_MIN_INPUT] = {0};
    OD_CONTROL_PARAMETERS *params = (OD_CONTROL_PARAMETERS *)request;
    DWORD returned = 0;

    params->Handle0 = 1;       /* must be non-zero */
    params->Command = 0x100;   /* high bit clear */
    params->ParamsSize = sizeof(request) - sizeof(OD_CONTROL_PARAMETERS);

    if (!DeviceIoControl(device, IOCTL_OD_CONTROL,
                         request, sizeof(request),
                         reply, sizeof(reply), &returned, NULL)) {
        printf("CONTROL failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Control accepted, %lu bytes returned\n", returned);
    return 0;
}

static int AdminEnumerate(void)
{
    OD_ADMIN_ENUMERATE_REPLY reply = {0};
    DWORD returned = 0;
    HANDLE admin = CreateFileW(OD_ADMIN_PATH, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (admin == INVALID_HANDLE_VALUE) {
        printf("Cannot open admin device: %lu\n", GetLastError());
        return 1;
    }

    if (!DeviceIoControl(admin, IOCTL_OD_ADMIN_ENUMERATE,
                         NULL, 0, &reply, sizeof(reply), &returned, NULL)) {
        printf("ADMIN_ENUMERATE failed: %lu\n", GetLastError());
        CloseHandle(admin);
        return 1;
    }

    printf("Admin reports %lu GPU device(s)\n", reply.GpuCount);
    CloseHandle(admin);
    return 0;
}

int main(void)
{
    HANDLE gpu = CreateFileW(OD_GPU_PATH, GENERIC_READ | GENERIC_WRITE,
                             0, NULL, OPEN_EXISTING, 0, NULL);
    if (gpu == INVALID_HANDLE_VALUE) {
        printf("Cannot open %ls: %lu (is the driver started?)\n",
               OD_GPU_PATH, GetLastError());
        return 1;
    }

    int result = GpuGetCaps(gpu);
    if (result == 0) {
        result = GpuControl(gpu);
    }
    CloseHandle(gpu);

    if (result == 0) {
        result = AdminEnumerate();
    }
    return result;
}
