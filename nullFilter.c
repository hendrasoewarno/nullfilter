//https://pubhtml5.com/dtiq/ufpk/Windows_Kernel_Programming/
#include <fltKernel.h>
#include <ntddk.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include "udf.h"

//bcdedit -set TESTSIGNING ON
//sc start nullFitler
//sc query nullFilter
//sc stop nullFilter
//sc delete nullFitler
//fltmc
//untuk perintah fltmc silakan baca: https://ss64.com/nt/fltmc.html

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

#define NULL_FILTER_FILTER_NAME     L"NullFilter"
#define EXECUTABLE_EXTENSION        L".exe;.ex_;.com;.cab;.cpl;.cmd;.pif;.run;.msi;.msp;.mst;.paf;.sys;.dll;.lib;.bat;.ws;.wsf;.wsh;.vbs;.vbscript;.ps1;.rgs;.scr;.sct"
//ada beberapa path dibutuhkan ketika pengembangan driver
#define ALLOWED_PATH                L"\\program files\\;\\program files (x86)\\;\\windows\\;\\debugview\\;\\source\\repos\\;\\programdata\\microsoft\\"
//ada beberapa process dibutuhkan ketika update virus definition defender
#define WHITELISTED_PROCESS         L"\\msmpeng.exe;\\mpsigstub.exe;\\mpam-"
//ada beberapa file dibutuhkan ketika update virus definition defender dan firefox
#define WHITELISTED_FILE            L"\\http+++;\\https+++;microsoft.com;\\mpcmdrun.exe;\\msmpeng.exe;\\msseces.exe;\\mpam-"
//https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html
//https://redcanary.com/threat-detection-report/techniques/mshta/
#define SUSPICIOUS_FILE             L"powershell.;powershell_ise.;psexec.;tasklist.exe;systeminfo.exe;\\net.exe;\\netsh.exe;\\wmic.exe;\\qprocess.exe;\\query.exe;\\qappsrv.exe;\\at.exe;\\reg.exe;\\regini.exe;\\tftp.exe;\\fsutil.exe;\\nbtstat.exe;\\nltest.exe;\\wevutil.exe;\\qwinsta.exe;\\fltmc.exe;\\schtasks.exe;\\mshta.exe;\\regsvcs.exe"
#define CHECK_DOSNAME               TRUE

UNICODE_STRING executableExtension = { sizeof(EXECUTABLE_EXTENSION) - sizeof(WCHAR), sizeof(EXECUTABLE_EXTENSION), EXECUTABLE_EXTENSION };
UNICODE_STRING allowedPath = { sizeof(ALLOWED_PATH) - sizeof(WCHAR), sizeof(ALLOWED_PATH), ALLOWED_PATH };
UNICODE_STRING whitelistedProcess = { sizeof(WHITELISTED_PROCESS) - sizeof(WCHAR), sizeof(WHITELISTED_PROCESS), WHITELISTED_PROCESS };
UNICODE_STRING whitelistedFile = { sizeof(WHITELISTED_FILE) - sizeof(WCHAR), sizeof(WHITELISTED_FILE), WHITELISTED_FILE };
UNICODE_STRING suspiciousFile = { sizeof(SUSPICIOUS_FILE) - sizeof(WCHAR), sizeof(SUSPICIOUS_FILE), SUSPICIOUS_FILE };

UNICODE_STRING executableExtension, allowedPath, whitelistedFile, suspiciousFile;

typedef struct _NULL_FILTER_DATA {

    PFLT_FILTER FilterHandle;

} NULL_FILTER_DATA, *PNULL_FILTER_DATA;


/*************************************************************************
    Prototypes for the startup and unload routines used for
    this Filter.

    Implementation in nullFilter.c
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
NullUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FLTAPI NullSetup(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType
    );

NTSTATUS
NullQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

//
//  Structure that contains all the global data structures
//  used throughout NullFilter.
//

NULL_FILTER_DATA NullFilterData;

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_textd(PAGE, NullUnload)
#pragma alloc_text(PAGE, NullQueryTeardown)
#endif

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    //DbgPrint("FltObjects %wZ\n", &FltObjects->FileObject->FileName);
    //DbgPrint("Iopb %wZ\n", &Data->Iopb->TargetFileObject->FileName);

    NTSTATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
   
    ULONG createOptions = Data->Iopb->Parameters.Create.Options;

    //if file
    if (!FlagOn(createOptions, FILE_DIRECTORY_FILE))
    {
        NTSTATUS status;

        BOOLEAN byPassByProcess = FALSE;
       
        ULONG processId = FltGetRequestorProcessId(Data);

        if (processId > 0) {

            PEPROCESS eProcess = FltGetRequestorProcess(Data);

            USHORT maximumLength = 300;
            PUNICODE_STRING processName = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool, maximumLength, 'hew');
            if (processName != NULL) {
                RtlZeroMemory(processName, maximumLength);
                status = SeLocateProcessImageName(eProcess, &processName);
                if (NT_SUCCESS(status)) {
                    DbgPrint("IRP_MJ_CREATE from pid %d(%wZ)\n", processId, processName);
                }

                UNICODE_STRING lcaseProcessName;
                RtlDowncaseUnicodeString(&lcaseProcessName, processName, TRUE);

                if (isContainSubstr(&lcaseProcessName, &whitelistedProcess)) {
                    byPassByProcess = TRUE;
                }

                //free memory
                RtlFreeUnicodeString(&lcaseProcessName);
            }            
            ExFreePool(processName);
        }
               
        PFLT_FILE_NAME_INFORMATION  fileNameInfo;
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

        if (NT_SUCCESS(status)) {

            if (CHECK_DOSNAME) {
                //Mengektrak volume
                ULONG volumeSize;
                UNICODE_STRING szVolTempPath;

                status = FltGetVolumeName(FltObjects->Volume, NULL, &volumeSize);
                szVolTempPath.MaximumLength = (USHORT)volumeSize;
                szVolTempPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, szVolTempPath.MaximumLength, 'hew');

                if (szVolTempPath.Buffer != NULL)
                {
                    status = FltGetVolumeName(FltObjects->Volume, &szVolTempPath, &volumeSize);
                    if (NT_SUCCESS(status))
                    {
                        //DbgPrint("%wZ\n", &szVolTempPath);

                        UNICODE_STRING DosName;
                        status = IoVolumeDeviceToDosName(FltObjects->FileObject->DeviceObject, &DosName);

                        if (NT_SUCCESS(status)) {

                            //DbgPrint("%wZ\n", &DosName);

                            ULONG oriDosNameLength = DosName.Length / sizeof(WCHAR);

                            status = ResizeUnicodeString(&DosName, (DosName.Length + fileNameInfo->Name.Length) * sizeof(WCHAR) + 2);

                            if (NT_SUCCESS(status)) {

                                status = RtlUnicodeStringCat(&DosName, &fileNameInfo->Name);

                                if (NT_SUCCESS(status)) {

                                    //delete VolumeName
                                    if (oriDosNameLength > 0 && szVolTempPath.Length > 0) {
                                        ULONG start = 0;
                                        for (int i = oriDosNameLength; i < (DosName.Length - szVolTempPath.Length) / sizeof(WCHAR); i++) {
                                            DosName.Buffer[i] = DosName.Buffer[i + szVolTempPath.Length / sizeof(WCHAR)];
                                            start++;
                                        }

                                        //rezise DosName after delete VolumeName
                                        DosName.Length = DosName.Length - szVolTempPath.Length;
                                    }

                                    //DbgPrint("%wZ\n", &DosName);

                                    UNICODE_STRING fullname;
                                    RtlDowncaseUnicodeString(&fullname, &DosName, TRUE);

                                    // Set variabel
                                    //RtlInitUnicodeString(&executableExtension, EXECUTABLE_EXTENSION);
                                    //RtlInitUnicodeString(&allowedPath, ALLOWED_PATH);
                                    //RtlInitUnicodeString(&whitelistedFile, WHITELISTED_FILE);
                                    //RtlInitUnicodeString(&suspiciousFile, SUSPICIOUS_FILE);

                                    //DbgPrint("%wZ\n", &fullname);
                                    //DbgPrint("%wZ\n", &executableExtension);
                                    //DbgPrint("%wZ\n", &allowedPath);
                                    //DbgPrint("%wZ\n", &whitelistedFile);
                                    //DbgPrint("%wZ\n", &suspiciousFile);

                                    if (isContainSubstr(&fullname, &whitelistedFile)) {
                                        DbgPrint("(Whitelisted) %wZ \n", &fullname);
                                    }
                                    else if (isContainSubstr(&fullname, &suspiciousFile)) {
                                        DbgPrint("(Suspicious) %wZ \n", &fullname);
                                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                                        Data->IoStatus.Information = 0;
                                        result = FLT_PREOP_COMPLETE;
                                    }
                                    else if (byPassByProcess) {
                                        DbgPrint("(ByPassByProcess) %wZ \n", &fullname);
                                    }
                                    else if (isEndsWith(&fullname, &executableExtension)) {
                                        if (!isContainSubstr(&fullname, &allowedPath)) {
                                            DbgPrint("(Executable->Blocked) %wZ \n", &fullname);
                                            Data->IoStatus.Status = STATUS_NO_SUCH_PRIVILEGE;
                                            Data->IoStatus.Information = 0;
                                            result = FLT_PREOP_COMPLETE;
                                        }
                                        else {
                                            DbgPrint("(Executable->Passed) %wZ\n", &fullname);
                                        }
                                    }
                                    else {
                                        //DbgPrint("%wZ Ok!\n", &fullname);
                                        //DbgPrint("(Non-Executable) %wZ\n", &fullname);
                                    }

                                    RtlFreeUnicodeString(&fullname);  // Free the memory
                                }
                                else {
                                    DbgPrint("Concat Failed");
                                }
                            }
                            else {
                                DbgPrint("Resize Failed");
                            }

                            ExFreePool(DosName.Buffer); // Free the memory
                        }

                        ExFreePool(szVolTempPath.Buffer); // Free the memory
                    }
                }
            }
            else {
                UNICODE_STRING fullname;
                RtlDowncaseUnicodeString(&fullname, &fileNameInfo->Name, TRUE);

                // Set variabel
                //RtlInitUnicodeString(&executableExtension, EXECUTABLE_EXTENSION);
                //RtlInitUnicodeString(&allowedPath, ALLOWED_PATH);
                //RtlInitUnicodeString(&whitelistedFile, WHITELISTED_FILE);
                //RtlInitUnicodeString(&suspiciousFile, SUSPICIOUS_FILE);

                //DbgPrint("%wZ\n", &fullname);
                //DbgPrint("%wZ\n", &executableExtension);
                //DbgPrint("%wZ\n", &allowedPath);
                //DbgPrint("%wZ\n", &whitelistedFile);
                //DbgPrint("%wZ\n", &suspiciousFile);

                if (isContainSubstr(&fullname, &whitelistedFile)) {
                    DbgPrint("(Whitelisted) %wZ \n", &fullname);
                }
                else if (isContainSubstr(&fullname, &suspiciousFile)) {
                    DbgPrint("(Suspicious) %wZ \n", &fullname);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    result = FLT_PREOP_COMPLETE;
                }
                else if (byPassByProcess) {
                    DbgPrint("(ByPassByProcess) %wZ \n", &fullname);
                }
                else if (isEndsWith(&fullname, &executableExtension)) {
                    if (!isContainSubstr(&fullname, &allowedPath)) {
                        DbgPrint("(Executable->Blocked) %wZ \n", &fullname);
                        Data->IoStatus.Status = STATUS_NO_SUCH_PRIVILEGE;
                        Data->IoStatus.Information = 0;
                        result = FLT_PREOP_COMPLETE;
                    }
                    else {
                        DbgPrint("(Executable->Passed) %wZ\n", &fullname);
                    }
                }
                else {
                    //DbgPrint("%wZ Ok!\n", &fullname);
                    //DbgPrint("(Non-Executable) %wZ\n", &fullname);
                }

                RtlFreeUnicodeString(&fullname);  // Free the memory
            }

            FltReleaseFileNameInformation(fileNameInfo);
        }
    }
    return result;
}


CONST FLT_OPERATION_REGISTRATION callbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
        PreOperationCreate,
        0
    },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    callbacks,                          //  Operation callbacks

    NullUnload,                         //  FilterUnload

    NullSetup,                          //  InstanceSetup
    NullQueryTeardown,                  //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};


/*************************************************************************
    Filter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    //
    //  Register with FltMgr
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &NullFilterData.FilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        status = FltStartFiltering( NullFilterData.FilterHandle );

        if (!NT_SUCCESS( status )) {
            FltUnregisterFilter( NullFilterData.FilterHandle );
        }

    }
    return status;
}

NTSTATUS
NullUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    if (NULL != NullFilterData.FilterHandle)
    {
        FltUnregisterFilter(NullFilterData.FilterHandle);
    }

    return STATUS_SUCCESS;
}

NTSTATUS 
FLTAPI NullSetup(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    //
    // This is called to see if a filter would like to attach an instance to the given volume.
    //

    return STATUS_SUCCESS;
}


NTSTATUS
NullQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    return STATUS_SUCCESS;
}