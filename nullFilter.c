#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include "udf.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

#define NULL_FILTER_FILTER_NAME  L"NullFilter"
#define EXECUTABLE_EXTENSION     L".exe;.com;.cmd;.inf;.pif;.run;.sys;.dll;.lib;.bat;.wsh;.vbs;.ps1"
#define ALLOWED_PATH     L"\\program files\\;\\program files (x86)\\;\\windows\\;debugview\\;\\http+++;\\https+++"
#define WHITELISTED_FILE     L"dbgview"
#define SUSPICIOUS_FILE     L"powershell.;cmd.;psexec."

UNICODE_STRING executableExtension = { sizeof(EXECUTABLE_EXTENSION) - sizeof(WCHAR), sizeof(EXECUTABLE_EXTENSION), EXECUTABLE_EXTENSION };
UNICODE_STRING allowedPath = { sizeof(ALLOWED_PATH) - sizeof(WCHAR), sizeof(ALLOWED_PATH), ALLOWED_PATH };
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
#pragma alloc_text(PAGE, NullUnload)
#pragma alloc_text(PAGE, NullQueryTeardown)
#endif

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //DbgPrint("%wZ\n", &FltObjects->FileObject->FileName);
    //DbgPrint("%wZ\n", &Data->Iopb->TargetFileObject->FileName);

    NTSTATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    //Mengektrak volume dan cetak
    NTSTATUS status;
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

                status = ResizeUnicodeString(&DosName, (DosName.Length + FltObjects->FileObject->FileName.Length) * sizeof(WCHAR) + 2);

                if (NT_SUCCESS(status)) {
                    status = RtlUnicodeStringCat(&DosName, &FltObjects->FileObject->FileName);
                    if (NT_SUCCESS(status)) {

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
                        else if (isExecutableExtension(&fullname, &executableExtension)) {
                            DbgPrint("(Executable) %wZ\n", &fullname);

                            if (!isContainSubstr(&fullname, &allowedPath)) {
                                DbgPrint("(Blocked) %wZ \n", &fullname);
                                Data->IoStatus.Status = STATUS_NO_SUCH_PRIVILEGE;
                                Data->IoStatus.Information = 0;
                                result = FLT_PREOP_COMPLETE;
                            }
                            else {
                                DbgPrint("(Passed) %wZ\n", &fullname);
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
