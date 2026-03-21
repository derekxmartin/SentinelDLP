/*
 * akeso_dlp_filter.c
 * AkesoDLP Minifilter Driver - Core Implementation
 *
 * Registers with Filter Manager, intercepts IRP_MJ_WRITE (pre-op)
 * and IRP_MJ_CREATE (post-op) on removable and network volumes.
 * Communicates with user-mode DLP agent via filter communication port.
 */

#include "akeso_dlp_filter.h"

/* ------------------------------------------------------------------ */
/*  Globals                                                            */
/* ------------------------------------------------------------------ */

AKESO_FILTER_DATA gFilterData = { 0 };

/* ------------------------------------------------------------------ */
/*  Fast-path noise filtering                                          */
/* ------------------------------------------------------------------ */

/*
 * AkesoShouldSkipProcess — skip known system PIDs.
 * PID 0 = Idle, PID 4 = System.
 */
static BOOLEAN
AkesoShouldSkipProcess(void)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    return (pid == 0 || pid == 4);
}

/*
 * Extensions we never need to scan — system logs, databases,
 * temp files, registry hives, ETW traces, etc.
 */
static const UNICODE_STRING SkippedExtensions[] = {
    RTL_CONSTANT_STRING(L"evtx"),
    RTL_CONSTANT_STRING(L"etl"),
    RTL_CONSTANT_STRING(L"LOG1"),
    RTL_CONSTANT_STRING(L"LOG2"),
    RTL_CONSTANT_STRING(L"regtrans-ms"),
    RTL_CONSTANT_STRING(L"blf"),
    RTL_CONSTANT_STRING(L"tmp"),
    RTL_CONSTANT_STRING(L"TMP"),
    RTL_CONSTANT_STRING(L"pf"),
    RTL_CONSTANT_STRING(L"db-wal"),
    RTL_CONSTANT_STRING(L"db-shm"),
    RTL_CONSTANT_STRING(L"db-journal"),
    RTL_CONSTANT_STRING(L"automaticDestinations-ms"),
    RTL_CONSTANT_STRING(L"log"),
    RTL_CONSTANT_STRING(L"lnk"),
    RTL_CONSTANT_STRING(L"aodl"),
    RTL_CONSTANT_STRING(L"lock"),
    RTL_CONSTANT_STRING(L"dat"),
    RTL_CONSTANT_STRING(L"jtx"),
    RTL_CONSTANT_STRING(L"edb"),
    RTL_CONSTANT_STRING(L"srd"),
    RTL_CONSTANT_STRING(L"srd-wal"),
    RTL_CONSTANT_STRING(L"srd-shm"),
    RTL_CONSTANT_STRING(L"jfm"),
    RTL_CONSTANT_STRING(L"chk"),
    RTL_CONSTANT_STRING(L"tbres"),
};
#define SKIPPED_EXT_COUNT (sizeof(SkippedExtensions) / sizeof(SkippedExtensions[0]))

/*
 * Path prefixes that are always noise — Windows internals,
 * recycle bin, package cache, etc.
 */
static const UNICODE_STRING SkippedPaths[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\winevt\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\LogFiles\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\config\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\sru\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\Prefetch\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\appcompat\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\Temp\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\ServiceProfiles\\"),
    RTL_CONSTANT_STRING(L"\\$Recycle.Bin\\"),
    RTL_CONSTANT_STRING(L"\\System Volume Information\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Windows Defender\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Windows\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\ConnectedDevicesPlatform\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Packages\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\OneDrive\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Search\\"),
    RTL_CONSTANT_STRING(L"\\AkesoDLP\\logs\\"),
    RTL_CONSTANT_STRING(L"\\AkesoDLP\\queue\\"),
    RTL_CONSTANT_STRING(L"\\AkesoDLP\\cache\\"),
    RTL_CONSTANT_STRING(L"\\AkesoDLP\\Recovery\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Comms\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\VSApplicationInsights\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Windows\\AppRepository\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Network\\Downloader\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\Tasks\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\TokenBroker\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Microsoft\\Edge\\User Data"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Google\\Chrome\\User Data"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\Mozilla\\Firefox\\Profiles"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"),
    RTL_CONSTANT_STRING(L"\\AppData\\Local\\D3DSCache"),
    RTL_CONSTANT_STRING(L"\\ProgramData\\Microsoft\\Windows\\WER\\"),
    RTL_CONSTANT_STRING(L"\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\"),
};
#define SKIPPED_PATH_COUNT (sizeof(SkippedPaths) / sizeof(SkippedPaths[0]))

/*
 * AkesoShouldSkipFile — returns TRUE if the file should be excluded
 * from DLP scanning.  Checks file extension and path substring.
 *
 * nameInfo must already be parsed (FltParseFileNameInformation).
 */
static BOOLEAN
AkesoShouldSkipFile(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
)
{
    ULONG i;

    /* Check extension */
    if (NameInfo->Extension.Length > 0) {
        for (i = 0; i < SKIPPED_EXT_COUNT; i++) {
            if (RtlEqualUnicodeString(&NameInfo->Extension,
                    &SkippedExtensions[i], TRUE)) {
                return TRUE;
            }
        }
    }

    /* Check path substrings */
    if (NameInfo->Name.Length > 0) {
        for (i = 0; i < SKIPPED_PATH_COUNT; i++) {
            /*
             * Use a simple substring search: walk the name looking
             * for the skip pattern.  The name is like
             * \Device\HarddiskVolume2\Windows\System32\winevt\...
             * and the pattern is \Windows\System32\winevt\ — so we
             * start searching after the volume prefix.
             */
            UNICODE_STRING searchArea = NameInfo->Name;

            /* FltParseFileNameInformation gives us ParentDir and FinalComponent,
             * but it's simpler to just search the full name. */
            if (searchArea.Length >= SkippedPaths[i].Length) {
                USHORT maxOffset = searchArea.Length - SkippedPaths[i].Length;
                USHORT offset;
                BOOLEAN found = FALSE;

                for (offset = 0; offset <= maxOffset; offset += sizeof(WCHAR)) {
                    UNICODE_STRING slice;
                    slice.Buffer = (PWCH)((PUCHAR)searchArea.Buffer + offset);
                    slice.Length = SkippedPaths[i].Length;
                    slice.MaximumLength = slice.Length;

                    if (RtlEqualUnicodeString(&slice, &SkippedPaths[i], TRUE)) {
                        found = TRUE;
                        break;
                    }
                }
                if (found) return TRUE;
            }
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  Context definitions                                                */
/* ------------------------------------------------------------------ */

static const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_INSTANCE_CONTEXT,
        0,
        NULL,           /* CleanupCallback */
        sizeof(AKESO_INSTANCE_CONTEXT),
        AKESO_DLP_POOL_TAG,
        NULL,           /* Allocate */
        NULL,           /* Free    */
        NULL            /* Reserved */
    },
    { FLT_CONTEXT_END }
};

/* ------------------------------------------------------------------ */
/*  Operation callbacks                                                */
/* ------------------------------------------------------------------ */

static const FLT_OPERATION_REGISTRATION OperationCallbacks[] = {
    {
        IRP_MJ_WRITE,
        0,
        AkesoPreWrite,       /* PreOperation  */
        NULL                    /* PostOperation */
    },
    {
        IRP_MJ_CREATE,
        0,
        NULL,                   /* PreOperation  */
        AkesoPostCreate      /* PostOperation */
    },
    { IRP_MJ_OPERATION_END }
};

/* ------------------------------------------------------------------ */
/*  Filter registration structure                                      */
/* ------------------------------------------------------------------ */

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size             */
    FLT_REGISTRATION_VERSION,       /* Version          */
    0,                              /* Flags            */
    ContextRegistration,            /* ContextRegistration */
    OperationCallbacks,             /* OperationRegistration */
    AkesoFilterUnload,           /* FilterUnloadCallback */
    AkesoInstanceSetup,          /* InstanceSetupCallback */
    NULL,                           /* InstanceQueryTeardown */
    AkesoInstanceTeardownStart,  /* InstanceTeardownStart */
    AkesoInstanceTeardownComplete, /* InstanceTeardownComplete */
    NULL,                           /* GenerateFileName */
    NULL,                           /* NormalizeNameComponent */
    NULL,                           /* NormalizeContextCleanup */
    NULL,                           /* TransactionNotification */
    NULL,                           /* NormalizeNameComponentEx */
    NULL                            /* SectionNotification */
};

/* ================================================================== */
/*  DriverEntry                                                        */
/* ================================================================== */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    AKESO_LOG("DriverEntry - loading minifilter\n");

    /*
     * Step 1: Register the minifilter with Filter Manager.
     */
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gFilterData.Filter
    );

    if (!NT_SUCCESS(status)) {
        AKESO_ERR("FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    /*
     * Step 2: Create the communication port so user-mode can connect.
     *
     * We use FltBuildDefaultSecurityDescriptor to create an SD that
     * grants FLT_PORT_ALL_ACCESS to administrators only.
     */
    status = FltBuildDefaultSecurityDescriptor(
        &sd,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        AKESO_ERR("FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        goto cleanup_filter;
    }

    RtlInitUnicodeString(&portName, AKESO_DLP_PORT_NAME);

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd
    );

    status = FltCreateCommunicationPort(
        gFilterData.Filter,
        &gFilterData.ServerPort,
        &oa,
        NULL,                       /* ServerPortCookie */
        AkesoPortConnect,
        AkesoPortDisconnect,
        AkesoPortMessageNotify,
        AKESO_DLP_MAX_CONNECTIONS
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        AKESO_ERR("FltCreateCommunicationPort failed: 0x%08X\n", status);
        goto cleanup_filter;
    }

    /*
     * Step 3: Start filtering I/O.
     */
    status = FltStartFiltering(gFilterData.Filter);

    if (!NT_SUCCESS(status)) {
        AKESO_ERR("FltStartFiltering failed: 0x%08X\n", status);
        goto cleanup_port;
    }

    AKESO_LOG("Minifilter loaded successfully (altitude %ws)\n",
        AKESO_DLP_ALTITUDE);

    return STATUS_SUCCESS;

cleanup_port:
    FltCloseCommunicationPort(gFilterData.ServerPort);
    gFilterData.ServerPort = NULL;

cleanup_filter:
    FltUnregisterFilter(gFilterData.Filter);
    gFilterData.Filter = NULL;

    return status;
}

/* ================================================================== */
/*  FilterUnload                                                       */
/* ================================================================== */

NTSTATUS
AkesoFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    AKESO_LOG("Unloading minifilter\n");

    /* Close the communication port first (stops new connections) */
    if (gFilterData.ServerPort != NULL) {
        FltCloseCommunicationPort(gFilterData.ServerPort);
        gFilterData.ServerPort = NULL;
    }

    /* Unregister the filter (detaches from all volumes) */
    if (gFilterData.Filter != NULL) {
        FltUnregisterFilter(gFilterData.Filter);
        gFilterData.Filter = NULL;
    }

    AKESO_LOG("Minifilter unloaded cleanly\n");

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  Instance setup / teardown                                          */
/* ================================================================== */

NTSTATUS
AkesoInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    NTSTATUS status;
    PAKESO_INSTANCE_CONTEXT instanceContext = NULL;
    AKESO_VOLUME_TYPE volumeType;

    UNREFERENCED_PARAMETER(Flags);

    /* Skip non-disk filesystems (named pipes, mailslots, etc.) */
    if (VolumeFilesystemType == FLT_FSTYPE_RAW ||
        VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        VolumeDeviceType == FILE_DEVICE_CD_ROM ||
        VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {

        /*
         * We still attach to network devices — classified separately.
         * Only skip truly uninteresting types.
         */
        if (VolumeDeviceType == FILE_DEVICE_CD_ROM ||
            VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM ||
            VolumeFilesystemType == FLT_FSTYPE_RAW) {
            return STATUS_FLT_DO_NOT_ATTACH;
        }
    }

    /* Classify the volume type */
    volumeType = AkesoClassifyVolume(FltObjects, VolumeDeviceType);

    /* Allocate and set instance context */
    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_INSTANCE_CONTEXT,
        sizeof(AKESO_INSTANCE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT *)&instanceContext
    );

    if (!NT_SUCCESS(status)) {
        AKESO_WARN("Failed to allocate instance context: 0x%08X\n", status);
        /* Attach anyway but without context — we'll skip monitoring */
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(instanceContext, sizeof(AKESO_INSTANCE_CONTEXT));
    instanceContext->VolumeType = volumeType;

    /*
     * Monitor all volume types for now.
     * TODO: Make configurable via user-mode command — in production,
     * fixed volumes may be excluded to reduce overhead.
     */
    instanceContext->MonitorEnabled = TRUE;

    /* Store volume name for logging */
    instanceContext->VolumeName.Buffer = instanceContext->VolumeNameBuffer;
    instanceContext->VolumeName.MaximumLength = sizeof(instanceContext->VolumeNameBuffer);
    instanceContext->VolumeName.Length = 0;

    status = FltSetInstanceContext(
        FltObjects->Instance,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        instanceContext,
        NULL
    );

    /* Release our reference — FltMgr holds its own if set succeeded */
    FltReleaseContext(instanceContext);

    if (!NT_SUCCESS(status) && status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        AKESO_WARN("FltSetInstanceContext failed: 0x%08X\n", status);
    }

    AKESO_LOG("Attached to volume (type=%d, monitor=%s)\n",
        volumeType,
        instanceContext->MonitorEnabled ? "YES" : "NO");

    return STATUS_SUCCESS;
}

VOID
AkesoInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    AKESO_LOG("Instance teardown start\n");
}

VOID
AkesoInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    AKESO_LOG("Instance teardown complete\n");
}

/* ================================================================== */
/*  Volume classification                                              */
/* ================================================================== */

AKESO_VOLUME_TYPE
AkesoClassifyVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ DEVICE_TYPE VolumeDeviceType
)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(FltObjects);

    /* Network filesystems */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        VolumeDeviceType == FILE_DEVICE_NETWORK) {
        return AkesoVolumeNetwork;
    }

    /* Try to get the disk device to check characteristics */
    status = FltGetDiskDeviceObject(FltObjects->Volume, &deviceObject);
    if (NT_SUCCESS(status) && deviceObject != NULL) {
        ULONG characteristics = deviceObject->Characteristics;
        ObDereferenceObject(deviceObject);

        if (characteristics & FILE_REMOVABLE_MEDIA) {
            return AkesoVolumeRemovable;
        }
    }

    /* Default: fixed volume */
    if (VolumeDeviceType == FILE_DEVICE_DISK ||
        VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
        return AkesoVolumeFixed;
    }

    return AkesoVolumeUnknown;
}

/* ================================================================== */
/*  IRP_MJ_WRITE pre-operation callback                                */
/* ================================================================== */

FLT_PREOP_CALLBACK_STATUS
AkesoPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    NTSTATUS status;
    PAKESO_INSTANCE_CONTEXT instanceContext = NULL;
    AKESO_MSG_TYPE verdict = AkesoMsgVerdictAllow;

    *CompletionContext = NULL;

    /*
     * Fast path 1: no user-mode client — allow everything.
     */
    if (!gFilterData.ClientConnected) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Fast path 2: skip system processes and paging I/O.
     */
    if (AkesoShouldSkipProcess() ||
        (Data->Iopb->IrpFlags & IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Get instance context to check if this volume is monitored */
    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status) || instanceContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!instanceContext->MonitorEnabled) {
        FltReleaseContext(instanceContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Fast path 3: skip noise files by extension and path.
     * Get file name info for the check (and for the notification).
     */
    {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            if (AkesoShouldSkipFile(nameInfo)) {
                FltReleaseFileNameInformation(nameInfo);
                FltReleaseContext(instanceContext);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    /*
     * Send notification to user-mode and get verdict.
     */
    status = AkesoSendNotification(
        FltObjects,
        Data,
        AkesoMsgFileWrite,
        instanceContext,
        &verdict
    );

    FltReleaseContext(instanceContext);

    if (!NT_SUCCESS(status)) {
        /* Communication failed — allow to prevent system hangs */
        AKESO_WARN("Notification failed (0x%08X), allowing write\n", status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Apply verdict */
    if (verdict == AkesoMsgVerdictBlock) {
        AKESO_LOG("BLOCKED write by PID %lu\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* AkesoMsgVerdictAllow or AkesoMsgVerdictScanFull (future) */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ================================================================== */
/*  IRP_MJ_CREATE post-operation callback                              */
/* ================================================================== */

FLT_POSTOP_CALLBACK_STATUS
AkesoPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PAKESO_INSTANCE_CONTEXT instanceContext = NULL;
    AKESO_MSG_TYPE verdict = AkesoMsgVerdictAllow;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Don't process if draining (volume being dismounted) */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Only process successful creates */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip if no client connected */
    if (!gFilterData.ClientConnected) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip system processes */
    if (AkesoShouldSkipProcess()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Get instance context */
    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status) || instanceContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!instanceContext->MonitorEnabled) {
        FltReleaseContext(instanceContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /*
     * Only track creates with write intent — these indicate a file
     * is being opened for modification on a monitored volume.
     */
    if (!(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
          (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
        FltReleaseContext(instanceContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip noise files by extension and path */
    {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            if (AkesoShouldSkipFile(nameInfo)) {
                FltReleaseFileNameInformation(nameInfo);
                FltReleaseContext(instanceContext);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    /*
     * Notify user-mode of the create event (informational).
     * We don't block creates — only writes.
     */
    status = AkesoSendNotification(
        FltObjects,
        Data,
        AkesoMsgFileCreate,
        instanceContext,
        &verdict
    );

    FltReleaseContext(instanceContext);

    /* Create post-ops are informational only — never block */
    UNREFERENCED_PARAMETER(verdict);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ================================================================== */
/*  Send notification to user-mode                                     */
/* ================================================================== */

NTSTATUS
AkesoSendNotification(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ AKESO_MSG_TYPE MsgType,
    _In_ PAKESO_INSTANCE_CONTEXT InstanceContext,
    _Out_ AKESO_MSG_TYPE *Verdict
)
{
    NTSTATUS status;
    PAKESO_NOTIFICATION notification = NULL;
    AKESO_REPLY reply = { 0 };
    ULONG replyLength = sizeof(AKESO_REPLY);
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    LARGE_INTEGER timeout;

    *Verdict = AkesoMsgVerdictAllow;

    /* Sanity: must have a client port */
    if (gFilterData.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    /* Allocate notification from nonpaged pool (we're at IRQL <= APC) */
    notification = (PAKESO_NOTIFICATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(AKESO_NOTIFICATION),
        AKESO_DLP_POOL_TAG
    );

    if (notification == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(notification, sizeof(AKESO_NOTIFICATION));

    /* Fill in the notification */
    notification->Type = MsgType;
    notification->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    notification->VolumeType = InstanceContext->VolumeType;

    /* Get the file name */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        /* Copy file path (truncate if too long) */
        ULONG copyLen = min(
            nameInfo->Name.Length,
            (AKESO_DLP_MAX_PATH - 1) * sizeof(WCHAR)
        );
        RtlCopyMemory(notification->FilePath, nameInfo->Name.Buffer, copyLen);
        notification->FilePath[copyLen / sizeof(WCHAR)] = L'\0';

        FltReleaseFileNameInformation(nameInfo);
    }

    /*
     * For write operations, capture the first 4KB of content
     * as a preview for quick pattern matching.
     */
    if (MsgType == AkesoMsgFileWrite &&
        Data->Iopb->Parameters.Write.Length > 0 &&
        Data->Iopb->Parameters.Write.WriteBuffer != NULL) {

        ULONG previewLen = min(
            Data->Iopb->Parameters.Write.Length,
            AKESO_DLP_PREVIEW_SIZE
        );

        __try {
            RtlCopyMemory(
                notification->Content,
                Data->Iopb->Parameters.Write.WriteBuffer,
                previewLen
            );
            notification->ContentLength = previewLen;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            notification->ContentLength = 0;
        }
    }

    /* Get file size (best effort) */
    {
        FILE_STANDARD_INFORMATION fileInfo;
        status = FltQueryInformationFile(
            FltObjects->Instance,
            Data->Iopb->TargetFileObject,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation,
            NULL
        );
        if (NT_SUCCESS(status)) {
            notification->FileSize = fileInfo.EndOfFile;
        }
    }

    /*
     * Send to user-mode with a generous timeout.
     * Must be long enough for UserCancel dialogs (up to 120s)
     * where the user needs time to type a justification.
     * Normal Allow/Block verdicts return in ~1ms so this only
     * matters as a safety net for the dialog case.
     */
    timeout.QuadPart = -1500000000LL;  /* 150 seconds in 100ns units */

    status = FltSendMessage(
        gFilterData.Filter,
        &gFilterData.ClientPort,
        notification,
        sizeof(AKESO_NOTIFICATION),
        &reply,
        &replyLength,
        &timeout
    );

    if (NT_SUCCESS(status) && replyLength >= sizeof(AKESO_REPLY)) {
        *Verdict = reply.Verdict;
    } else if (status == STATUS_TIMEOUT) {
        AKESO_WARN("Timeout waiting for user-mode reply, allowing\n");
        *Verdict = AkesoMsgVerdictAllow;
        status = STATUS_SUCCESS;  /* Don't fail the I/O on timeout */
    }

    ExFreePoolWithTag(notification, AKESO_DLP_POOL_TAG);
    return status;
}
