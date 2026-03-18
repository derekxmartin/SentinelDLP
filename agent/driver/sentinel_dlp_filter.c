/*
 * sentinel_dlp_filter.c
 * SentinelDLP Minifilter Driver - Core Implementation
 *
 * Registers with Filter Manager, intercepts IRP_MJ_WRITE (pre-op)
 * and IRP_MJ_CREATE (post-op) on removable and network volumes.
 * Communicates with user-mode DLP agent via filter communication port.
 */

#include "sentinel_dlp_filter.h"

/* ------------------------------------------------------------------ */
/*  Globals                                                            */
/* ------------------------------------------------------------------ */

SENTINEL_FILTER_DATA gFilterData = { 0 };

/* ------------------------------------------------------------------ */
/*  Context definitions                                                */
/* ------------------------------------------------------------------ */

static const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_INSTANCE_CONTEXT,
        0,
        NULL,           /* CleanupCallback */
        sizeof(SENTINEL_INSTANCE_CONTEXT),
        SENTINEL_DLP_POOL_TAG,
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
        SentinelPreWrite,       /* PreOperation  */
        NULL                    /* PostOperation */
    },
    {
        IRP_MJ_CREATE,
        0,
        NULL,                   /* PreOperation  */
        SentinelPostCreate      /* PostOperation */
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
    SentinelFilterUnload,           /* FilterUnloadCallback */
    SentinelInstanceSetup,          /* InstanceSetupCallback */
    NULL,                           /* InstanceQueryTeardown */
    SentinelInstanceTeardownStart,  /* InstanceTeardownStart */
    SentinelInstanceTeardownComplete, /* InstanceTeardownComplete */
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

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: DriverEntry - loading minifilter\n"));

    /*
     * Step 1: Register the minifilter with Filter Manager.
     */
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gFilterData.Filter
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelDLP: FltRegisterFilter failed: 0x%08X\n", status));
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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelDLP: FltBuildDefaultSecurityDescriptor failed: 0x%08X\n",
            status));
        goto cleanup_filter;
    }

    RtlInitUnicodeString(&portName, SENTINEL_DLP_PORT_NAME);

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
        SentinelPortConnect,
        SentinelPortDisconnect,
        SentinelPortMessageNotify,
        SENTINEL_DLP_MAX_CONNECTIONS
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelDLP: FltCreateCommunicationPort failed: 0x%08X\n",
            status));
        goto cleanup_filter;
    }

    /*
     * Step 3: Start filtering I/O.
     */
    status = FltStartFiltering(gFilterData.Filter);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelDLP: FltStartFiltering failed: 0x%08X\n", status));
        goto cleanup_port;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Minifilter loaded successfully (altitude %ws)\n",
        SENTINEL_DLP_ALTITUDE));

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
SentinelFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Unloading minifilter\n"));

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

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Minifilter unloaded cleanly\n"));

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  Instance setup / teardown                                          */
/* ================================================================== */

NTSTATUS
SentinelInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    NTSTATUS status;
    PSENTINEL_INSTANCE_CONTEXT instanceContext = NULL;
    SENTINEL_VOLUME_TYPE volumeType;

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
    volumeType = SentinelClassifyVolume(FltObjects, VolumeDeviceType);

    /* Allocate and set instance context */
    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_INSTANCE_CONTEXT,
        sizeof(SENTINEL_INSTANCE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT *)&instanceContext
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelDLP: Failed to allocate instance context: 0x%08X\n",
            status));
        /* Attach anyway but without context — we'll skip monitoring */
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(instanceContext, sizeof(SENTINEL_INSTANCE_CONTEXT));
    instanceContext->VolumeType = volumeType;

    /*
     * Only monitor removable and network volumes by default.
     * Fixed volumes are attached to but not actively monitored.
     */
    instanceContext->MonitorEnabled =
        (volumeType == SentinelVolumeRemovable ||
         volumeType == SentinelVolumeNetwork);

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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelDLP: FltSetInstanceContext failed: 0x%08X\n", status));
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Attached to volume (type=%d, monitor=%s)\n",
        volumeType,
        instanceContext->MonitorEnabled ? "YES" : "NO"));

    return STATUS_SUCCESS;
}

VOID
SentinelInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Instance teardown start\n"));
}

VOID
SentinelInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelDLP: Instance teardown complete\n"));
}

/* ================================================================== */
/*  Volume classification                                              */
/* ================================================================== */

SENTINEL_VOLUME_TYPE
SentinelClassifyVolume(
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
        return SentinelVolumeNetwork;
    }

    /* Try to get the disk device to check characteristics */
    status = FltGetDiskDeviceObject(FltObjects->Volume, &deviceObject);
    if (NT_SUCCESS(status) && deviceObject != NULL) {
        ULONG characteristics = deviceObject->Characteristics;
        ObDereferenceObject(deviceObject);

        if (characteristics & FILE_REMOVABLE_MEDIA) {
            return SentinelVolumeRemovable;
        }
    }

    /* Default: fixed volume */
    if (VolumeDeviceType == FILE_DEVICE_DISK ||
        VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
        return SentinelVolumeFixed;
    }

    return SentinelVolumeUnknown;
}

/* ================================================================== */
/*  IRP_MJ_WRITE pre-operation callback                                */
/* ================================================================== */

FLT_PREOP_CALLBACK_STATUS
SentinelPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    NTSTATUS status;
    PSENTINEL_INSTANCE_CONTEXT instanceContext = NULL;
    SENTINEL_MSG_TYPE verdict = SentinelMsgVerdictAllow;

    *CompletionContext = NULL;

    /*
     * Fast path: if no user-mode client is connected, allow everything.
     * We don't want to block I/O when the agent isn't running.
     */
    if (!gFilterData.ClientConnected) {
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
     * Skip kernel-mode originators (paging I/O, system threads).
     * We only care about user-initiated writes.
     */
    if (Data->Iopb->IrpFlags & IRP_PAGING_IO) {
        FltReleaseContext(instanceContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Send notification to user-mode and get verdict.
     */
    status = SentinelSendNotification(
        FltObjects,
        Data,
        SentinelMsgFileWrite,
        instanceContext,
        &verdict
    );

    FltReleaseContext(instanceContext);

    if (!NT_SUCCESS(status)) {
        /* Communication failed — allow to prevent system hangs */
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelDLP: Notification failed (0x%08X), allowing write\n",
            status));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Apply verdict */
    if (verdict == SentinelMsgVerdictBlock) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SentinelDLP: BLOCKED write by PID %lu\n",
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId()));

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* SentinelMsgVerdictAllow or SentinelMsgVerdictScanFull (future) */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ================================================================== */
/*  IRP_MJ_CREATE post-operation callback                              */
/* ================================================================== */

FLT_POSTOP_CALLBACK_STATUS
SentinelPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PSENTINEL_INSTANCE_CONTEXT instanceContext = NULL;
    SENTINEL_MSG_TYPE verdict = SentinelMsgVerdictAllow;

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

    /*
     * Notify user-mode of the create event (informational).
     * We don't block creates — only writes.
     */
    status = SentinelSendNotification(
        FltObjects,
        Data,
        SentinelMsgFileCreate,
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
SentinelSendNotification(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ SENTINEL_MSG_TYPE MsgType,
    _In_ PSENTINEL_INSTANCE_CONTEXT InstanceContext,
    _Out_ SENTINEL_MSG_TYPE *Verdict
)
{
    NTSTATUS status;
    PSENTINEL_NOTIFICATION notification = NULL;
    SENTINEL_REPLY reply = { 0 };
    ULONG replyLength = sizeof(SENTINEL_REPLY);
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    LARGE_INTEGER timeout;

    *Verdict = SentinelMsgVerdictAllow;

    /* Sanity: must have a client port */
    if (gFilterData.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    /* Allocate notification from nonpaged pool (we're at IRQL <= APC) */
    notification = (PSENTINEL_NOTIFICATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SENTINEL_NOTIFICATION),
        SENTINEL_DLP_POOL_TAG
    );

    if (notification == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(notification, sizeof(SENTINEL_NOTIFICATION));

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
            (SENTINEL_DLP_MAX_PATH - 1) * sizeof(WCHAR)
        );
        RtlCopyMemory(notification->FilePath, nameInfo->Name.Buffer, copyLen);
        notification->FilePath[copyLen / sizeof(WCHAR)] = L'\0';

        FltReleaseFileNameInformation(nameInfo);
    }

    /*
     * For write operations, capture the first 4KB of content
     * as a preview for quick pattern matching.
     */
    if (MsgType == SentinelMsgFileWrite &&
        Data->Iopb->Parameters.Write.Length > 0 &&
        Data->Iopb->Parameters.Write.WriteBuffer != NULL) {

        ULONG previewLen = min(
            Data->Iopb->Parameters.Write.Length,
            SENTINEL_DLP_PREVIEW_SIZE
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
     * Send to user-mode with a 5-second timeout.
     * This prevents blocking the I/O path if user-mode is hung.
     */
    timeout.QuadPart = -50000000LL;  /* 5 seconds in 100ns units */

    status = FltSendMessage(
        gFilterData.Filter,
        &gFilterData.ClientPort,
        notification,
        sizeof(SENTINEL_NOTIFICATION),
        &reply,
        &replyLength,
        &timeout
    );

    if (NT_SUCCESS(status) && replyLength >= sizeof(SENTINEL_REPLY)) {
        *Verdict = reply.Verdict;
    } else if (status == STATUS_TIMEOUT) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelDLP: Timeout waiting for user-mode reply, allowing\n"));
        *Verdict = SentinelMsgVerdictAllow;
        status = STATUS_SUCCESS;  /* Don't fail the I/O on timeout */
    }

    ExFreePoolWithTag(notification, SENTINEL_DLP_POOL_TAG);
    return status;
}
