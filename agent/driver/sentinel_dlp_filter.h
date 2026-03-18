/*
 * sentinel_dlp_filter.h
 * SentinelDLP Minifilter Driver - Header
 *
 * Kernel-mode minifilter that intercepts file I/O on removable and
 * network volumes, forwarding events to the user-mode DLP agent
 * via a filter communication port.
 *
 * Altitude: 320100 (FSFilter Content Screener range 320000-329999)
 */

#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define SENTINEL_DLP_FILTER_NAME    L"SentinelDLPFilter"
#define SENTINEL_DLP_PORT_NAME      L"\\SentinelDLPPort"
#define SENTINEL_DLP_ALTITUDE       L"320100"
#define SENTINEL_DLP_POOL_TAG       'plDS'   /* SDlp */

/*
 * Maximum number of concurrent user-mode connections.
 * Only the DLP agent service should connect.
 */
#define SENTINEL_DLP_MAX_CONNECTIONS    1

/* Maximum file path length we track */
#define SENTINEL_DLP_MAX_PATH           1024

/* Size of the content preview sent to user-mode (first 4KB) */
#define SENTINEL_DLP_PREVIEW_SIZE       4096

/* ------------------------------------------------------------------ */
/*  Message types (driver <-> user-mode)                               */
/* ------------------------------------------------------------------ */

typedef enum _SENTINEL_MSG_TYPE {
    SentinelMsgFileWrite = 1,       /* Driver -> UM: file write detected */
    SentinelMsgFileCreate,          /* Driver -> UM: file create/open    */
    SentinelMsgVerdictAllow,        /* UM -> Driver: allow the operation */
    SentinelMsgVerdictBlock,        /* UM -> Driver: block the operation */
    SentinelMsgVerdictScanFull,     /* UM -> Driver: pend, scan full     */
    SentinelMsgScanResult,          /* UM -> Driver: scan complete       */
    SentinelMsgConfigUpdate,        /* UM -> Driver: config change       */
} SENTINEL_MSG_TYPE;

/* ------------------------------------------------------------------ */
/*  Volume type classification                                         */
/* ------------------------------------------------------------------ */

typedef enum _SENTINEL_VOLUME_TYPE {
    SentinelVolumeFixed = 0,
    SentinelVolumeRemovable,
    SentinelVolumeNetwork,
    SentinelVolumeUnknown,
} SENTINEL_VOLUME_TYPE;

/* ------------------------------------------------------------------ */
/*  Messages exchanged over the communication port                     */
/* ------------------------------------------------------------------ */

/*
 * Notification sent from driver to user-mode when a file operation
 * is intercepted on a monitored volume.
 */
#pragma pack(push, 1)
typedef struct _SENTINEL_NOTIFICATION {
    SENTINEL_MSG_TYPE   Type;
    ULONG               ProcessId;
    SENTINEL_VOLUME_TYPE VolumeType;
    LARGE_INTEGER       FileSize;
    ULONG               ContentLength;  /* Actual bytes in Content[] */
    WCHAR               FilePath[SENTINEL_DLP_MAX_PATH];
    UCHAR               Content[SENTINEL_DLP_PREVIEW_SIZE];
} SENTINEL_NOTIFICATION, *PSENTINEL_NOTIFICATION;

/*
 * Reply from user-mode back to the driver.
 */
typedef struct _SENTINEL_REPLY {
    SENTINEL_MSG_TYPE   Verdict;
    ULONG               Reserved;
} SENTINEL_REPLY, *PSENTINEL_REPLY;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Per-instance context (attached to each volume instance)            */
/* ------------------------------------------------------------------ */

typedef struct _SENTINEL_INSTANCE_CONTEXT {
    SENTINEL_VOLUME_TYPE    VolumeType;
    BOOLEAN                 MonitorEnabled;
    UNICODE_STRING          VolumeName;
    WCHAR                   VolumeNameBuffer[64];
} SENTINEL_INSTANCE_CONTEXT, *PSENTINEL_INSTANCE_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Global filter data                                                 */
/* ------------------------------------------------------------------ */

typedef struct _SENTINEL_FILTER_DATA {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    BOOLEAN         ClientConnected;
    LONG            ConnectionCount;
} SENTINEL_FILTER_DATA, *PSENTINEL_FILTER_DATA;

extern SENTINEL_FILTER_DATA gFilterData;

/* ------------------------------------------------------------------ */
/*  Function prototypes - filter registration                          */
/* ------------------------------------------------------------------ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
SentinelFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

/* Instance setup/teardown */
NTSTATUS
SentinelInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
SentinelInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

VOID
SentinelInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

/* ------------------------------------------------------------------ */
/*  Function prototypes - IRP callbacks                                */
/* ------------------------------------------------------------------ */

FLT_PREOP_CALLBACK_STATUS
SentinelPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
SentinelPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

/* ------------------------------------------------------------------ */
/*  Function prototypes - communication port                           */
/* ------------------------------------------------------------------ */

NTSTATUS
SentinelPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID
SentinelPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
SentinelPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

/* ------------------------------------------------------------------ */
/*  Function prototypes - helpers                                      */
/* ------------------------------------------------------------------ */

SENTINEL_VOLUME_TYPE
SentinelClassifyVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ DEVICE_TYPE VolumeDeviceType
);

NTSTATUS
SentinelSendNotification(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ SENTINEL_MSG_TYPE MsgType,
    _In_ PSENTINEL_INSTANCE_CONTEXT InstanceContext,
    _Out_ SENTINEL_MSG_TYPE *Verdict
);
