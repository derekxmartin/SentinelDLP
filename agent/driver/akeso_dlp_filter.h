/*
 * akeso_dlp_filter.h
 * AkesoDLP Minifilter Driver - Header
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
/*  Debug output                                                       */
/* ------------------------------------------------------------------ */

/*
 * Use DbgPrint instead of KdPrintEx so output is visible in
 * Sysinternals DebugView on retail Windows builds without a
 * kernel debugger attached.
 */
#define AKESO_LOG(fmt, ...)   DbgPrint("AkesoDLP: " fmt, ##__VA_ARGS__)
#define AKESO_ERR(fmt, ...)   DbgPrint("AkesoDLP [ERR]: " fmt, ##__VA_ARGS__)
#define AKESO_WARN(fmt, ...)  DbgPrint("AkesoDLP [WARN]: " fmt, ##__VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define AKESO_DLP_FILTER_NAME    L"AkesoDLPFilter"
#define AKESO_DLP_PORT_NAME      L"\\AkesoDLPPort"
#define AKESO_DLP_ALTITUDE       L"320100"
#define AKESO_DLP_POOL_TAG       'plDS'   /* SDlp */

/*
 * Maximum number of concurrent user-mode connections.
 * Only the DLP agent service should connect.
 */
#define AKESO_DLP_MAX_CONNECTIONS    1

/* Maximum file path length we track */
#define AKESO_DLP_MAX_PATH           1024

/* Size of the content preview sent to user-mode (first 4KB) */
#define AKESO_DLP_PREVIEW_SIZE       4096

/* ------------------------------------------------------------------ */
/*  Message types (driver <-> user-mode)                               */
/* ------------------------------------------------------------------ */

typedef enum _AKESO_MSG_TYPE {
    AkesoMsgFileWrite = 1,       /* Driver -> UM: file write detected */
    AkesoMsgFileCreate,          /* Driver -> UM: file create/open    */
    AkesoMsgVerdictAllow,        /* UM -> Driver: allow the operation */
    AkesoMsgVerdictBlock,        /* UM -> Driver: block the operation */
    AkesoMsgVerdictScanFull,     /* UM -> Driver: pend, scan full     */
    AkesoMsgScanResult,          /* UM -> Driver: scan complete       */
    AkesoMsgConfigUpdate,        /* UM -> Driver: config change       */
} AKESO_MSG_TYPE;

/* ------------------------------------------------------------------ */
/*  Volume type classification                                         */
/* ------------------------------------------------------------------ */

typedef enum _AKESO_VOLUME_TYPE {
    AkesoVolumeFixed = 0,
    AkesoVolumeRemovable,
    AkesoVolumeNetwork,
    AkesoVolumeUnknown,
} AKESO_VOLUME_TYPE;

/* ------------------------------------------------------------------ */
/*  Messages exchanged over the communication port                     */
/* ------------------------------------------------------------------ */

/*
 * Notification sent from driver to user-mode when a file operation
 * is intercepted on a monitored volume.
 */
#pragma pack(push, 1)
typedef struct _AKESO_NOTIFICATION {
    AKESO_MSG_TYPE   Type;
    ULONG               ProcessId;
    AKESO_VOLUME_TYPE VolumeType;
    LARGE_INTEGER       FileSize;
    ULONG               ContentLength;  /* Actual bytes in Content[] */
    WCHAR               FilePath[AKESO_DLP_MAX_PATH];
    UCHAR               Content[AKESO_DLP_PREVIEW_SIZE];
} AKESO_NOTIFICATION, *PAKESO_NOTIFICATION;

/*
 * Reply from user-mode back to the driver.
 */
typedef struct _AKESO_REPLY {
    AKESO_MSG_TYPE   Verdict;
    ULONG               Reserved;
} AKESO_REPLY, *PAKESO_REPLY;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Per-instance context (attached to each volume instance)            */
/* ------------------------------------------------------------------ */

typedef struct _AKESO_INSTANCE_CONTEXT {
    AKESO_VOLUME_TYPE    VolumeType;
    BOOLEAN                 MonitorEnabled;
    UNICODE_STRING          VolumeName;
    WCHAR                   VolumeNameBuffer[64];
} AKESO_INSTANCE_CONTEXT, *PAKESO_INSTANCE_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Global filter data                                                 */
/* ------------------------------------------------------------------ */

typedef struct _AKESO_FILTER_DATA {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    BOOLEAN         ClientConnected;
    LONG            ConnectionCount;
} AKESO_FILTER_DATA, *PAKESO_FILTER_DATA;

extern AKESO_FILTER_DATA gFilterData;

/* ------------------------------------------------------------------ */
/*  Function prototypes - filter registration                          */
/* ------------------------------------------------------------------ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
AkesoFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

/* Instance setup/teardown */
NTSTATUS
AkesoInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
AkesoInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

VOID
AkesoInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

/* ------------------------------------------------------------------ */
/*  Function prototypes - IRP callbacks                                */
/* ------------------------------------------------------------------ */

FLT_PREOP_CALLBACK_STATUS
AkesoPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
AkesoPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

/* ------------------------------------------------------------------ */
/*  Function prototypes - communication port                           */
/* ------------------------------------------------------------------ */

NTSTATUS
AkesoPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID
AkesoPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
AkesoPortMessageNotify(
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

AKESO_VOLUME_TYPE
AkesoClassifyVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ DEVICE_TYPE VolumeDeviceType
);

NTSTATUS
AkesoSendNotification(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ AKESO_MSG_TYPE MsgType,
    _In_ PAKESO_INSTANCE_CONTEXT InstanceContext,
    _Out_ AKESO_MSG_TYPE *Verdict
);
