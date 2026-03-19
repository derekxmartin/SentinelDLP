#pragma once
// ──────────────────────────────────────────────────────────────────
//  SentinelDLP — Driver ↔ User-mode Protocol
//  Shared definitions used by both the minifilter driver and the
//  user-mode agent service.  Keep this header clean of kernel-only
//  or user-only dependencies.
// ──────────────────────────────────────────────────────────────────

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <windows.h>
#include <fltUser.h>
#endif

// ── Constants ───────────────────────────────────────────────────

#define SENTINEL_DLP_PORT_NAME      L"\\SentinelDLPPort"
#define SENTINEL_DLP_MAX_PATH       1024
#define SENTINEL_DLP_PREVIEW_SIZE   4096

// ── Message types ───────────────────────────────────────────────

typedef enum _SENTINEL_MSG_TYPE {
    SentinelMsgFileWrite = 1,       // Driver -> UM: file write detected
    SentinelMsgFileCreate,          // Driver -> UM: file create/open
    SentinelMsgVerdictAllow,        // UM -> Driver: allow the operation
    SentinelMsgVerdictBlock,        // UM -> Driver: block the operation
    SentinelMsgVerdictScanFull,     // UM -> Driver: pend, scan full
    SentinelMsgScanResult,          // UM -> Driver: scan complete
    SentinelMsgConfigUpdate,        // UM -> Driver: config change
} SENTINEL_MSG_TYPE;

// ── Volume classification ───────────────────────────────────────

typedef enum _SENTINEL_VOLUME_TYPE {
    SentinelVolumeFixed = 0,
    SentinelVolumeRemovable,
    SentinelVolumeNetwork,
    SentinelVolumeUnknown,
} SENTINEL_VOLUME_TYPE;

// ── Notification: driver -> user-mode ───────────────────────────

#pragma pack(push, 1)
typedef struct _SENTINEL_NOTIFICATION {
    SENTINEL_MSG_TYPE       Type;
    ULONG                   ProcessId;
    SENTINEL_VOLUME_TYPE    VolumeType;
    LARGE_INTEGER           FileSize;
    ULONG                   ContentLength;  // Actual bytes in Content[]
    WCHAR                   FilePath[SENTINEL_DLP_MAX_PATH];
    UCHAR                   Content[SENTINEL_DLP_PREVIEW_SIZE];
} SENTINEL_NOTIFICATION, *PSENTINEL_NOTIFICATION;

// ── Reply: user-mode -> driver ──────────────────────────────────

typedef struct _SENTINEL_REPLY {
    SENTINEL_MSG_TYPE   Verdict;
    ULONG               Reserved;
} SENTINEL_REPLY, *PSENTINEL_REPLY;

/*
 * FltSendMessage wraps the notification in a FILTER_MESSAGE_HEADER.
 * The user-mode side receives:
 *   [ FILTER_MESSAGE_HEADER ] [ SENTINEL_NOTIFICATION ]
 * And replies with:
 *   [ FILTER_REPLY_HEADER ] [ SENTINEL_REPLY ]
 */
typedef struct _SENTINEL_MESSAGE {
    FILTER_MESSAGE_HEADER   Header;
    SENTINEL_NOTIFICATION   Notification;
} SENTINEL_MESSAGE, *PSENTINEL_MESSAGE;

typedef struct _SENTINEL_REPLY_MESSAGE {
    FILTER_REPLY_HEADER     Header;
    SENTINEL_REPLY          Reply;
} SENTINEL_REPLY_MESSAGE, *PSENTINEL_REPLY_MESSAGE;
#pragma pack(pop)
