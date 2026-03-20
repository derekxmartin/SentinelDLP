/*
 * filter_comm.c
 * AkesoDLP Minifilter Driver - Communication Port Handlers
 *
 * Handles user-mode connection, disconnection, and message processing
 * over the filter communication port (\AkesoDLPPort).
 */

#include "akeso_dlp_filter.h"

/* ================================================================== */
/*  Port Connect callback                                              */
/* ================================================================== */

NTSTATUS
AkesoPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    /*
     * Only allow one connection at a time.
     * The DLP agent service is the sole consumer.
     */
    if (InterlockedIncrement(&gFilterData.ConnectionCount) > AKESO_DLP_MAX_CONNECTIONS) {
        InterlockedDecrement(&gFilterData.ConnectionCount);
        AKESO_WARN("Connection rejected (max connections reached)\n");
        return STATUS_CONNECTION_REFUSED;
    }

    gFilterData.ClientPort = ClientPort;
    gFilterData.ClientConnected = TRUE;
    *ConnectionCookie = NULL;

    AKESO_LOG("User-mode client connected (PID: %lu)\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  Port Disconnect callback                                           */
/* ================================================================== */

VOID
AkesoPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    AKESO_LOG("User-mode client disconnected\n");

    /*
     * Close the client port handle. This is required to properly
     * tear down the connection.
     */
    FltCloseClientPort(gFilterData.Filter, &gFilterData.ClientPort);

    gFilterData.ClientPort = NULL;
    gFilterData.ClientConnected = FALSE;
    InterlockedDecrement(&gFilterData.ConnectionCount);
}

/* ================================================================== */
/*  Port Message handler (user-mode -> driver)                         */
/* ================================================================== */

NTSTATUS
AkesoPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    AKESO_MSG_TYPE msgType;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    /*
     * Validate input buffer.
     * User-mode sends configuration commands via this channel.
     */
    if (InputBuffer == NULL || InputBufferLength < sizeof(AKESO_MSG_TYPE)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        msgType = *(AKESO_MSG_TYPE *)InputBuffer;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    switch (msgType) {
    case AkesoMsgConfigUpdate:
        AKESO_LOG("Config update received from user-mode\n");
        /*
         * Future: parse config payload to update monitoring settings,
         * volume filters, PID exclusions, etc.
         */
        break;

    default:
        AKESO_WARN("Unknown message type %d from user-mode\n", msgType);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}
