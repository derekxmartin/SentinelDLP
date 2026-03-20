/*
 * user_cancel.cpp
 * AkesoDLP Agent - User Cancel Response Action (P4-T9)
 *
 * Shows a modal Win32 dialog when a policy triggers UserCancel.
 * The dialog runs on a dedicated thread with its own message loop
 * and uses a timer for the auto-block timeout.
 *
 * Dialog layout (Win32 DialogBoxIndirect):
 *   ┌────────────────────────────────────────┐
 *   │  ⚠ AkesoDLP: Policy Violation          │
 *   │                                         │
 *   │  File: payment_report.xlsx              │
 *   │  Policy: PCI-DSS - Credit Cards         │
 *   │  Severity: CRITICAL                     │
 *   │  Matches: 3 match(es)                   │
 *   │                                         │
 *   │  This file operation requires           │
 *   │  justification to proceed.              │
 *   │                                         │
 *   │  Justification:                         │
 *   │  ┌─────────────────────────────────┐    │
 *   │  │                                 │    │
 *   │  └─────────────────────────────────┘    │
 *   │                                         │
 *   │  Time remaining: 120s                   │
 *   │                                         │
 *   │       [ Submit ]    [ Block ]           │
 *   └────────────────────────────────────────┘
 */

#include "akeso/response/user_cancel.h"

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#else
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)
#endif

#ifdef _WIN32
#include <windows.h>
#include <commctrl.h>
#endif

#include <condition_variable>
#include <mutex>
#include <thread>

namespace akeso::dlp {

/* ================================================================== */
/*  Control IDs                                                         */
/* ================================================================== */

#ifdef _WIN32

static constexpr int IDC_JUSTIFICATION_EDIT = 1001;
static constexpr int IDC_TIMER_LABEL        = 1002;
static constexpr int IDC_DETAIL_LABEL       = 1003;
static constexpr int IDC_SUBMIT_BTN         = IDOK;
static constexpr int IDC_BLOCK_BTN          = IDCANCEL;

static constexpr UINT_PTR TIMER_ID          = 1;
static constexpr UINT     TIMER_INTERVAL_MS = 1000;

/* ================================================================== */
/*  Dialog state (passed via LPARAM)                                    */
/* ================================================================== */

struct DialogState {
    std::string policy_name;
    std::string severity;
    std::string file_name;
    std::string match_summary;
    int         timeout_seconds;
    int         seconds_remaining;

    /* Output */
    std::string justification;
    bool        submitted{false};
    bool        timed_out{false};
};

/* ================================================================== */
/*  Dialog procedure                                                    */
/* ================================================================== */

static INT_PTR CALLBACK UserCancelDlgProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    DialogState* state = reinterpret_cast<DialogState*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_INITDIALOG: {
        state = reinterpret_cast<DialogState*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

        /* Build detail text */
        auto toWide = [](const std::string& s) -> std::wstring {
            if (s.empty()) return L"";
            int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            std::wstring ws(len - 1, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
            return ws;
        };

        /* Extract just the filename */
        std::string display_name = state->file_name;
        auto pos = display_name.find_last_of("/\\");
        if (pos != std::string::npos) {
            display_name = display_name.substr(pos + 1);
        }

        std::string detail =
            "File: " + display_name + "\r\n"
            "Policy: " + state->policy_name + "\r\n"
            "Severity: " + state->severity + "\r\n"
            "Matches: " + state->match_summary + "\r\n\r\n"
            "This file operation requires justification to proceed.\r\n"
            "Enter a reason below or click Block to deny.";

        SetDlgItemTextW(hwnd, IDC_DETAIL_LABEL, toWide(detail).c_str());

        /* Set initial timer label */
        state->seconds_remaining = state->timeout_seconds;
        wchar_t timer_text[64];
        swprintf_s(timer_text, L"Time remaining: %ds", state->seconds_remaining);
        SetDlgItemTextW(hwnd, IDC_TIMER_LABEL, timer_text);

        /* Start countdown timer */
        SetTimer(hwnd, TIMER_ID, TIMER_INTERVAL_MS, nullptr);

        /* Focus on justification field */
        SetFocus(GetDlgItem(hwnd, IDC_JUSTIFICATION_EDIT));

        /* Center dialog on screen */
        RECT rc;
        GetWindowRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;
        int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE);

        return FALSE;  /* We set focus manually */
    }

    case WM_TIMER:
        if (wParam == TIMER_ID && state) {
            state->seconds_remaining--;

            wchar_t timer_text[64];
            swprintf_s(timer_text, L"Time remaining: %ds", state->seconds_remaining);
            SetDlgItemTextW(hwnd, IDC_TIMER_LABEL, timer_text);

            if (state->seconds_remaining <= 0) {
                KillTimer(hwnd, TIMER_ID);
                state->timed_out = true;
                state->submitted = false;
                EndDialog(hwnd, IDCANCEL);
            }
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_SUBMIT_BTN: {
            if (!state) break;

            /* Get justification text */
            wchar_t buf[1024] = {};
            GetDlgItemTextW(hwnd, IDC_JUSTIFICATION_EDIT, buf, 1024);

            /* Require non-empty justification */
            if (wcslen(buf) == 0) {
                MessageBoxW(hwnd,
                    L"Please enter a justification to proceed.",
                    L"AkesoDLP", MB_OK | MB_ICONWARNING);
                SetFocus(GetDlgItem(hwnd, IDC_JUSTIFICATION_EDIT));
                return TRUE;
            }

            /* Convert to UTF-8 */
            int utf8_len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            state->justification.resize(utf8_len - 1);
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, state->justification.data(), utf8_len, nullptr, nullptr);

            state->submitted = true;
            KillTimer(hwnd, TIMER_ID);
            EndDialog(hwnd, IDOK);
            return TRUE;
        }

        case IDC_BLOCK_BTN:
            if (state) {
                state->submitted = false;
                KillTimer(hwnd, TIMER_ID);
            }
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        if (state) {
            state->submitted = false;
            KillTimer(hwnd, TIMER_ID);
        }
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }

    return FALSE;
}

/* ================================================================== */
/*  Dialog template (built in memory)                                   */
/* ================================================================== */

/*
 * Build a DLGTEMPLATE in memory. This avoids needing a .rc resource file.
 * Layout: detail label, justification edit, timer label, Submit + Block buttons.
 */
static std::vector<BYTE> BuildDialogTemplate()
{
    /* Helper: align pointer to DWORD boundary */
    auto align4 = [](size_t offset) -> size_t {
        return (offset + 3) & ~size_t(3);
    };

    /* Helper: append wide string */
    auto appendStr = [](std::vector<BYTE>& buf, const wchar_t* str) {
        size_t len = (wcslen(str) + 1) * sizeof(wchar_t);
        size_t off = buf.size();
        buf.resize(off + len);
        memcpy(buf.data() + off, str, len);
    };

    /* Helper: pad to DWORD alignment */
    auto padAlign = [](std::vector<BYTE>& buf) {
        while (buf.size() % 4 != 0) buf.push_back(0);
    };

    std::vector<BYTE> buf;

    /* Dialog header (DLGTEMPLATE) */
    DLGTEMPLATE dlg = {};
    dlg.style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT;
    dlg.cdit = 5;   /* 5 controls */
    dlg.cx = 280;
    dlg.cy = 200;

    buf.resize(sizeof(DLGTEMPLATE));
    memcpy(buf.data(), &dlg, sizeof(dlg));

    /* Menu (none) */
    buf.push_back(0); buf.push_back(0);
    /* Class (default) */
    buf.push_back(0); buf.push_back(0);
    /* Title */
    appendStr(buf, L"AkesoDLP: Policy Violation");
    /* Font (DS_SETFONT): size + name */
    WORD fontSize = 9;
    buf.resize(buf.size() + sizeof(WORD));
    memcpy(buf.data() + buf.size() - sizeof(WORD), &fontSize, sizeof(WORD));
    appendStr(buf, L"Segoe UI");

    /* ---- Control 1: Detail label (static) ---- */
    padAlign(buf);
    {
        DLGITEMTEMPLATE item = {};
        item.style = WS_CHILD | WS_VISIBLE | SS_LEFT;
        item.x = 10; item.y = 10; item.cx = 260; item.cy = 80;
        item.id = IDC_DETAIL_LABEL;

        size_t off = buf.size();
        buf.resize(off + sizeof(DLGITEMTEMPLATE));
        memcpy(buf.data() + off, &item, sizeof(item));

        /* Class: 0x0082 = Static */
        WORD cls[] = {0xFFFF, 0x0082};
        buf.resize(buf.size() + sizeof(cls));
        memcpy(buf.data() + buf.size() - sizeof(cls), cls, sizeof(cls));
        /* Text */
        appendStr(buf, L"");
        /* Creation data (none) */
        buf.push_back(0); buf.push_back(0);
    }

    /* ---- Control 2: Justification edit box ---- */
    padAlign(buf);
    {
        DLGITEMTEMPLATE item = {};
        item.style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP
                   | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN;
        item.x = 10; item.y = 95; item.cx = 260; item.cy = 40;
        item.id = IDC_JUSTIFICATION_EDIT;

        size_t off = buf.size();
        buf.resize(off + sizeof(DLGITEMTEMPLATE));
        memcpy(buf.data() + off, &item, sizeof(item));

        WORD cls[] = {0xFFFF, 0x0081};  /* Edit */
        buf.resize(buf.size() + sizeof(cls));
        memcpy(buf.data() + buf.size() - sizeof(cls), cls, sizeof(cls));
        appendStr(buf, L"");
        buf.push_back(0); buf.push_back(0);
    }

    /* ---- Control 3: Timer label ---- */
    padAlign(buf);
    {
        DLGITEMTEMPLATE item = {};
        item.style = WS_CHILD | WS_VISIBLE | SS_CENTER;
        item.x = 10; item.y = 142; item.cx = 260; item.cy = 12;
        item.id = IDC_TIMER_LABEL;

        size_t off = buf.size();
        buf.resize(off + sizeof(DLGITEMTEMPLATE));
        memcpy(buf.data() + off, &item, sizeof(item));

        WORD cls[] = {0xFFFF, 0x0082};
        buf.resize(buf.size() + sizeof(cls));
        memcpy(buf.data() + buf.size() - sizeof(cls), cls, sizeof(cls));
        appendStr(buf, L"Time remaining: 120s");
        buf.push_back(0); buf.push_back(0);
    }

    /* ---- Control 4: Submit button ---- */
    padAlign(buf);
    {
        DLGITEMTEMPLATE item = {};
        item.style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
        item.x = 100; item.y = 160; item.cx = 70; item.cy = 20;
        item.id = IDC_SUBMIT_BTN;

        size_t off = buf.size();
        buf.resize(off + sizeof(DLGITEMTEMPLATE));
        memcpy(buf.data() + off, &item, sizeof(item));

        WORD cls[] = {0xFFFF, 0x0080};  /* Button */
        buf.resize(buf.size() + sizeof(cls));
        memcpy(buf.data() + buf.size() - sizeof(cls), cls, sizeof(cls));
        appendStr(buf, L"Submit");
        buf.push_back(0); buf.push_back(0);
    }

    /* ---- Control 5: Block button ---- */
    padAlign(buf);
    {
        DLGITEMTEMPLATE item = {};
        item.style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
        item.x = 180; item.y = 160; item.cx = 70; item.cy = 20;
        item.id = IDC_BLOCK_BTN;

        size_t off = buf.size();
        buf.resize(off + sizeof(DLGITEMTEMPLATE));
        memcpy(buf.data() + off, &item, sizeof(item));

        WORD cls[] = {0xFFFF, 0x0080};
        buf.resize(buf.size() + sizeof(cls));
        memcpy(buf.data() + buf.size() - sizeof(cls), cls, sizeof(cls));
        appendStr(buf, L"Block");
        buf.push_back(0); buf.push_back(0);
    }

    return buf;
}

#endif /* _WIN32 */

/* ================================================================== */
/*  Constructor                                                         */
/* ================================================================== */

UserCancelAction::UserCancelAction(int timeout_seconds)
    : timeout_seconds_(timeout_seconds)
{
}

/* ================================================================== */
/*  Public API                                                          */
/* ================================================================== */

UserCancelResult UserCancelAction::ShowDialog(
    const std::string& policy_name,
    const std::string& severity,
    const std::string& file_name,
    const std::string& match_summary)
{
    ++dialogs_shown_;

    LOG_INFO("UserCancelAction: showing dialog - policy='{}' severity={} file={}",
             policy_name, severity, file_name);

    UserCancelResult result;
    result.verdict = DriverMsgType::VerdictBlock;  /* Default: block */

#ifdef _WIN32
    DialogState state;
    state.policy_name = policy_name;
    state.severity = severity;
    state.file_name = file_name;
    state.match_summary = match_summary;
    state.timeout_seconds = timeout_seconds_;

    /* Build dialog template */
    auto dlgTemplate = BuildDialogTemplate();

    /*
     * Run the dialog on a dedicated thread with its own message loop.
     * We use a mutex + condition variable to synchronize with the
     * calling thread.
     */
    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;

    std::thread dialog_thread([&]() {
        INT_PTR ret = DialogBoxIndirectParamW(
            GetModuleHandleW(nullptr),
            reinterpret_cast<DLGTEMPLATE*>(dlgTemplate.data()),
            nullptr,  /* No parent — top-level */
            UserCancelDlgProc,
            reinterpret_cast<LPARAM>(&state));

        (void)ret;

        {
            std::lock_guard<std::mutex> lock(mtx);
            done = true;
        }
        cv.notify_one();
    });
    dialog_thread.detach();

    /* Wait for dialog to complete or timeout + grace period */
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(timeout_seconds_ + 5),
                     [&done] { return done; });
    }

    if (state.submitted) {
        result.verdict = DriverMsgType::VerdictAllow;
        result.justification = state.justification;
        result.timed_out = false;
        result.user_cancelled = false;
        ++dialogs_allowed_;
        LOG_INFO("UserCancelAction: user submitted justification - allowing. Justification: '{}'",
                 result.justification);
    } else if (state.timed_out) {
        result.verdict = DriverMsgType::VerdictBlock;
        result.timed_out = true;
        result.user_cancelled = false;
        ++dialogs_timed_out_;
        ++dialogs_blocked_;
        LOG_WARN("UserCancelAction: dialog timed out after {}s - blocking",
                 timeout_seconds_);
    } else {
        result.verdict = DriverMsgType::VerdictBlock;
        result.timed_out = false;
        result.user_cancelled = true;
        ++dialogs_blocked_;
        LOG_INFO("UserCancelAction: user clicked Block");
    }

#else
    /* Non-Windows: always block */
    result.verdict = DriverMsgType::VerdictBlock;
    result.timed_out = true;
    (void)policy_name; (void)severity; (void)file_name; (void)match_summary;
#endif

    return result;
}

}  // namespace akeso::dlp
