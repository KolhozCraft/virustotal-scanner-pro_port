#include "win32_shell.h"

#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <objbase.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace {

std::wstring f3yui10rqgw(const char* s) {
    if (!s || !*s) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
    return w;
}

std::string fzrg137893b(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

char* f8tea9f3uuu(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

constexpr const wchar_t* kDpapiDescription = L"VirusTotalScannerPro API key";

std::string f1y0w6y9ou8(const std::vector<BYTE>& data) {
    if (data.empty()) return {};
    DWORD outLen = 0;
    CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &outLen);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<BYTE> fogcac8l5n0(const std::string& text) {
    if (text.empty()) return {};
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                              nullptr, &outLen, nullptr, nullptr)) {
        return {};
    }
    std::vector<BYTE> out(outLen);
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                              out.data(), &outLen, nullptr, nullptr)) {
        return {};
    }
    return out;
}

struct UrlParts {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    bool secure = true;
};

bool ftbflgl7vc8(const std::wstring& url, UrlParts& out) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostBuf[512]{};
    wchar_t pathBuf[4096]{};
    uc.lpszHostName = hostBuf;
    uc.dwHostNameLength = 512;
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &uc)) return false;
    out.host = hostBuf;
    out.path = pathBuf;
    out.port = uc.nPort;
    out.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

std::string f9mcca1ladl(HINTERNET hRequest) {
    std::string body;
    DWORD avail = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
        body.append(buf.data(), read);
    } while (avail > 0);
    return body;
}

int f6yzufy3f3s(HINTERNET hRequest) {
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    return static_cast<int>(statusCode);
}

struct HttpResult {
    int status = 0;
    std::string body;
    bool networkError = false;
    bool timedOut = false;
};

void fmjn6sudg7g(HttpResult& r) {
    DWORD err = GetLastError();
    if (err == ERROR_WINHTTP_TIMEOUT) r.timedOut = true; else r.networkError = true;
}

void fji9vjbphts(const HttpResult& r, VtHttpResponse* out) {
    out->status = r.status;
    out->network_error = r.networkError ? 1 : 0;
    out->timed_out = r.timedOut ? 1 : 0;
    out->body = f8tea9f3uuu(r.body);
    out->body_len = out->body ? r.body.size() : 0;
}

HttpResult f4v6tk2b89h(const std::wstring& url, const std::wstring& apiKey, int timeoutMs) {
    HttpResult result;
    UrlParts parts;
    if (!ftbflgl7vc8(url, parts)) { result.networkError = true; return result; }

    HINTERNET hSession = WinHttpOpen(L"VirusTotalScanner/3.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { result.networkError = true; return result; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parts.host.c_str(), parts.port, 0);
    if (!hConnect) { result.networkError = true; WinHttpCloseHandle(hSession); return result; }

    DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", parts.path.c_str(), nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        result.networkError = true;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring headerBlock = L"accept: application/json\r\nx-apikey: " + apiKey + L"\r\n";
    WinHttpAddRequestHeaders(hRequest, headerBlock.c_str(), static_cast<DWORD>(headerBlock.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, nullptr)) {
            result.status = f6yzufy3f3s(hRequest);
            result.body = f9mcca1ladl(hRequest);
        } else {
            fmjn6sudg7g(result);
        }
    } else {
        fmjn6sudg7g(result);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

HttpResult fkbdr95pb0b(const std::wstring& url, const std::wstring& apiKey, const std::wstring& filePath,
                      const std::string& fieldName, const std::string& fileNameUtf8, int timeoutMs) {
    HttpResult result;
    UrlParts parts;
    if (!ftbflgl7vc8(url, parts)) { result.networkError = true; return result; }

    std::ifstream file(filePath.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) { result.networkError = true; return result; }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::mt19937_64 rng(std::random_device{}());
    char boundary[48];
    std::snprintf(boundary, sizeof(boundary), "----VTScannerBoundary%016llx",
                  static_cast<unsigned long long>(rng()));

    std::string preamble = "--" + std::string(boundary) + "\r\n" +
        "Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + fileNameUtf8 + "\"\r\n" +
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string epilogue = "\r\n--" + std::string(boundary) + "--\r\n";

    DWORD totalLen = static_cast<DWORD>(preamble.size() + static_cast<size_t>(fileSize) + epilogue.size());

    HINTERNET hSession = WinHttpOpen(L"VirusTotalScanner/3.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { result.networkError = true; return result; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parts.host.c_str(), parts.port, 0);
    if (!hConnect) { result.networkError = true; WinHttpCloseHandle(hSession); return result; }

    DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", parts.path.c_str(), nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        result.networkError = true;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring headerBlock = L"accept: application/json\r\nx-apikey: " + apiKey +
                               L"\r\nContent-Type: multipart/form-data; boundary=" + f3yui10rqgw(boundary) + L"\r\n";
    WinHttpAddRequestHeaders(hRequest, headerBlock.c_str(), static_cast<DWORD>(headerBlock.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, totalLen, 0)) {
        fmjn6sudg7g(result);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD written = 0;
    WinHttpWriteData(hRequest, preamble.data(), static_cast<DWORD>(preamble.size()), &written);

    std::vector<char> buf(1 << 16);
    while (file.good() && fileSize > 0) {
        file.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = file.gcount();
        if (got <= 0) break;
        WinHttpWriteData(hRequest, buf.data(), static_cast<DWORD>(got), &written);
    }

    WinHttpWriteData(hRequest, epilogue.data(), static_cast<DWORD>(epilogue.size()), &written);

    if (WinHttpReceiveResponse(hRequest, nullptr)) {
        result.status = f6yzufy3f3s(hRequest);
        result.body = f9mcca1ladl(hRequest);
    } else {
        fmjn6sudg7g(result);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kCmdShow = 1001;
constexpr UINT kCmdExit = 1002;
constexpr const wchar_t* kTrayClass = L"VTScannerTrayWnd";

struct TrayState {
    HWND hwnd = nullptr;
    NOTIFYICONDATAW nid{};
    bool added = false;
    UINT taskbarCreated = 0;
    VtTrayCallback callback = nullptr;
    void* user = nullptr;
    std::wstring tooltip;
    std::wstring showLabel;
    std::wstring exitLabel;
};

TrayState g_tray;

void fldo2eqq6vd() {
    if (g_tray.added || !g_tray.hwnd) return;

    ZeroMemory(&g_tray.nid, sizeof(g_tray.nid));
    g_tray.nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_tray.nid.hWnd = g_tray.hwnd;
    g_tray.nid.uID = 1;
    g_tray.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_tray.nid.uCallbackMessage = kTrayMessage;

    g_tray.nid.hIcon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON,
                                                     GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                                     LR_DEFAULTCOLOR));
    if (!g_tray.nid.hIcon) g_tray.nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

    wcsncpy_s(g_tray.nid.szTip, g_tray.tooltip.c_str(), _TRUNCATE);

    g_tray.added = Shell_NotifyIconW(NIM_ADD, &g_tray.nid) != FALSE;
    if (g_tray.added) {
        g_tray.nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_tray.nid);
    }
}

void fklptxtfb6l() {
    if (!g_tray.added) return;
    Shell_NotifyIconW(NIM_DELETE, &g_tray.nid);
    if (g_tray.nid.hIcon) {
        DestroyIcon(g_tray.nid.hIcon);
        g_tray.nid.hIcon = nullptr;
    }
    g_tray.added = false;
}

void f0aur9p8rfz(int event) {
    if (g_tray.callback) g_tray.callback(event, g_tray.user);
}

void f5qnif97g2k() {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    AppendMenuW(menu, MF_STRING, kCmdShow, g_tray.showLabel.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCmdExit, g_tray.exitLabel.c_str());

    POINT pt{};
    GetCursorPos(&pt);

    SetForegroundWindow(g_tray.hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_tray.hwnd, nullptr);
    PostMessageW(g_tray.hwnd, WM_NULL, 0, 0);

    DestroyMenu(menu);
}

LRESULT CALLBACK fjhmy0u9fgc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_tray.taskbarCreated != 0 && msg == g_tray.taskbarCreated) {
        g_tray.added = false;
        fldo2eqq6vd();
        return 0;
    }
    switch (msg) {
    case kTrayMessage:
        switch (LOWORD(lParam)) {
        case WM_LBUTTONDBLCLK:
            f0aur9p8rfz(VT_TRAY_SHOW);
            break;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            f5qnif97g2k();
            break;
        default:
            break;
        }
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == kCmdShow) {
            f0aur9p8rfz(VT_TRAY_SHOW);
        } else if (LOWORD(wParam) == kCmdExit) {
            fklptxtfb6l();
            f0aur9p8rfz(VT_TRAY_EXIT);
        }
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

BOOL CALLBACK f0hua977ibs(HWND hwnd, LPARAM param) {
    if (hwnd == g_tray.hwnd) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
    *reinterpret_cast<HWND*>(param) = hwnd;
    return FALSE;
}

}

extern "C" {

void f3un4d5fjcu(char* s) { std::free(s); }

char* f6nep1f9o7n(void) {
    PWSTR path = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        dir = path;
        CoTaskMemFree(path);
    } else {
        dir = L".";
    }
    std::wstring mid = dir + L"\\ky4ka_boroxla";
    CreateDirectoryW(mid.c_str(), nullptr);
    dir = mid + L"\\VirusTotalScanner";
    CreateDirectoryW(dir.c_str(), nullptr);
    return f8tea9f3uuu(fzrg137893b(dir));
}

char* fjdckhr30rn(const char* plain_utf8) {
    if (!plain_utf8 || !*plain_utf8) return nullptr;
    std::string plain = plain_utf8;

    DATA_BLOB in{};
    in.pbData = reinterpret_cast<BYTE*>(plain.data());
    in.cbData = static_cast<DWORD>(plain.size());

    DATA_BLOB out{};
    if (!CryptProtectData(&in, kDpapiDescription, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return nullptr;
    }

    std::vector<BYTE> cipher(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return f8tea9f3uuu(f1y0w6y9ou8(cipher));
}

char* f2funfd6n3n(const char* base64_utf8) {
    if (!base64_utf8) return nullptr;
    std::vector<BYTE> cipher = fogcac8l5n0(base64_utf8);
    if (cipher.empty()) return nullptr;

    DATA_BLOB in{};
    in.pbData = cipher.data();
    in.cbData = static_cast<DWORD>(cipher.size());

    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return nullptr;
    }

    std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return f8tea9f3uuu(plain);
}

int f3uktifcxgm(int enable) {
    HKEY hKey = nullptr;
    LONG openRes = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                 0, KEY_SET_VALUE, &hKey);
    if (openRes != ERROR_SUCCESS) return 0;

    bool ok;
    if (enable) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring value = L"\"" + std::wstring(exePath) + L"\"";
        LONG res = RegSetValueExW(hKey, L"VirusTotalScannerPro", 0, REG_SZ,
                                  reinterpret_cast<const BYTE*>(value.c_str()),
                                  static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
        ok = (res == ERROR_SUCCESS);
    } else {
        LONG res = RegDeleteValueW(hKey, L"VirusTotalScannerPro");
        ok = (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND);
    }

    RegCloseKey(hKey);
    return ok ? 1 : 0;
}

void* ffzma9z86zi(void) { return GetActiveWindow(); }

char* fkzznls4w30(void* owner) {
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    wchar_t fileBuf[MAX_PATH] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = static_cast<HWND>(owner);
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All files\0*.*\0Executables\0*.exe;*.dll;*.sys;*.msi\0"
                      L"Documents\0*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.txt\0"
                      L"Archives\0*.zip;*.rar;*.7z;*.tar;*.gz\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    char* result = nullptr;
    if (GetOpenFileNameW(&ofn)) result = f8tea9f3uuu(fzrg137893b(fileBuf));

    if (SUCCEEDED(com)) CoUninitialize();
    return result;
}

void f32pnbb7me8(const char* url_utf8) {
    std::wstring url = f3yui10rqgw(url_utf8);
    if (url.empty()) return;
    ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void f9jwldhl375(const char* text_utf8) {
    std::wstring w = f3yui10rqgw(text_utf8);
    if (w.empty()) return;
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (mem) {
        void* p = GlobalLock(mem);
        if (p) {
            std::memcpy(p, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
            GlobalUnlock(mem);
            if (!SetClipboardData(CF_UNICODETEXT, mem)) GlobalFree(mem);
        } else {
            GlobalFree(mem);
        }
    }
    CloseClipboard();
}

void fksaxrq228o(void) { MessageBeep(MB_ICONASTERISK); }

void fy4vo2fr45h(void) {
    HWND target = nullptr;
    EnumThreadWindows(GetCurrentThreadId(), f0hua977ibs, reinterpret_cast<LPARAM>(&target));
    if (!target) return;
    if (IsIconic(target)) ShowWindow(target, SW_RESTORE);
    SetForegroundWindow(target);
}

void ffy9yybo2ia(const char* url_utf8, const char* api_key_utf8, int timeout_ms, VtHttpResponse* out) {
    if (!out) return;
    fji9vjbphts(f4v6tk2b89h(f3yui10rqgw(url_utf8), f3yui10rqgw(api_key_utf8), timeout_ms), out);
}

void f1t55yc0vd7(const char* url_utf8, const char* api_key_utf8, const char* file_path_utf8,
                       const char* field_name, const char* file_name_utf8, int timeout_ms,
                       VtHttpResponse* out) {
    if (!out) return;
    fji9vjbphts(fkbdr95pb0b(f3yui10rqgw(url_utf8), f3yui10rqgw(api_key_utf8), f3yui10rqgw(file_path_utf8),
                      field_name ? field_name : "file", file_name_utf8 ? file_name_utf8 : "", timeout_ms),
           out);
}

void fs064iemdmn(VtHttpResponse* r) {
    if (!r) return;
    std::free(r->body);
    r->body = nullptr;
    r->body_len = 0;
}

int fuw8nd6w1gk(VtTrayCallback callback, void* user, const char* tooltip_utf8,
                   const char* show_label_utf8, const char* exit_label_utf8) {
    if (g_tray.hwnd) return 1;

    g_tray.callback = callback;
    g_tray.user = user;
    g_tray.tooltip = f3yui10rqgw(tooltip_utf8);
    g_tray.showLabel = f3yui10rqgw(show_label_utf8);
    g_tray.exitLabel = f3yui10rqgw(exit_label_utf8);
    g_tray.taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    HINSTANCE inst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = fjhmy0u9fgc;
    wc.hInstance = inst;
    wc.lpszClassName = kTrayClass;
    RegisterClassExW(&wc);

    g_tray.hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, kTrayClass, L"", WS_POPUP, 0, 0, 0, 0,
                                  nullptr, nullptr, inst, nullptr);
    if (!g_tray.hwnd) return 0;

    fldo2eqq6vd();
    return g_tray.added ? 1 : 0;
}

void f8tgjs2kv3w(const char* show_label_utf8, const char* exit_label_utf8) {
    g_tray.showLabel = f3yui10rqgw(show_label_utf8);
    g_tray.exitLabel = f3yui10rqgw(exit_label_utf8);
}

void fcn40nf3rzw(void) {
    fklptxtfb6l();
    if (g_tray.hwnd) {
        DestroyWindow(g_tray.hwnd);
        g_tray.hwnd = nullptr;
        UnregisterClassW(kTrayClass, GetModuleHandleW(nullptr));
    }
    g_tray.callback = nullptr;
}

}
