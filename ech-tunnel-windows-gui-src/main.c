#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Unique name for Mutex
#define SINGLE_INSTANCE_MUTEX_NAME "ECHTunnelClient_Mutex_Unique_ID"

// 图标资源 ID
#define IDI_APP_ICON 101 

// 声明 DPI 感知函数
typedef BOOL (WINAPI *SetProcessDPIAwareFunc)(void);

// 版本信息
#define APP_VERSION "2.0"
#define APP_TITLE "ECH Tunnel 客户端 v" APP_VERSION

// 缓冲区大小定义
#define MAX_URL_LEN 8192
#define MAX_SMALL_LEN 2048
#define MAX_CMD_LEN 32768
#define MAX_NAME_LEN 256

// 服务器配置限制
#define MAX_SERVERS 50

// 消息定义
#define WM_TRAYICON (WM_USER + 1)
#define WM_APPEND_LOG (WM_USER + 2) 

// 托盘菜单ID
#define ID_TRAY_ICON 9001
#define ID_TRAY_OPEN 9002
#define ID_TRAY_EXIT 9003

// 输入对话框控件ID
#define ID_INPUT_EDIT 2001
#define ID_INPUT_OK 2002
#define ID_INPUT_CANCEL 2003

// 字体与绘图对象
HFONT hFontUI = NULL;    
HFONT hFontLog = NULL;   
HBRUSH hBrushLog = NULL;

// DPI 感知
int g_dpi = 96;
int g_scale = 100;

// 缩放函数
int Scale(int x) {
    return (x * g_scale) / 100;
}

// 窗口控件ID定义
#define ID_SERVER_COMBO     1000
#define ID_SERVER_ADD       1001
#define ID_SERVER_DELETE    1002
#define ID_SERVER_RENAME    1003
#define ID_SERVER_EDIT      1004
#define ID_LISTEN_EDIT      1005
#define ID_TOKEN_EDIT       1006
#define ID_IP_EDIT          1007
#define ID_DNS_EDIT         1008
#define ID_ECH_EDIT         1009
#define ID_CONN_EDIT        1010
#define ID_CONN_UP          1011
#define ID_CONN_DOWN        1012
#define ID_START_BTN        1013
#define ID_STOP_BTN         1014
#define ID_CLEAR_LOG_BTN    1015
#define ID_LOG_EDIT         1016
#define ID_FALLBACK_CHECK   1017
#define ID_AUTOSTART_CHECK  1018

// 全局变量
HWND hMainWindow;
HWND hServerCombo;
HWND hServerEdit, hListenEdit, hTokenEdit, hIpEdit, hDnsEdit, hEchEdit;
HWND hConnEdit, hStartBtn, hStopBtn, hLogEdit;
HWND hFallbackCheck;
HWND hAutoStartCheck;
PROCESS_INFORMATION processInfo;
HANDLE hLogPipe = NULL;
HANDLE hLogThread = NULL;
BOOL isProcessRunning = FALSE;
NOTIFYICONDATA nid;
BOOL g_isAutoStart = FALSE;

// 程序所在目录（全局缓存）
char g_exeDir[MAX_PATH] = {0};

// 配置结构体
typedef struct {
    char name[MAX_NAME_LEN];
    char dns[MAX_SMALL_LEN];     
    char ech[MAX_SMALL_LEN];     
    char server[MAX_URL_LEN];    
    char ip[MAX_SMALL_LEN];      
    char listen[MAX_SMALL_LEN];  
    int connections;
    char token[MAX_URL_LEN];
    int fallback;
} ServerConfig;

// 全局服务器配置数组
ServerConfig servers[MAX_SERVERS];
int serverCount = 0;
int currentServerIndex = 0;
BOOL g_autoStartEnabled = FALSE;

// 输入对话框数据
typedef struct {
    char* buffer;
    int bufferSize;
    const char* prompt;
    BOOL result;
} InputDialogData;

// 函数声明
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK InputDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void StartProcess();
void StopProcess();
void AppendLog(const char* text);
void AppendLogAsync(const char* text);
DWORD WINAPI LogReaderThread(LPVOID lpParam);
void SaveConfig();
void LoadConfig();
void GetControlValues();
void SetControlValues();
void InitTrayIcon(HWND hwnd);
void ShowTrayIcon();
void RemoveTrayIcon();

// 路径相关函数
void InitExeDir();
void GetConfigFilePath(char* path, int maxLen);

// 服务器管理函数
void InitDefaultServer();
void RefreshServerCombo();
void SwitchServer(int index);
void AddNewServer();
void DeleteCurrentServer();
void RenameCurrentServer();
ServerConfig* GetCurrentServer();
BOOL ShowInputDialog(HWND parent, const char* title, const char* prompt, char* buffer, int bufferSize);

// 开机启动相关函数
BOOL IsRunAsAdministrator();
BOOL SetAutoStart(BOOL enable);
BOOL IsAutoStartEnabled();
void UpdateAutoStartCheckbox();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    
    // 初始化程序所在目录
    InitExeDir();
    
    // 解析命令行参数
    if (lpCmdLine && strstr(lpCmdLine, "-autostart")) {
        g_isAutoStart = TRUE;
    }
    
    // --- 单实例检查开始 ---
    HANDLE hMutex = CreateMutex(NULL, TRUE, SINGLE_INSTANCE_MUTEX_NAME);

    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND hExistingWnd = FindWindow("ECHTunnelClient", NULL); 
        if (hExistingWnd) {
            PostMessage(hExistingWnd, WM_TRAYICON, ID_TRAY_ICON, WM_LBUTTONUP);
        }
        CloseHandle(hMutex);
        return 0; 
    }
    
    HMODULE hUser32 = LoadLibrary("user32.dll");
    if (hUser32) {
        SetProcessDPIAwareFunc setDPIAware = (SetProcessDPIAwareFunc)(void*)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setDPIAware) setDPIAware();
        FreeLibrary(hUser32);
    }
    
    HDC hdc = GetDC(NULL);
    g_dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    g_scale = (g_dpi * 100) / 96;
    ReleaseDC(NULL, hdc);
    
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    hFontUI = CreateFont(Scale(19), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Microsoft YaHei UI");

    hFontLog = CreateFont(Scale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

    hBrushLog = CreateSolidBrush(RGB(255, 255, 255));

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ECHTunnelClient";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClass(&wc)) return 1;

    // 注册输入对话框窗口类
    WNDCLASS wcInput = {0};
    wcInput.lpfnWndProc = InputDialogProc;
    wcInput.hInstance = hInstance;
    wcInput.lpszClassName = "InputDialog";
    wcInput.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcInput.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcInput.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClass(&wcInput);

    int winWidth = Scale(900);
    int winHeight = Scale(820);
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    DWORD winStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;

    hMainWindow = CreateWindowEx(
        0, "ECHTunnelClient", APP_TITLE, 
        winStyle,
        (screenW - winWidth) / 2, (screenH - winHeight) / 2, 
        winWidth, winHeight,
        NULL, NULL, hInstance, NULL
    );

    if (!hMainWindow) return 1;

    InitTrayIcon(hMainWindow);
    ShowTrayIcon();

    // 如果是开机自动启动，启动时隐藏窗口
    if (g_isAutoStart) {
        ShowWindow(hMainWindow, SW_HIDE);
    } else {
        ShowWindow(hMainWindow, nCmdShow);
    }
    
    UpdateWindow(hMainWindow);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_TAB) {
            IsDialogMessage(hMainWindow, &msg);
        } else {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    CloseHandle(hMutex); 

    return (int)msg.wParam;
}

// ========== 路径相关函数 ==========

void InitExeDir() {
    GetModuleFileName(NULL, g_exeDir, MAX_PATH);
    char* lastSlash = strrchr(g_exeDir, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = 0; // 保留最后的反斜杠
    }
}

void GetConfigFilePath(char* path, int maxLen) {
    snprintf(path, maxLen, "%sconfig.ini", g_exeDir);
}

// ========== 开机启动相关函数实现 ==========

BOOL IsRunAsAdministrator() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    return isAdmin;
}

BOOL SetAutoStart(BOOL enable) {
    HKEY hKey;
    const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "ECHTunnelClient";
    LONG result;
    
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }
    
    if (enable) {
        char exePath[MAX_PATH];
        char cmdLine[MAX_PATH + 20];
        
        GetModuleFileName(NULL, exePath, MAX_PATH);
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\" -autostart", exePath);
        
        result = RegSetValueEx(hKey, valueName, 0, REG_SZ, 
            (BYTE*)cmdLine, (DWORD)(strlen(cmdLine) + 1));
    } else {
        result = RegDeleteValue(hKey, valueName);
    }
    
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}

BOOL IsAutoStartEnabled() {
    HKEY hKey;
    const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "ECHTunnelClient";
    LONG result;
    BOOL enabled = FALSE;
    
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        char value[MAX_PATH];
        DWORD valueSize = sizeof(value);
        DWORD type;
        
        result = RegQueryValueEx(hKey, valueName, NULL, &type, (BYTE*)value, &valueSize);
        
        if (result == ERROR_SUCCESS && type == REG_SZ) {
            enabled = TRUE;
        }
        
        RegCloseKey(hKey);
    }
    
    return enabled;
}

void UpdateAutoStartCheckbox() {
    if (hAutoStartCheck) {
        BOOL enabled = IsAutoStartEnabled();
        SendMessage(hAutoStartCheck, BM_SETCHECK, enabled ? BST_CHECKED : BST_UNCHECKED, 0);
        g_autoStartEnabled = enabled;
    }
}

// ========== 输入对话框实现 ==========
LRESULT CALLBACK InputDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static InputDialogData* pData = NULL;

    switch (uMsg) {
        case WM_CREATE: {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            pData = (InputDialogData*)cs->lpCreateParams;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pData);
            
            int dlgW = Scale(400);
            int dlgH = Scale(160);
            int margin = Scale(20);
            int btnW = Scale(80);
            int btnH = Scale(30);
            int editH = Scale(26);
            
            HWND hPrompt = CreateWindow("STATIC", pData->prompt, 
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                margin, margin, dlgW - margin * 2, Scale(20),
                hwnd, NULL, NULL, NULL);
            SendMessage(hPrompt, WM_SETFONT, (WPARAM)hFontUI, TRUE);
            
            HWND hEdit = CreateWindow("EDIT", pData->buffer,
                WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                margin, margin + Scale(30), dlgW - margin * 2, editH,
                hwnd, (HMENU)ID_INPUT_EDIT, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFontUI, TRUE);
            SendMessage(hEdit, EM_SETLIMITTEXT, pData->bufferSize - 1, 0);
            SendMessage(hEdit, EM_SETSEL, 0, -1);
            
            HWND hOK = CreateWindow("BUTTON", "确定",
                WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON,
                dlgW - margin - btnW * 2 - Scale(10), dlgH - margin - btnH - Scale(10),
                btnW, btnH,
                hwnd, (HMENU)ID_INPUT_OK, NULL, NULL);
            SendMessage(hOK, WM_SETFONT, (WPARAM)hFontUI, TRUE);
            
            HWND hCancel = CreateWindow("BUTTON", "取消",
                WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                dlgW - margin - btnW, dlgH - margin - btnH - Scale(10),
                btnW, btnH,
                hwnd, (HMENU)ID_INPUT_CANCEL, NULL, NULL);
            SendMessage(hCancel, WM_SETFONT, (WPARAM)hFontUI, TRUE);
            
            SetFocus(hEdit);
            return 0;
        }

        case WM_COMMAND:
            pData = (InputDialogData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            
            switch (LOWORD(wParam)) {
                case ID_INPUT_OK: {
                    HWND hEdit = GetDlgItem(hwnd, ID_INPUT_EDIT);
                    GetWindowText(hEdit, pData->buffer, pData->bufferSize);
                    
                    char* start = pData->buffer;
                    while (*start == ' ' || *start == '\t') start++;
                    char* end = start + strlen(start) - 1;
                    while (end > start && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) end--;
                    *(end + 1) = 0;
                    memmove(pData->buffer, start, strlen(start) + 1);
                    
                    if (strlen(pData->buffer) == 0) {
                        MessageBox(hwnd, "名称不能为空！", "提示", MB_OK | MB_ICONWARNING);
                        SetFocus(hEdit);
                        return 0;
                    }
                    
                    pData->result = TRUE;
                    DestroyWindow(hwnd);
                    return 0;
                }
                
                case ID_INPUT_CANCEL:
                    pData->result = FALSE;
                    DestroyWindow(hwnd);
                    return 0;
            }
            break;

        case WM_CLOSE:
            pData = (InputDialogData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (pData) pData->result = FALSE;
            DestroyWindow(hwnd);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

BOOL ShowInputDialog(HWND parent, const char* title, const char* prompt, char* buffer, int bufferSize) {
    InputDialogData data;
    data.buffer = buffer;
    data.bufferSize = bufferSize;
    data.prompt = prompt;
    data.result = FALSE;
    
    int dlgW = Scale(400);
    int dlgH = Scale(160);
    
    RECT parentRect;
    GetWindowRect(parent, &parentRect);
    int x = parentRect.left + (parentRect.right - parentRect.left - dlgW) / 2;
    int y = parentRect.top + (parentRect.bottom - parentRect.top - dlgH) / 2;
    
    HWND hDlg = CreateWindowEx(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "InputDialog",
        title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y, dlgW, dlgH,
        parent,
        NULL,
        GetModuleHandle(NULL),
        &data
    );
    
    if (!hDlg) return FALSE;
    
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    
    EnableWindow(parent, FALSE);
    
    MSG msg;
    while (IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN) {
            if (msg.wParam == VK_RETURN) {
                PostMessage(hDlg, WM_COMMAND, ID_INPUT_OK, 0);
                continue;
            } else if (msg.wParam == VK_ESCAPE) {
                PostMessage(hDlg, WM_COMMAND, ID_INPUT_CANCEL, 0);
                continue;
            }
        }
        
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    SetActiveWindow(parent);
    
    return data.result;
}

void InitTrayIcon(HWND hwnd) {
    memset(&nid, 0, sizeof(NOTIFYICONDATA));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APP_ICON));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy(nid.szTip, APP_TITLE);
}

void ShowTrayIcon() {
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            LoadConfig();
            if (serverCount == 0) InitDefaultServer();
            RefreshServerCombo();
            SetControlValues();
            UpdateAutoStartCheckbox();
            
            // 如果是开机自动启动，延迟1秒后自动开始连接
            if (g_isAutoStart) {
                SetTimer(hwnd, 1, 1000, NULL);
            }
            break;

        case WM_TIMER:
            if (wParam == 1) {
                KillTimer(hwnd, 1);
                // 自动启动代理
                if (!isProcessRunning) {
                    GetControlValues();
                    ServerConfig* cfg = GetCurrentServer();
                    if (strlen(cfg->server) > 0 && strlen(cfg->listen) > 0) {
                        StartProcess();
                        AppendLog("[系统] 开机自动启动代理\r\n");
                    }
                }
            }
            break;

        case WM_SYSCOMMAND:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);

        case WM_TRAYICON:
            if (lParam == WM_LBUTTONUP) {
                if (!IsWindowVisible(hwnd)) {
                    ShowWindow(hwnd, SW_RESTORE);
                }
                SetForegroundWindow(hwnd);
                SetActiveWindow(hwnd);
            } 
            else if (lParam == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                if (hMenu) {
                    AppendMenu(hMenu, MF_STRING, ID_TRAY_OPEN, "打开界面");
                    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "退出程序");
                    SetForegroundWindow(hwnd); 
                    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    PostMessage(hwnd, WM_NULL, 0, 0);
                    DestroyMenu(hMenu);
                }
            }
            break;

        case WM_APPEND_LOG: {
            char* logText = (char*)lParam;
            if (logText) {
                AppendLog(logText);
                free(logText);
            }
            break;
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            int ctrlId = GetDlgCtrlID(hCtrl);
            if (ctrlId == ID_LOG_EDIT) {
                SetBkColor(hdcStatic, RGB(255, 255, 255)); 
                SetBkMode(hdcStatic, OPAQUE);              
                return (LRESULT)hBrushLog;                 
            }
            SetBkMode(hdcStatic, TRANSPARENT);             
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_OPEN:
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                    SetActiveWindow(hwnd);
                    break;
                
                case ID_TRAY_EXIT:
                    if (isProcessRunning) StopProcess();
                    GetControlValues();
                    SaveConfig();
                    RemoveTrayIcon();
                    DestroyWindow(hwnd);
                    break;

                case ID_AUTOSTART_CHECK: {
                    BOOL checked = (SendMessage(hAutoStartCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    
                    if (!IsRunAsAdministrator()) {
                        SendMessage(hAutoStartCheck, BM_SETCHECK, 
                            g_autoStartEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
                        
                        MessageBox(hwnd, 
                            "设置开机启动需要管理员权限。\n\n"
                            "请关闭程序，右键选择\"以管理员身份运行\"后重试。",
                            "需要管理员权限", 
                            MB_OK | MB_ICONWARNING);
                        break;
                    }
                    
                    if (SetAutoStart(checked)) {
                        g_autoStartEnabled = checked;
                        if (checked) {
                            AppendLog("[系统] 已设置开机启动\r\n");
                        } else {
                            AppendLog("[系统] 已取消开机启动\r\n");
                        }
                    } else {
                        SendMessage(hAutoStartCheck, BM_SETCHECK, 
                            g_autoStartEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
                        MessageBox(hwnd, "设置开机启动失败，请确保以管理员权限运行", 
                            "错误", MB_OK | MB_ICONERROR);
                    }
                    break;
                }

                case ID_SERVER_COMBO:
                    if (HIWORD(wParam) == CBN_SELCHANGE) {
                        if (!isProcessRunning) {
                            GetControlValues();
                            int newIndex = (int)SendMessage(hServerCombo, CB_GETCURSEL, 0, 0);
                            if (newIndex != CB_ERR) {
                                SwitchServer(newIndex);
                            }
                        } else {
                            SendMessage(hServerCombo, CB_SETCURSEL, currentServerIndex, 0);
                            MessageBox(hwnd, "请先停止当前连接后再切换服务器", "提示", MB_OK | MB_ICONWARNING);
                        }
                    }
                    break;

                case ID_SERVER_ADD:
                    if (!isProcessRunning) {
                        AddNewServer();
                    } else {
                        MessageBox(hwnd, "请先停止当前连接", "提示", MB_OK | MB_ICONWARNING);
                    }
                    break;

                case ID_SERVER_DELETE:
                    if (!isProcessRunning) {
                        DeleteCurrentServer();
                    } else {
                        MessageBox(hwnd, "请先停止当前连接", "提示", MB_OK | MB_ICONWARNING);
                    }
                    break;

                case ID_SERVER_RENAME:
                    if (!isProcessRunning) {
                        RenameCurrentServer();
                    } else {
                        MessageBox(hwnd, "请先停止当前连接", "提示", MB_OK | MB_ICONWARNING);
                    }
                    break;

                case ID_START_BTN:
                    if (!isProcessRunning) {
                        GetControlValues();
                        ServerConfig* cfg = GetCurrentServer();
                        if (strlen(cfg->server) == 0) {
                            MessageBox(hwnd, "请输入服务地址 (wss://...)", "提示", MB_OK | MB_ICONWARNING);
                            SetFocus(hServerEdit);
                            break;
                        }
                        if (strlen(cfg->listen) == 0) {
                            MessageBox(hwnd, "请输入监听地址 (127.0.0.1:...)", "提示", MB_OK | MB_ICONWARNING);
                            SetFocus(hListenEdit);
                            break;
                        }
                        SaveConfig();
                        StartProcess();
                    }
                    break;

                case ID_STOP_BTN:
                    if (isProcessRunning) StopProcess();
                    break;

                case ID_CLEAR_LOG_BTN:
                    SetWindowText(hLogEdit, "");
                    break;

                case ID_CONN_UP: {
                    char buf[16];
                    GetWindowText(hConnEdit, buf, 16);
                    int val = atoi(buf);
                    if (val < 20) {
                        sprintf(buf, "%d", val + 1);
                        SetWindowText(hConnEdit, buf);
                    }
                    break;
                }

                case ID_CONN_DOWN: {
                    char buf[16];
                    GetWindowText(hConnEdit, buf, 16);
                    int val = atoi(buf);
                    if (val > 1) {
                        sprintf(buf, "%d", val - 1);
                        SetWindowText(hConnEdit, buf);
                    }
                    break;
                }
                
                case ID_FALLBACK_CHECK: {
                    BOOL fallbackChecked = (SendMessage(hFallbackCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    EnableWindow(hDnsEdit, !fallbackChecked);
                    EnableWindow(hEchEdit, !fallbackChecked);
                    break;
                }
            }
            break;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;

        case WM_DESTROY:
            RemoveTrayIcon();
            if (hFontUI) DeleteObject(hFontUI);
            if (hFontLog) DeleteObject(hFontLog);
            if (hBrushLog) DeleteObject(hBrushLog);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void CreateLabelAndEdit(HWND parent, const char* labelText, int x, int y, int w, int h, int editId, HWND* outEdit, BOOL numberOnly) {
    HWND hStatic = CreateWindow("STATIC", labelText, WS_VISIBLE | WS_CHILD | SS_LEFT, 
        x, y + Scale(3), Scale(100), Scale(20), parent, NULL, NULL, NULL);
    SendMessage(hStatic, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    DWORD style = WS_VISIBLE | WS_CHILD | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;
    if (numberOnly) style |= ES_NUMBER | ES_CENTER;

    *outEdit = CreateWindow("EDIT", "", style, 
        x + Scale(110), y, w - Scale(110), h, parent, (HMENU)(intptr_t)editId, NULL, NULL);
    SendMessage(*outEdit, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    SendMessage(*outEdit, EM_SETLIMITTEXT, (editId == ID_SERVER_EDIT || editId == ID_TOKEN_EDIT) ? MAX_URL_LEN : MAX_SMALL_LEN, 0);
}

void CreateControls(HWND hwnd) {
    RECT rect;
    GetClientRect(hwnd, &rect);
    int winW = rect.right;
    int margin = Scale(20);
    int groupW = winW - (margin * 2);
    int lineHeight = Scale(30);
    int lineGap = Scale(10);
    int editH = Scale(26);
    int curY = margin;

    // ========== 服务器管理区域 ==========
    int serverMgrH = Scale(70);
    HWND hGroupServer = CreateWindow("BUTTON", "服务器管理", WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        margin, curY, groupW, serverMgrH, hwnd, NULL, NULL, NULL);
    SendMessage(hGroupServer, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    int innerY = curY + Scale(25);
    int innerX = margin + Scale(15);

    HWND hLblServer = CreateWindow("STATIC", "选择服务器:", WS_VISIBLE | WS_CHILD, 
        innerX, innerY + Scale(3), Scale(100), Scale(20), hwnd, NULL, NULL, NULL);
    SendMessage(hLblServer, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    hServerCombo = CreateWindow("COMBOBOX", "", 
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        innerX + Scale(110), innerY, Scale(350), Scale(200), 
        hwnd, (HMENU)ID_SERVER_COMBO, NULL, NULL);
    SendMessage(hServerCombo, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    int btnX = innerX + Scale(110) + Scale(360);
    int btnW = Scale(70);
    int btnH = Scale(26);
    int btnGap = Scale(8);

    HWND hBtnAdd = CreateWindow("BUTTON", "新增", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        btnX, innerY, btnW, btnH, hwnd, (HMENU)ID_SERVER_ADD, NULL, NULL);
    SendMessage(hBtnAdd, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnRename = CreateWindow("BUTTON", "重命名", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        btnX + btnW + btnGap, innerY, btnW, btnH, hwnd, (HMENU)ID_SERVER_RENAME, NULL, NULL);
    SendMessage(hBtnRename, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnDelete = CreateWindow("BUTTON", "删除", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        btnX + (btnW + btnGap) * 2, innerY, btnW, btnH, hwnd, (HMENU)ID_SERVER_DELETE, NULL, NULL);
    SendMessage(hBtnDelete, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += serverMgrH + Scale(15);

    // ========== 核心配置 ==========
    int group1H = Scale(110);
    HWND hGroup1 = CreateWindow("BUTTON", "核心配置", WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        margin, curY, groupW, group1H, hwnd, NULL, NULL, NULL);
    SendMessage(hGroup1, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    
    innerY = curY + Scale(25);
    
    int midGap = Scale(20); 
    int halfW = (groupW - Scale(30) - midGap) / 2; 
    int col2X = margin + Scale(15) + halfW + midGap;

    CreateLabelAndEdit(hwnd, "服务地址:", margin + Scale(15), innerY, groupW - Scale(30), editH, ID_SERVER_EDIT, &hServerEdit, FALSE);
    innerY += lineHeight + lineGap;

    CreateLabelAndEdit(hwnd, "监听地址:", margin + Scale(15), innerY, halfW, editH, ID_LISTEN_EDIT, &hListenEdit, FALSE);
    
    HWND hLbl = CreateWindow("STATIC", "并发连接:", WS_VISIBLE | WS_CHILD, col2X, innerY + Scale(3), Scale(80), Scale(20), hwnd, NULL, NULL, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    int btnSize = Scale(26);
    int numW = Scale(50);
    int numX = col2X + Scale(85);

    hConnEdit = CreateWindow("EDIT", "3", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER | ES_CENTER, 
        numX, innerY, numW, editH, hwnd, (HMENU)ID_CONN_EDIT, NULL, NULL);
    SendMessage(hConnEdit, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnDown = CreateWindow("BUTTON", "-", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
        numX + numW + Scale(5), innerY, btnSize, editH, hwnd, (HMENU)ID_CONN_DOWN, NULL, NULL);
    SendMessage(hBtnDown, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hBtnUp = CreateWindow("BUTTON", "+", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
        numX + numW + Scale(5) + btnSize + Scale(5), innerY, btnSize, editH, hwnd, (HMENU)ID_CONN_UP, NULL, NULL);
    SendMessage(hBtnUp, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += group1H + Scale(15);

    // ========== 高级选项 ==========
    int group2H = Scale(195);
    HWND hGroup2 = CreateWindow("BUTTON", "高级选项 (可选)", WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        margin, curY, groupW, group2H, hwnd, NULL, NULL, NULL);
    SendMessage(hGroup2, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    innerY = curY + Scale(25);

    CreateLabelAndEdit(hwnd, "身份令牌:", margin + Scale(15), innerY, groupW - Scale(30), editH, ID_TOKEN_EDIT, &hTokenEdit, FALSE);
    innerY += lineHeight + lineGap;

    CreateLabelAndEdit(hwnd, "指定IP:", margin + Scale(15), innerY, halfW, editH, ID_IP_EDIT, &hIpEdit, FALSE);
    CreateLabelAndEdit(hwnd, "DOH服务器:", col2X, innerY, halfW, editH, ID_DNS_EDIT, &hDnsEdit, FALSE);
    innerY += lineHeight + lineGap;

    CreateLabelAndEdit(hwnd, "ECH域名:", margin + Scale(15), innerY, halfW, editH, ID_ECH_EDIT, &hEchEdit, FALSE);
    
    hFallbackCheck = CreateWindow("BUTTON", "禁用ECH (回落到普通TLS 1.3)", 
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
        col2X, innerY + Scale(2), halfW, Scale(22), 
        hwnd, (HMENU)ID_FALLBACK_CHECK, NULL, NULL);
    SendMessage(hFallbackCheck, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += group2H + Scale(15);

    // ========== 按钮栏 ==========
    int btnW2 = Scale(120);
    int btnH2 = Scale(38);
    int btnGap2 = Scale(20);
    int startX = margin;

    hStartBtn = CreateWindow("BUTTON", "启动代理", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        startX, curY, btnW2, btnH2, hwnd, (HMENU)ID_START_BTN, NULL, NULL);
    SendMessage(hStartBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    hStopBtn = CreateWindow("BUTTON", "停止", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        startX + btnW2 + btnGap2, curY, btnW2, btnH2, hwnd, (HMENU)ID_STOP_BTN, NULL, NULL);
    SendMessage(hStopBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    EnableWindow(hStopBtn, FALSE);

    // 开机启动复选框
    hAutoStartCheck = CreateWindow("BUTTON", "开机启动", 
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
        startX + btnW2 * 2 + btnGap2 * 2, curY + Scale(10), Scale(120), Scale(22), 
        hwnd, (HMENU)ID_AUTOSTART_CHECK, NULL, NULL);
    SendMessage(hAutoStartCheck, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    HWND hClrBtn = CreateWindow("BUTTON", "清空日志", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        rect.right - margin - btnW2, curY, btnW2, btnH2, hwnd, (HMENU)ID_CLEAR_LOG_BTN, NULL, NULL);
    SendMessage(hClrBtn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

    curY += btnH2 + Scale(15);

    // ========== 日志区域 ==========
    HWND hLogLabel = CreateWindow("STATIC", "运行日志:", WS_VISIBLE | WS_CHILD, 
        margin, curY, Scale(100), Scale(20), hwnd, NULL, NULL, NULL);
    SendMessage(hLogLabel, WM_SETFONT, (WPARAM)hFontUI, TRUE);
    
    curY += Scale(25);

    hLogEdit = CreateWindow("EDIT", "", 
        WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
        margin, curY, winW - (margin * 2), Scale(200), hwnd, (HMENU)ID_LOG_EDIT, NULL, NULL);
    SendMessage(hLogEdit, WM_SETFONT, (WPARAM)hFontLog, TRUE);
    SendMessage(hLogEdit, EM_SETLIMITTEXT, 0, 0);
}

// ========== 服务器管理函数 ==========

void InitDefaultServer() {
    serverCount = 1;
    currentServerIndex = 0;
    strcpy(servers[0].name, "默认服务器");
    strcpy(servers[0].server, "wss://example.com:443");
    strcpy(servers[0].listen, "proxy://127.0.0.1:30000");
    strcpy(servers[0].token, "");
    strcpy(servers[0].ip, "");
    strcpy(servers[0].dns, "");
    strcpy(servers[0].ech, "");
    servers[0].connections = 3;
    servers[0].fallback = 0;
}

void RefreshServerCombo() {
    SendMessage(hServerCombo, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < serverCount; i++) {
        SendMessage(hServerCombo, CB_ADDSTRING, 0, (LPARAM)servers[i].name);
    }
    SendMessage(hServerCombo, CB_SETCURSEL, currentServerIndex, 0);
}

void SwitchServer(int index) {
    if (index < 0 || index >= serverCount) return;
    currentServerIndex = index;
    SetControlValues();
    SaveConfig();
    char msg[512];
    sprintf(msg, "[系统] 已切换到服务器: %s\r\n", servers[index].name);
    AppendLog(msg);
}

void AddNewServer() {
    if (serverCount >= MAX_SERVERS) {
        MessageBox(hMainWindow, "服务器数量已达上限", "提示", MB_OK | MB_ICONWARNING);
        return;
    }
    
    char newName[MAX_NAME_LEN] = "新服务器";
    if (!ShowInputDialog(hMainWindow, "新增服务器", "请输入服务器名称:", newName, MAX_NAME_LEN)) {
        return;
    }
    
    for (int i = 0; i < serverCount; i++) {
        if (strcmp(servers[i].name, newName) == 0) {
            MessageBox(hMainWindow, "服务器名称已存在，请使用其他名称", "提示", MB_OK | MB_ICONWARNING);
            return;
        }
    }
    
    ServerConfig* newServer = &servers[serverCount];
    if (serverCount > 0) {
        memcpy(newServer, &servers[currentServerIndex], sizeof(ServerConfig));
    } else {
        memset(newServer, 0, sizeof(ServerConfig));
        strcpy(newServer->server, "wss://example.com:443");
        strcpy(newServer->listen, "proxy://127.0.0.1:30000");
        newServer->connections = 3;
    }
    
    strcpy(newServer->name, newName);
    
    serverCount++;
    currentServerIndex = serverCount - 1;
    
    RefreshServerCombo();
    SetControlValues();
    SaveConfig();
    
    char logMsg[512];
    sprintf(logMsg, "[系统] 已添加新服务器: %s\r\n", newName);
    AppendLog(logMsg);
}

void DeleteCurrentServer() {
    if (serverCount <= 1) {
        MessageBox(hMainWindow, "至少需要保留一个服务器配置", "提示", MB_OK | MB_ICONWARNING);
        return;
    }
    
    char msg[512];
    sprintf(msg, "确定要删除服务器 \"%s\" 吗？", servers[currentServerIndex].name);
    if (MessageBox(hMainWindow, msg, "确认删除", MB_YESNO | MB_ICONQUESTION) != IDYES) {
        return;
    }
    
    char deletedName[MAX_NAME_LEN];
    strcpy(deletedName, servers[currentServerIndex].name);
    
    for (int i = currentServerIndex; i < serverCount - 1; i++) {
        memcpy(&servers[i], &servers[i + 1], sizeof(ServerConfig));
    }
    serverCount--;
    
    if (currentServerIndex >= serverCount) {
        currentServerIndex = serverCount - 1;
    }
    
    RefreshServerCombo();
    SetControlValues();
    SaveConfig();
    
    sprintf(msg, "[系统] 已删除服务器: %s\r\n", deletedName);
    AppendLog(msg);
}

void RenameCurrentServer() {
    char newName[MAX_NAME_LEN];
    strcpy(newName, servers[currentServerIndex].name);
    
    if (!ShowInputDialog(hMainWindow, "重命名服务器", "请输入新的服务器名称:", newName, MAX_NAME_LEN)) {
        return;
    }
    
    for (int i = 0; i < serverCount; i++) {
        if (i != currentServerIndex && strcmp(servers[i].name, newName) == 0) {
            MessageBox(hMainWindow, "服务器名称已存在，请使用其他名称", "提示", MB_OK | MB_ICONWARNING);
            return;
        }
    }
    
    char oldName[MAX_NAME_LEN];
    strcpy(oldName, servers[currentServerIndex].name);
    strcpy(servers[currentServerIndex].name, newName);
    
    RefreshServerCombo();
    SaveConfig();
    
    char logMsg[512];
    sprintf(logMsg, "[系统] 服务器已重命名: %s -> %s\r\n", oldName, newName);
    AppendLog(logMsg);
}

ServerConfig* GetCurrentServer() {
    if (currentServerIndex >= 0 && currentServerIndex < serverCount) {
        return &servers[currentServerIndex];
    }
    return &servers[0];
}

void GetControlValues() {
    ServerConfig* cfg = GetCurrentServer();
    
    char buf[MAX_URL_LEN];
    GetWindowText(hServerEdit, buf, sizeof(buf));
    if (strlen(buf) > 0 && strncmp(buf, "wss://", 6) != 0) 
        snprintf(cfg->server, sizeof(cfg->server), "wss://%s", buf);
    else 
        strcpy(cfg->server, buf);

    GetWindowText(hListenEdit, buf, sizeof(buf));
    if (strlen(buf) > 0 && strncmp(buf, "proxy://", 8) != 0) 
        snprintf(cfg->listen, sizeof(cfg->listen), "proxy://%s", buf);
    else 
        strcpy(cfg->listen, buf);

    GetWindowText(hTokenEdit, cfg->token, sizeof(cfg->token));
    GetWindowText(hIpEdit, cfg->ip, sizeof(cfg->ip));
    GetWindowText(hDnsEdit, cfg->dns, sizeof(cfg->dns));
    GetWindowText(hEchEdit, cfg->ech, sizeof(cfg->ech));

    char connBuf[32];
    GetWindowText(hConnEdit, connBuf, 32);
    cfg->connections = atoi(connBuf);
    if (cfg->connections < 1) cfg->connections = 1;
    
    cfg->fallback = (SendMessage(hFallbackCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
}

void SetControlValues() {
    ServerConfig* cfg = GetCurrentServer();
    
    if (strncmp(cfg->server, "wss://", 6) == 0) 
        SetWindowText(hServerEdit, cfg->server + 6);
    else 
        SetWindowText(hServerEdit, cfg->server);

    if (strncmp(cfg->listen, "proxy://", 8) == 0) 
        SetWindowText(hListenEdit, cfg->listen + 8);
    else 
        SetWindowText(hListenEdit, cfg->listen);

    SetWindowText(hTokenEdit, cfg->token);
    SetWindowText(hIpEdit, cfg->ip);
    SetWindowText(hDnsEdit, cfg->dns);
    SetWindowText(hEchEdit, cfg->ech);

    char connBuf[32];
    sprintf(connBuf, "%d", cfg->connections);
    SetWindowText(hConnEdit, connBuf);
    
    SendMessage(hFallbackCheck, BM_SETCHECK, cfg->fallback ? BST_CHECKED : BST_UNCHECKED, 0);
    
    BOOL fallbackChecked = (cfg->fallback != 0);
    EnableWindow(hDnsEdit, !fallbackChecked);
    EnableWindow(hEchEdit, !fallbackChecked);
}

void StartProcess() {
    ServerConfig* cfg = GetCurrentServer();
    
    char cmdLine[MAX_CMD_LEN];
    char exePath[MAX_PATH];
    
    // 构建 ech-tunnel.exe 的完整路径
    snprintf(exePath, MAX_PATH, "%sech-tunnel.exe", g_exeDir);
    
    if (GetFileAttributes(exePath) == INVALID_FILE_ATTRIBUTES) {
        char errMsg[512];
        snprintf(errMsg, sizeof(errMsg), "错误: 找不到 ech-tunnel.exe 文件!\n路径: %s\r\n", exePath);
        AppendLog(errMsg);
        return;
    }
    
    snprintf(cmdLine, MAX_CMD_LEN, "\"%s\"", exePath);
    #define APPEND_ARG(flag, val) if(strlen(val) > 0) { strcat(cmdLine, " " flag " \""); strcat(cmdLine, val); strcat(cmdLine, "\""); }

    APPEND_ARG("-f", cfg->server);
    APPEND_ARG("-l", cfg->listen);
    APPEND_ARG("-token", cfg->token);
    APPEND_ARG("-ip", cfg->ip);
    
    if (cfg->fallback) {
        strcat(cmdLine, " -fallback");
    } else {
        if (strlen(cfg->dns) > 0 && strcmp(cfg->dns, "dns.alidns.com/dns-query") != 0) {
            APPEND_ARG("-dns", cfg->dns);
        }
        if (strlen(cfg->ech) > 0 && strcmp(cfg->ech, "cloudflare-ech.com") != 0) {
            APPEND_ARG("-ech", cfg->ech);
        }
    }
    
    if (cfg->connections != 3) {
        char nBuf[32]; 
        sprintf(nBuf, " -n %d", cfg->connections);
        strcat(cmdLine, nBuf);
    }

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    // 设置工作目录为程序所在目录
    if (CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, g_exeDir, &si, &processInfo)) {
        CloseHandle(hWrite);
        hLogPipe = hRead;
        hLogThread = CreateThread(NULL, 0, LogReaderThread, NULL, 0, NULL);
        isProcessRunning = TRUE;
        EnableWindow(hStartBtn, FALSE);
        EnableWindow(hStopBtn, TRUE);
        EnableWindow(hServerEdit, FALSE);
        EnableWindow(hListenEdit, FALSE);
        EnableWindow(hServerCombo, FALSE);
        
        char logMsg[512];
        sprintf(logMsg, "[系统] 已启动服务器: %s (%s模式)\r\n", 
            cfg->name, cfg->fallback ? "普通TLS" : "ECH");
        AppendLog(logMsg);
    } else {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        
        char errMsg[512];
        snprintf(errMsg, sizeof(errMsg), "[错误] 启动失败，错误代码: %d\r\n", GetLastError());
        AppendLog(errMsg);
    }
}

void StopProcess() {
    isProcessRunning = FALSE;

    if (hLogPipe) {
        CloseHandle(hLogPipe);
        hLogPipe = NULL;
    }

    if (processInfo.hProcess) {
        TerminateProcess(processInfo.hProcess, 0);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
        processInfo.hProcess = NULL;
    }

    if (hLogThread) {
        if (WaitForSingleObject(hLogThread, 500) == WAIT_TIMEOUT) {
            TerminateThread(hLogThread, 0);
        }
        CloseHandle(hLogThread);
        hLogThread = NULL;
    }
    
    if (IsWindow(hMainWindow)) {
        EnableWindow(hStartBtn, TRUE);
        EnableWindow(hStopBtn, FALSE);
        EnableWindow(hServerEdit, TRUE);
        EnableWindow(hListenEdit, TRUE);
        EnableWindow(hServerCombo, TRUE);
        AppendLog("[系统] 进程已停止。\r\n");
    }
}

void AppendLogAsync(const char* text) {
    if (!text) return;
    char* msgCopy = strdup(text); 
    if (msgCopy) {
        if (!PostMessage(hMainWindow, WM_APPEND_LOG, 0, (LPARAM)msgCopy)) {
            free(msgCopy);
        }
    }
}

DWORD WINAPI LogReaderThread(LPVOID lpParam) {
    (void)lpParam;
    char buf[1024];
    char u8Buf[2048];
    DWORD read;
    
    while (isProcessRunning && hLogPipe) {
        if (ReadFile(hLogPipe, buf, sizeof(buf)-1, &read, NULL) && read > 0) {
            buf[read] = 0;
            int wLen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
            if (wLen > 0) {
                WCHAR* wBuf = (WCHAR*)malloc(wLen * sizeof(WCHAR));
                if (wBuf) {
                    MultiByteToWideChar(CP_UTF8, 0, buf, -1, wBuf, wLen);
                    WideCharToMultiByte(CP_ACP, 0, wBuf, -1, u8Buf, sizeof(u8Buf), NULL, NULL);
                    AppendLogAsync(u8Buf);
                    free(wBuf);
                }
            } else {
                AppendLogAsync(buf);
            }
        } else {
            break; 
        }
    }
    return 0;
}

void AppendLog(const char* text) {
    if (!IsWindow(hLogEdit)) return;
    
    int currentLen = GetWindowTextLength(hLogEdit);
    
    // 限制日志最大长度为80KB
    if (currentLen > 80000) {
        SendMessage(hLogEdit, WM_SETREDRAW, FALSE, 0);
        SendMessage(hLogEdit, EM_SETSEL, 0, 32000);  // 删除前32KB
        SendMessage(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)"");
        SendMessage(hLogEdit, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hLogEdit, NULL, TRUE);
    }
    
    int len = GetWindowTextLength(hLogEdit);
    SendMessage(hLogEdit, EM_SETSEL, len, len);
    SendMessage(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
}

void SaveConfig() {
    char configPath[MAX_PATH];
    GetConfigFilePath(configPath, MAX_PATH);
    
    FILE* f = fopen(configPath, "w");
    if (!f) return;
    
    fprintf(f, "[Settings]\n");
    fprintf(f, "current_server=%d\n", currentServerIndex);
    fprintf(f, "server_count=%d\n\n", serverCount);
    
    for (int i = 0; i < serverCount; i++) {
        fprintf(f, "[Server%d]\n", i);
        fprintf(f, "name=%s\n", servers[i].name);
        fprintf(f, "server=%s\n", servers[i].server);
        fprintf(f, "listen=%s\n", servers[i].listen);
        fprintf(f, "token=%s\n", servers[i].token);
        fprintf(f, "ip=%s\n", servers[i].ip);
        fprintf(f, "dns=%s\n", servers[i].dns);
        fprintf(f, "ech=%s\n", servers[i].ech);
        fprintf(f, "connections=%d\n", servers[i].connections);
        fprintf(f, "fallback=%d\n\n", servers[i].fallback);
    }
    
    fclose(f);
}

void LoadConfig() {
    char configPath[MAX_PATH];
    GetConfigFilePath(configPath, MAX_PATH);
    
    FILE* f = fopen(configPath, "r");
    if (!f) return;
    
    char line[MAX_URL_LEN];
    int currentSection = -1;
    
    while (fgets(line, sizeof(line), f)) {
        char* newline = strchr(line, '\n');
        if (newline) *newline = 0;
        
        if (line[0] == 0 || line[0] == ';' || line[0] == '#') continue;
        
        if (line[0] == '[') {
            if (strncmp(line, "[Settings]", 10) == 0) {
                currentSection = -1;
            } else if (strncmp(line, "[Server", 7) == 0) {
                int idx;
                if (sscanf(line, "[Server%d]", &idx) == 1) {
                    currentSection = idx;
                }
            }
            continue;
        }
        
        char* val = strchr(line, '=');
        if (!val) continue;
        *val++ = 0;
        
        if (currentSection == -1) {
            if (strcmp(line, "current_server") == 0) {
                currentServerIndex = atoi(val);
            } else if (strcmp(line, "server_count") == 0) {
                serverCount = atoi(val);
                if (serverCount > MAX_SERVERS) serverCount = MAX_SERVERS;
                if (serverCount < 0) serverCount = 0;
            }
        } else if (currentSection >= 0 && currentSection < MAX_SERVERS) {
            ServerConfig* srv = &servers[currentSection];
            if (strcmp(line, "name") == 0) {
                strncpy(srv->name, val, MAX_NAME_LEN - 1);
                srv->name[MAX_NAME_LEN - 1] = 0;
            } else if (strcmp(line, "server") == 0) {
                strncpy(srv->server, val, MAX_URL_LEN - 1);
            } else if (strcmp(line, "listen") == 0) {
                strncpy(srv->listen, val, MAX_SMALL_LEN - 1);
            } else if (strcmp(line, "token") == 0) {
                strncpy(srv->token, val, MAX_URL_LEN - 1);
            } else if (strcmp(line, "ip") == 0) {
                strncpy(srv->ip, val, MAX_SMALL_LEN - 1);
            } else if (strcmp(line, "dns") == 0) {
                strncpy(srv->dns, val, MAX_SMALL_LEN - 1);
            } else if (strcmp(line, "ech") == 0) {
                strncpy(srv->ech, val, MAX_SMALL_LEN - 1);
            } else if (strcmp(line, "connections") == 0) {
                srv->connections = atoi(val);
            } else if (strcmp(line, "fallback") == 0) {
                srv->fallback = atoi(val);
            }
        }
    }
    
    fclose(f);
    
    if (currentServerIndex < 0 || currentServerIndex >= serverCount) {
        currentServerIndex = 0;
    }
}