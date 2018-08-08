// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "wireguard_config.h"
#include "network_win32_api.h"
#include "network_win32_dnsblock.h"
#include <Commctrl.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>
#include <stddef.h>
#include "resource.h"
#include <string.h>
#include <Richedit.h>
#include <vector>
#include <Iphlpapi.h>
#include <assert.h>
#include <shldisp.h>
#include <shlobj.h>
#include <exdisp.h>
#include "tunsafe_endian.h"
#include "util.h"
#include <atlbase.h>
#include <algorithm>
#include "crypto/curve25519-donna.h"

#undef min
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib,"comctl32.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

void InitCpuFeatures();
void PrintCpuFeatures();
void Benchmark();
static const char *GetCurrentConfigTitle(char *buf, size_t max_size);

#pragma warning(disable: 4200)

static void MyPostMessage(int msg, WPARAM wparam, LPARAM lparam);

static HWND g_ui_window;
static in_addr_t g_ui_ip;
static HICON g_icons[2];
static bool g_minimize_on_connect;

static bool g_ui_visible;
static char *g_current_filename;
static HKEY g_reg_key;
static HINSTANCE g_hinstance;
static TunsafeBackendWin32 *g_backend;
static bool g_last_popup_is_tray;

int RegReadInt(const char *key, int def) {
  DWORD value = def, n = sizeof(value);
  RegQueryValueEx(g_reg_key, key, NULL, NULL, (BYTE*)&value, &n);
  return value;
}

void RegWriteInt(const char *key, int value) {
  RegSetValueEx(g_reg_key, key, NULL, REG_DWORD, (BYTE*)&value, sizeof(value));
}

char *RegReadStr(const char *key, const char *def) {
  char buf[1024];
  DWORD n = sizeof(buf) - 1;
  DWORD type = 0;
  if (RegQueryValueEx(g_reg_key, key, NULL, &type, (BYTE*)buf, &n) != ERROR_SUCCESS || type != REG_SZ)
    return def ? _strdup(def) : NULL;
  if (n && buf[n - 1] == 0)
    n--;
  buf[n] = 0;
  return _strdup(buf);
}

void RegWriteStr(const char *key, const char *v) {
  RegSetValueEx(g_reg_key, key, NULL, REG_SZ, (BYTE*)v, (DWORD)strlen(v) + 1);
}

void str_set(char **x, const char *s) {
  free(*x);
  *x = _strdup(s);
}

char *str_cat_alloc(const char *a, const char *b) {
  size_t al = strlen(a);
  size_t bl = strlen(b);
  char *r = (char *)malloc(al + bl + 1);
  memcpy(r, a, al);
  r[al + bl] = 0;
  memcpy(r + al, b, bl);
  return r;
}

static const char *FindLastFolderSep(const char *s) {
  size_t len = strlen(s);
  for (;;) {
    if (len == 0)
      return NULL;
    len--;
    if (s[len] == '\\' || s[len] == '/')
      break;
  }
  return s + len;
}


static bool GetConfigFullName(const char *basename, char *fullname, size_t fullname_size) {
  size_t len = strlen(basename);

  if (FindLastFolderSep(basename)) {
    if (len >= fullname_size)
      return false;
    memcpy(fullname, basename, len + 1);
    return true;
  }
  if (!GetModuleFileName(NULL, fullname, (DWORD)fullname_size))
    return false;
  char *last = (char *)FindLastFolderSep(fullname);
  if (!last || last + len + 8 >= fullname + fullname_size)
    return false;
  memcpy(last + 1, "Config\\", 7 * sizeof(last[0]));
  memcpy(last + 8, basename, (len + 1) * sizeof(last[0]));
  return true;
}


enum UpdateIconWhy {
  UIW_NONE = 0,
  UIW_STOPPED_WORKING_FAIL = 1,
  UIW_STOPPED_WORKING_RETRY = 2,
  UIW_EXITING = 3,
};
static void UpdateIcon(UpdateIconWhy error);
static void UpdateButtons();


void StopService(UpdateIconWhy error) {
  if (g_backend->is_started()) {
    g_backend->Stop();

    g_ui_ip = 0;

    if (error != UIW_EXITING) {
      UpdateIcon(error);
      RINFO("Disconnecting");
      UpdateButtons();
      RegWriteInt("IsConnected", 0);
    }
  }
}

const char *print_ip(char buf[kSizeOfAddress], in_addr_t ip) {
  snprintf(buf, kSizeOfAddress, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip >> 0) & 0xff);
  return buf;
}

class MyProcessorDelegate : public ProcessorDelegate {
public:
  virtual void OnConnected(in_addr_t my_ip) {
    if (my_ip != g_ui_ip) {

      if (my_ip) {
        char buf[kSizeOfAddress];
        print_ip(buf, my_ip);
        RINFO("Connection established. IP %s", buf);
      }
      g_ui_ip = my_ip;
      MyPostMessage(WM_USER + 2, 0, 0);
    }
  }
  virtual void OnDisconnected() {
    MyProcessorDelegate::OnConnected(0);
  }
};

static MyProcessorDelegate my_procdel;

void StartService(bool skip_clear = false) {
  char buf[1024];
  if (!GetConfigFullName(g_current_filename, buf, ARRAYSIZE(buf)))
    return;
  
  if (!g_backend->is_started()) {
    if (!skip_clear)
      PostMessage(g_ui_window, WM_USER + 6, NULL, NULL);
   
    g_backend->Start(&my_procdel, buf);

    UpdateButtons();
    RegWriteInt("IsConnected", 1);
  }
}

static bool g_has_icon;

static char *PrintMB(char *buf, int64 bytes) {
  char *bo = buf;
  if (bytes < 0) {
    *buf++ = '-';
    bytes = -bytes;
  }
  int64 big = bytes / (1024*1024);
  int little = bytes % (1024*1024);
  if (bytes < 10*1024*1024) {
    // X.XXX
    snprintf(buf, 64, "%lld.%.3d MB", big, 1000 * little / (1024*1024));
  } else if (bytes < 100*1024*1024) {
    // XX.XX
    snprintf(buf, 64, "%lld.%.2d MB", big, 100 * little / (1024*1024));
  } else {
    // XX.X
    snprintf(buf, 64, "%lld.%.1d MB", big, 10 * little / (1024*1024));
  }
  return bo;
}

static void UpdateStats() {
  ProcessorStats stats = g_backend->GetStats();

  char tmp[64], tmp2[64];
  char buf[512];
  snprintf(buf, 512, "%s received (%lld packets), %s sent (%lld packets)",
    PrintMB(tmp, stats.udp_bytes_in), stats.udp_packets_in,
    PrintMB(tmp2, stats.udp_bytes_out), stats.udp_packets_out/*, udp_qsize2 - udp_qsize1, g_tun_reads*/);
  SetDlgItemText(g_ui_window, IDTXT_UDP, buf);

  snprintf(buf, 512, "%s received (%lld packets), %s sent (%lld packets)",
    PrintMB(tmp, stats.tun_bytes_in), stats.tun_packets_in,
    PrintMB(tmp2, stats.tun_bytes_out), stats.tun_packets_out/*,
          tpq_last_qsize, g_tun_writes*/);
  SetDlgItemText(g_ui_window, IDTXT_TUN, buf);

  char *d = buf;
  if (stats.last_complete_handskake_timestamp) {
    uint32 ago = (uint32)((OsGetMilliseconds() - stats.last_complete_handskake_timestamp) / 1000);
    uint32 hours = ago / 3600;
    uint32 minutes = (ago - hours * 3600) / 60;
    uint32 seconds = (ago - hours * 3600 - minutes * 60);

    if (hours)
      d += snprintf(d, 32, hours == 1 ? "%d hour, " : "%d hours, ", hours);
    if (minutes)
      d += snprintf(d, 32, minutes == 1 ? "%d minute, " : "%d minutes, ", minutes);
    if (d == buf || seconds)
      d += snprintf(d, 32, seconds == 1 ? "%d second, " : "%d seconds, ", seconds);
    memcpy(d - 2, " ago", 5);
  } else {
    memcpy(buf, "(never)", 8);
  }
  SetDlgItemText(g_ui_window, IDTXT_HANDSHAKE, buf);
}

void UpdatePublicKey(char *s) {
  SetDlgItemText(g_ui_window, IDC_PUBLIC_KEY, s);
  free(s);
}

static void UpdateButtons() {
  bool running = g_backend->is_started();
  SetDlgItemText(g_ui_window, ID_START, running ? "Re&connect" : "&Connect");
  EnableWindow(GetDlgItem(g_ui_window, ID_STOP), running);
}

static void UpdateIcon(UpdateIconWhy why) {
  in_addr_t ip = g_ui_ip;
  NOTIFYICONDATA nid;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = sizeof(nid);
  nid.hWnd = g_ui_window;
  nid.uID = 1;
  nid.uVersion = NOTIFYICON_VERSION;
  nid.uCallbackMessage = WM_USER + 1;
  nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
  nid.hIcon = g_icons[ip ? 0 : 1];
  
  char buf[kSizeOfAddress];
  char namebuf[64];
  if (ip != 0) {
    snprintf(nid.szTip, sizeof(nid.szTip), "TunSafe [%s - %s]", GetCurrentConfigTitle(namebuf, sizeof(namebuf)), print_ip(buf, ip));
    nid.uFlags |= NIF_INFO;
    snprintf(nid.szInfoTitle, sizeof(nid.szInfoTitle), "Connected to: %s", namebuf);
    snprintf(nid.szInfo, sizeof(nid.szInfo), "IP: %s", buf);
    nid.uTimeout = 5000;
    nid.dwInfoFlags = NIIF_INFO;
  } else {
    snprintf(nid.szTip, sizeof(nid.szTip), "TunSafe [%s]", "Disconnected");

    if (why == UIW_STOPPED_WORKING_FAIL) {
      nid.uFlags |= NIF_INFO;
      strcpy(nid.szInfoTitle, "Disconnected!");
      strcpy(nid.szInfo, "There was a problem with the connection. You are now disconnected.");
      nid.uTimeout = 5000;
      nid.dwInfoFlags = NIIF_ERROR;
    }
  }
  Shell_NotifyIcon(g_has_icon ? NIM_MODIFY : NIM_ADD, &nid);

  SendMessage(g_ui_window, WM_SETICON, ICON_SMALL, (LPARAM)g_icons[ip ? 0 : 1]);

  g_has_icon = true;
}

static void RemoveIcon() {
  if (g_has_icon) {
    NOTIFYICONDATA nid;
    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_ui_window;
    nid.uID = 1;
    Shell_NotifyIcon(NIM_DELETE, &nid);
  }
}

#define MAX_CONFIG_FILES 100
#define ID_POPUP_CONFIG_FILE 10000
char *config_filenames[MAX_CONFIG_FILES];

static void RestartService(UpdateIconWhy why, bool only_if_active) {
  if (!only_if_active || g_backend->is_started()) {
    StopService(why);
    StartService(why != UIW_NONE);
  }
}

static char *StripConfExtension(const char *src, char *target, size_t size) {
  size_t len = strlen(src);
  if (len >= 5 && memcmp(src + len - 5, ".conf", 5) == 0)
    len -= 5;

  len = std::min(len, size - 1);
  target[len] = 0;
  memcpy(target, src, len);
  return target;
}

static const char *GetCurrentConfigTitle(char *target, size_t size) {
  const char *ll = FindLastFolderSep(g_current_filename);
  return StripConfExtension(ll ? ll + 1 : g_current_filename, target, size);
}

static void LoadConfigFile(const char *filename, bool save, bool force_start) {
  str_set(&g_current_filename, filename);
  char namebuf[64];
  char *f = str_cat_alloc("TunSafe VPN Client - ", GetCurrentConfigTitle(namebuf, sizeof(namebuf)));
  SetWindowText(g_ui_window, f);
  free(f);
  RestartService(UIW_NONE, !force_start);
  if (save)
    RegWriteStr("ConfigFile", filename);
}

static void AddToAvailableFilesPopup(HMENU menu, int max_num_items, bool is_settings) {
  char buf[1024];
  int nfiles = 0;
  if (!GetConfigFullName("*.*", buf, ARRAYSIZE(buf)))
    return;
    
  int selected_item = -1;
  WIN32_FIND_DATA wfd;
  HANDLE handle = FindFirstFile(buf, &wfd);
  if (handle != INVALID_HANDLE_VALUE) {
    do {
      if (wfd.cFileName[0] == '.')
        continue;

      if (strcmp(g_current_filename, wfd.cFileName) == 0)
        selected_item = nfiles;

      str_set(&config_filenames[nfiles], wfd.cFileName);
      
      nfiles++;
      if (nfiles == MAX_CONFIG_FILES)
        break;
    } while (FindNextFile(handle, &wfd));
    FindClose(handle);
  }

  HMENU where;

  bool is_connected = g_backend->is_started();

  where = menu;
  for (int i = 0; i < nfiles; i++) {
    if (i == max_num_items) {
      where = CreatePopupMenu();
      AppendMenu(menu, MF_POPUP, (UINT_PTR)where, "&More");
    }

    AppendMenu(where, (i == selected_item && is_connected) ? MF_CHECKED : 0, ID_POPUP_CONFIG_FILE + i, StripConfExtension(config_filenames[i], buf, sizeof(buf)));

    if (i == selected_item)
      SetMenuDefaultItem(where, ID_POPUP_CONFIG_FILE + i, MF_BYCOMMAND);
  }
  if (nfiles)
    AppendMenu(menu, MF_SEPARATOR, 0, 0);
}

static void ShowSettingsMenu(HWND wnd) {
  HMENU menu = CreatePopupMenu();

  AddToAvailableFilesPopup(menu, 10, true);

  AppendMenu(menu, 0, IDSETT_OPEN_FILE, "&Import File...");
  AppendMenu(menu, 0, IDSETT_BROWSE_FILES, "&Browse in Explorer");

  AppendMenu(menu, MF_SEPARATOR, 0, 0);
  AppendMenu(menu, 0, IDSETT_KEYPAIR, "Generate &Key Pair...");
  AppendMenu(menu, MF_SEPARATOR, 0, 0);

  HMENU blockinternet = CreatePopupMenu();
  AppendMenu(blockinternet, 0, IDSETT_BLOCKINTERNET_OFF, "Off");
  AppendMenu(blockinternet, MF_SEPARATOR, 0, 0);
  AppendMenu(blockinternet, 0, IDSETT_BLOCKINTERNET_ROUTE, "Yes, with Routing Rules");
  AppendMenu(blockinternet, 0, IDSETT_BLOCKINTERNET_FIREWALL, "Yes, with Firewall Rules");
  AppendMenu(blockinternet, 0, IDSETT_BLOCKINTERNET_BOTH, "Yes, Both Methods");
  bool is_activated = false;
  int value = GetInternetBlockState(&is_activated);
  CheckMenuRadioItem(blockinternet, IDSETT_BLOCKINTERNET_OFF, IDSETT_BLOCKINTERNET_BOTH, IDSETT_BLOCKINTERNET_OFF + value, MF_BYCOMMAND);
  AppendMenu(menu, MF_POPUP + is_activated * MF_CHECKED, (UINT_PTR)blockinternet, "Block &All Internet Traffic");
  
  if (g_allow_pre_post || GetAsyncKeyState(VK_SHIFT) < 0) {
    AppendMenu(menu, g_allow_pre_post ? MF_CHECKED : 0, IDSETT_PREPOST, "&Allow Pre/Post commands");
  }

  AppendMenu(menu, MF_SEPARATOR, 0, 0);
  AppendMenu(menu, 0, IDSETT_WEB_PAGE, "Go to &Web Page");
  AppendMenu(menu, 0, IDSETT_OPENSOURCE, "See Open Source Licenses");
  AppendMenu(menu, 0, IDSETT_ABOUT, "&About TunSafe...");
  
  POINT pt;
  GetCursorPos(&pt);

  g_last_popup_is_tray = false;
  int rv = TrackPopupMenu(menu, 0, pt.x, pt.y, 0, wnd, NULL);
  DestroyMenu(menu);
}

void FindDesktopFolderView(REFIID riid, void **ppv) {
  CComPtr<IShellWindows> spShellWindows;
  spShellWindows.CoCreateInstance(CLSID_ShellWindows);

  CComVariant vtLoc(CSIDL_DESKTOP);
  CComVariant vtEmpty;
  long lhwnd;
  CComPtr<IDispatch> spdisp;
  spShellWindows->FindWindowSW(
    &vtLoc, &vtEmpty,
    SWC_DESKTOP, &lhwnd, SWFO_NEEDDISPATCH, &spdisp);

  CComPtr<IShellBrowser> spBrowser;
  CComQIPtr<IServiceProvider>(spdisp)->
    QueryService(SID_STopLevelBrowser,
                 IID_PPV_ARGS(&spBrowser));

  CComPtr<IShellView> spView;
  spBrowser->QueryActiveShellView(&spView);

  spView->QueryInterface(riid, ppv);
}

void GetDesktopAutomationObject(REFIID riid, void **ppv) {
  CComPtr<IShellView> spsv;
  FindDesktopFolderView(IID_PPV_ARGS(&spsv));
  CComPtr<IDispatch> spdispView;
  spsv->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&spdispView));
  spdispView->QueryInterface(riid, ppv);
}

void ShellExecuteFromExplorer(
  PCSTR pszFile,
  PCSTR pszParameters = nullptr,
  PCSTR pszDirectory = nullptr,
  PCSTR pszOperation = nullptr,
  int nShowCmd = SW_SHOWNORMAL) {
  CComPtr<IShellFolderViewDual> spFolderView;
  GetDesktopAutomationObject(IID_PPV_ARGS(&spFolderView));
  CComPtr<IDispatch> spdispShell;
  spFolderView->get_Application(&spdispShell);

  CComQIPtr<IShellDispatch2>(spdispShell)
    ->ShellExecute(CComBSTR(pszFile),
                   CComVariant(pszParameters ? pszParameters : ""),
                   CComVariant(pszDirectory ? pszDirectory : ""),
                   CComVariant(pszOperation ? pszOperation : ""),
                   CComVariant(nShowCmd));
}

static void OpenEditor() {
  char buf[MAX_PATH];
  if (GetConfigFullName(g_current_filename, buf, ARRAYSIZE(buf))) {
    SHELLEXECUTEINFO shinfo = {0};
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_CLASSNAME;
    shinfo.lpFile = buf;
    shinfo.lpParameters = "";
    shinfo.lpClass = ".txt";
    shinfo.nShow = SW_SHOWNORMAL;
    ShellExecuteEx(&shinfo);
  }
}

static void BrowseFiles() {
  char buf[MAX_PATH];
  if (GetConfigFullName("", buf, ARRAYSIZE(buf))) {
    size_t l = strlen(buf);
    buf[l - 1] = 0;
    ShellExecuteFromExplorer(buf, NULL, NULL, "explore");
  }
}

bool FileExists(const CHAR *fileName) {
  DWORD fileAttr = GetFileAttributes(fileName);
  return (0xFFFFFFFF != fileAttr);
}

__int64 FileSize(const char* name) {
  WIN32_FILE_ATTRIBUTE_DATA fad;
  if (!GetFileAttributesEx(name, GetFileExInfoStandard, &fad))
    return -1; // error condition, could call GetLastError to find out more
  LARGE_INTEGER size;
  size.HighPart = fad.nFileSizeHigh;
  size.LowPart = fad.nFileSizeLow;
  return size.QuadPart;
}

static bool is_space(uint8_t c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

static bool is_valid(uint8_t c) {
  return c >= ' ' || c == '\r' || c == '\n' || c == '\t';
}

bool SanityCheckBuf(uint8 *buf, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (!is_space(buf[i])) {
      if (buf[i] != '[' && buf[i] != '#')
        return false;
      for (; i < n; i++)
        if (!is_valid(buf[i]))
          return false;
      return true;
    }
  }
  return false;
}

uint8* LoadFileSane(const char *name, size_t *size) {
  FILE *f = fopen(name, "rb");
  uint8 *new_file = NULL, *file = NULL;
  size_t j, i, n;
  if (!f) return false;
  fseek(f, 0, SEEK_END);
  long x = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (x < 0 || x >= 65536) goto error;
  file = (uint8*)malloc(x + 1);
  if (!file) goto error;
  n = fread(file, 1, x + 1, f);
  if (n != x || !SanityCheckBuf(file, n))
    goto error;
  // Convert the file to DOS new lines
  for (i = j = 0; i < n; i++)
    j += (file[i] == '\n');
  new_file = (uint8*)malloc(n + 1 + j);
  if (!new_file) goto error;
  for (i = j = 0; i < n; i++) {
    uint8 c = file[i];
    if (c == '\r')
      continue;
    if (c == '\n')
      new_file[j++] = '\r';
    new_file[j++] = c;
  }
  new_file[j] = 0;
  *size = j;

error:
  fclose(f);
  free(file);
  return new_file;
}

bool WriteOutFile(const char *filename, uint8 *filedata, size_t filesize) {
  FILE *f = fopen(filename, "wb");
  if (!f) return false;
  if (fwrite(filedata, 1, filesize, f) != filesize) {
    fclose(f);
    return false;
  }
  fclose(f);
  return true;
}

void ImportFile(const char *s) {
  char buf[1024];
  char mesg[1024];
  size_t filesize;
  const char *last = FindLastFolderSep(s);
  if (!last || !GetConfigFullName(last + 1, buf, ARRAYSIZE(buf)) || _stricmp(buf, s) == 0)
    return;

  uint8 *filedata = LoadFileSane(s, &filesize);
  if (!filedata) goto fail;

  if (FileExists(buf)) {
    snprintf(mesg, ARRAYSIZE(mesg), "A file already exists with the name '%s' in the configuration folder. Do you want to overwrite it?", last + 1);
    if (MessageBoxA(g_ui_window, mesg, "TunSafe", MB_OKCANCEL | MB_ICONEXCLAMATION) != IDOK)
      goto out;
  } else {
    snprintf(mesg, ARRAYSIZE(mesg), "Do you want to import '%s' into TunSafe?", last + 1);
    if (MessageBoxA(g_ui_window, mesg, "TunSafe", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
      goto out;
  }

  if (!WriteOutFile(buf, filedata, filesize)) {
    DeleteFileA(buf);
fail:
    MessageBoxA(g_ui_window, "There was a problem importing the file.", "TunSafe", MB_ICONEXCLAMATION);
  } else {
    LoadConfigFile(last + 1, true, false);
  }

out:
  free(filedata);
}

void ShowUI(HWND hWnd) {
  g_ui_visible = true;
  UpdateStats();
  ShowWindow(hWnd, SW_SHOW);
  BringWindowToTop(hWnd);
  SetForegroundWindow(hWnd);
}

void HandleDroppedFiles(HWND wnd, HDROP hdrop) {
  char buf[MAX_PATH];
  if (DragQueryFile(hdrop, -1, NULL, 0) == 1) {
    if (DragQueryFile(hdrop, 0, buf, ARRAYSIZE(buf))) {
      SetForegroundWindow(wnd);
      ImportFile(buf);
    }
  }
  DragFinish(hdrop);
}

void BrowseFile(HWND wnd) {
  char szFile[1024];

  // open a file name
  OPENFILENAME ofn = {0};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_ui_window;
  ofn.lpstrFile = szFile;
  ofn.lpstrFile[0] = '\0';
  ofn.nMaxFile = sizeof(szFile);
  ofn.lpstrFilter = "Config Files (*.conf)\0*.conf\0";
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = NULL;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = NULL;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
  if (GetOpenFileName(&ofn))
    ImportFile(szFile);
}

static const uint8 kCurve25519Basepoint[32] = {9};

static void SetKeyBox(HWND wnd, int ctr, uint8 buf[32]) {
  uint8 *privs = base64_encode(buf, 32, NULL);
  SetDlgItemText(wnd, ctr, (char*)privs);
  free(privs);
}

static INT_PTR WINAPI KeyPairDlgProc(HWND hWnd, UINT message, WPARAM wParam,
                              LPARAM lParam) {
  switch (message) {
  case WM_INITDIALOG:
    return TRUE;
  case WM_CLOSE:
    EndDialog(hWnd, 0);
    return TRUE;
  case WM_COMMAND:
    switch (wParam) {
    case IDCANCEL:
      EndDialog(hWnd, 0);
      return TRUE;
    case IDC_PRIVATE_KEY | (EN_CHANGE << 16) : {
      char buf[128];
      uint8 pub[32];
      uint8 priv[32];
      buf[0] = 0;
      size_t len = GetDlgItemText(hWnd, IDC_PRIVATE_KEY, buf, sizeof(buf));
      size_t olen = 32;
      if (base64_decode((uint8*)buf, len, priv, &olen) && olen == 32) {
        curve25519_donna(pub, priv, kCurve25519Basepoint);
        SetKeyBox(hWnd, IDC_PUBLIC_KEY, pub);
      } else {
        SetDlgItemText(hWnd, IDC_PUBLIC_KEY, "(Invalid Private Key)");
      }

      return TRUE;
    }
    case IDRAND: {
      uint8 priv[32];
      uint8 pub[32];
      OsGetRandomBytes(priv, 32);
      curve25519_normalize(priv);
      curve25519_donna(pub, priv, kCurve25519Basepoint);
      SetKeyBox(hWnd, IDC_PRIVATE_KEY, priv);
      SetKeyBox(hWnd, IDC_PUBLIC_KEY, pub);
      return TRUE;
    }
    }
  }
  return FALSE;
}

bool wm_dropfiles_recursive;
uint64 last_auto_service_restart;
static INT_PTR WINAPI DlgProc(HWND hWnd, UINT message, WPARAM wParam,
                                LPARAM lParam) {
  switch(message) {
  case WM_INITDIALOG:
    return TRUE;
  case WM_CLOSE:
    g_ui_visible = false;
    ShowWindow(hWnd, SW_HIDE);
    return TRUE;
  case WM_COMMAND:
    if (wParam >= ID_POPUP_CONFIG_FILE && wParam < ID_POPUP_CONFIG_FILE + MAX_CONFIG_FILES) {
      const char *new_conf = config_filenames[wParam - ID_POPUP_CONFIG_FILE];
      if (!new_conf)
        return TRUE;

      if (g_last_popup_is_tray && strcmp(new_conf, g_current_filename) == 0 && g_backend->is_started()) {
        StopService(UIW_NONE);
      } else {
        LoadConfigFile(new_conf, true, g_last_popup_is_tray);
      }


      return TRUE;
    }
    switch(wParam) {
    case ID_START: 
      StopService(UIW_NONE);
      StartService();
      break;
    case ID_STOP:  StopService(UIW_NONE); break;
    case ID_EXIT:  PostQuitMessage(0); break;
    case ID_RESET: g_backend->ResetStats(); break;
    case ID_MORE_BUTTON: ShowSettingsMenu(hWnd); break;
    case IDSETT_WEB_PAGE: ShellExecute(NULL, NULL, "https://tunsafe.com/", NULL, NULL, 0); break;
    case IDSETT_OPENSOURCE: ShellExecute(NULL, NULL, "https://tunsafe.com/open-source", NULL, NULL, 0); break;
    case ID_EDITCONF: OpenEditor(); break;
    case IDSETT_BROWSE_FILES:BrowseFiles(); break;
    case IDSETT_OPEN_FILE: BrowseFile(hWnd); break;
    case IDSETT_ABOUT:
      MessageBoxA(g_ui_window, TUNSAFE_VERSION_STRING "\r\n\r\nCopyright © 2018, Ludvig Strigeus\r\n\r\nThanks for choosing TunSafe!\r\n\r\nThis version was built on " __DATE__ " " __TIME__, "About TunSafe", MB_ICONINFORMATION);
      break;
    case IDSETT_KEYPAIR:
      DialogBox(g_hinstance, MAKEINTRESOURCE(IDD_DIALOG2), hWnd, &KeyPairDlgProc);
      break;
    case IDSETT_BLOCKINTERNET_OFF:
    case IDSETT_BLOCKINTERNET_ROUTE:
    case IDSETT_BLOCKINTERNET_FIREWALL: 
    case IDSETT_BLOCKINTERNET_BOTH: {
      InternetBlockState old_state = GetInternetBlockState(NULL);
      InternetBlockState new_state = (InternetBlockState)(wParam - IDSETT_BLOCKINTERNET_OFF);

      if (old_state == kBlockInternet_Off && new_state != kBlockInternet_Off) {
        if (MessageBoxA(g_ui_window, "Warning! All Internet traffic will be blocked until you restart your computer. Only traffic through TunSafe will be allowed.\r\n\r\nThe blocking is activated the next time you connect to a VPN server.\r\n\r\nDo you want to continue?", "TunSafe", MB_ICONWARNING | MB_OKCANCEL) == IDCANCEL)
          return TRUE;
      }

      SetInternetBlockState(new_state);

      if ((~old_state & new_state) && g_backend->is_started()) {
        StopService(UIW_NONE);
        StartService();
      }
      return TRUE;
    }
    case IDSETT_PREPOST: {
      g_allow_pre_post = !g_allow_pre_post;
      RegWriteInt("AllowPrePost", g_allow_pre_post);
      return TRUE;
    }
    }
    break;
  case WM_DROPFILES:
    if (!wm_dropfiles_recursive) {
      wm_dropfiles_recursive = true;
      HandleDroppedFiles(hWnd, (HDROP)wParam);
      wm_dropfiles_recursive = false;
    }
    break;
  case WM_USER + 1:
    if (lParam == WM_RBUTTONUP) {
      HMENU menu = CreatePopupMenu();
      AddToAvailableFilesPopup(menu, 10, false);

      bool active = g_backend->is_started();
      AppendMenu(menu, 0, ID_START, active ? "Re&connect" : "&Connect");
      AppendMenu(menu, active ? 0 : MF_GRAYED, ID_STOP, "&Disconnect");
      AppendMenu(menu, MF_SEPARATOR, 0, NULL);
      AppendMenu(menu, 0, ID_EXIT, "&Exit");
      POINT pt;
      GetCursorPos(&pt);

      SetForegroundWindow(hWnd);

      g_last_popup_is_tray = true;

      int rv = TrackPopupMenu(menu, 0, pt.x, pt.y, 0, hWnd, NULL);      
      DestroyMenu(menu);
    } else if (lParam == WM_LBUTTONDBLCLK) {
      if (IsWindowVisible(hWnd)) {
        g_ui_visible = false;
        ShowWindow(hWnd, SW_HIDE);
      } else {
        ShowUI(hWnd);
      }
    }
    return TRUE;
  case WM_USER + 2:
    if (g_ui_ip != 0 && g_minimize_on_connect) {
      g_minimize_on_connect = false;
      g_ui_visible = false;
      ShowWindow(hWnd, SW_HIDE);
    }
    UpdateIcon(UIW_NONE);
    return TRUE;
  case WM_USER + 3: {
    CHARRANGE cr;
    cr.cpMin = -1;
    cr.cpMax = -1;
    // hwnd = rich edit hwnd
    SendDlgItemMessage(hWnd, IDC_RICHEDIT21, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendDlgItemMessage(hWnd, IDC_RICHEDIT21, EM_REPLACESEL, 0, (LPARAM)lParam);
    free( (void*) lParam);
    return true;
  }
  case WM_USER + 6:
    SetDlgItemText(hWnd, IDC_RICHEDIT21, "");
    return true;
  case WM_USER + 5:
    UpdatePublicKey((char*)lParam);
    return true;
  case WM_USER + 4: {
    UpdateStats();
    return true;
  }                      
  case WM_USER + 10:
    break;

  case WM_USER + 11: {
    uint64 now = GetTickCount64();
    if (now < last_auto_service_restart + 5000) {
      RERROR("Too many automatic restarts...");
      StopService(UIW_STOPPED_WORKING_FAIL);
    } else {
      last_auto_service_restart = now;
      RestartService(UIW_STOPPED_WORKING_RETRY, true);
    }
    break;
  }
  }
  return FALSE;
}

struct PostMsg {
  int msg;
  WPARAM wparam;
  LPARAM lparam;
  PostMsg(int a, WPARAM b, LPARAM c) : msg(a), wparam(b), lparam(c) {}
};

static HANDLE msg_event;
static CRITICAL_SECTION msg_section;
static std::vector<PostMsg> msgvect;

static DWORD WINAPI MessageThread(void *x) {
  std::vector<PostMsg> proc;
  for(;;) {
    WaitForSingleObject(msg_event, INFINITE);
    proc.clear();
    EnterCriticalSection(&msg_section);
    std::swap(proc, msgvect);
    LeaveCriticalSection(&msg_section);
    for(size_t i = 0; i != proc.size(); i++)
      PostMessage(g_ui_window, proc[i].msg, proc[i].wparam, proc[i].lparam);
  }
}

static void MyPostMessage(int msg, WPARAM wparam, LPARAM lparam) {
  size_t count;
  EnterCriticalSection(&msg_section);
  count = msgvect.size();
  msgvect.emplace_back(msg, wparam, lparam);
  LeaveCriticalSection(&msg_section);
  if (count == 0) SetEvent(msg_event);
}

static void InitMyPostMessage() {
  msg_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  InitializeCriticalSection(&msg_section);
  DWORD thread_id;
  CloseHandle(CreateThread(NULL, 0, &MessageThread, NULL, 0, &thread_id));
}


void OsGetRandomBytes(uint8 *data, size_t data_size) {
#if defined(OS_WIN)
  static BOOLEAN(APIENTRY *pfn)(void*, ULONG);
  static bool resolved;
  if (!resolved) {
    pfn = (BOOLEAN(APIENTRY *)(void*, ULONG))GetProcAddress(LoadLibrary("ADVAPI32.DLL"), "SystemFunction036");
    resolved = true;
  }
  if (pfn && pfn(data, (ULONG)data_size))
    return;
  int r = 0;
#else
  int fd = open("/dev/urandom", O_RDONLY);
  int r = read(fd, data, data_size);
  if (r < 0) r = 0;
  close(fd);
#endif
  for (; r < data_size; r++)
    data[r] = rand() >> 6;
}

void OsInterruptibleSleep(int millis) {
  SleepEx(millis, TRUE);
}


uint64 OsGetMilliseconds() {
  return GetTickCount64();
}

void OsGetTimestampTAI64N(uint8 dst[12]) {
  SYSTEMTIME systime;
  uint64 file_time_uint64 = 0;
  GetSystemTime(&systime);
  SystemTimeToFileTime(&systime, (FILETIME*)&file_time_uint64);
  uint64 time_since_epoch_100ns = (file_time_uint64 - 116444736000000000);
  uint64 secs_since_epoch = time_since_epoch_100ns / 10000000 + 0x400000000000000a;
  uint32 nanos = (uint32)(time_since_epoch_100ns % 10000000) * 100;
  WriteBE64(dst, secs_since_epoch);
  WriteBE32(dst + 8, nanos);
}



void PushLine(const char *s) {
  size_t l = strlen(s);
  char buf[64];
  SYSTEMTIME t;

  GetLocalTime(&t);

  snprintf(buf, sizeof(buf), "[%.2d:%.2d:%.2d] ", t.wHour, t.wMinute, t.wSecond);
  size_t tl = strlen(buf);

  char *x = (char*)malloc(tl + l + 3);
  if (!x) return;
  memcpy(x, buf, tl);
  memcpy(x + tl, s, l);
  x[l + tl] = '\r';
  x[l + tl + 1] = '\n';
  x[l + tl + 2] = '\0';
  MyPostMessage(WM_USER + 3, 0, (LPARAM)x);
}

void EnsureConfigDirCreated() {
  char fullname[1024];
  if (GetConfigFullName("", fullname, sizeof(fullname)))
    CreateDirectory(fullname, NULL);
}

void EnableControl(int wnd, bool b) {
  EnableWindow(GetDlgItem(g_ui_window, wnd), b);
}


LRESULT CALLBACK NotifyWndProc(HWND  hwnd, UINT  uMsg, WPARAM wParam, LPARAM lParam) {
  switch (uMsg) {
  case WM_USER + 10:
    if (wParam == 1) {
      PostQuitMessage(0);
      return 31337;
    } else if (wParam == 0) {
      ShowUI(g_ui_window);
      return 31337;
    }
    break;
  }
  return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CreateNotificationWindow() {
  WNDCLASSEX wce = {0};
  wce.cbSize = sizeof(wce);
  wce.lpfnWndProc = &NotifyWndProc;
  wce.hInstance = g_hinstance;
  wce.lpszClassName = "TunSafe-f19e092db01cbe0fb6aee132f8231e5b71c98f90";
  RegisterClassEx(&wce);
  CreateWindow("TunSafe-f19e092db01cbe0fb6aee132f8231e5b71c98f90", "TunSafe-f19e092db01cbe0fb6aee132f8231e5b71c98f90", 0, 0, 0, 0, 0, 0, 0, g_hinstance, NULL);
}


void CallbackUpdateUI() {
  if (g_ui_visible)
    MyPostMessage(WM_USER + 4, NULL, NULL);
}

void CallbackTriggerReconnect() {
  PostMessage(g_ui_window, WM_USER + 11, 0, 0);
}

void CallbackSetPublicKey(const uint8 public_key[32]) {
  char *str = (char*)base64_encode(public_key, 32, NULL);
  PostMessage(g_ui_window, WM_USER + 5, NULL, (LPARAM)str);
}

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
  g_hinstance = hInstance;
  InitCpuFeatures();

  // Check if the app is already running.
  CreateMutexA(0, FALSE, "TunSafe-f19e092db01cbe0fb6aee132f8231e5b71c98f90");
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    HWND window = FindWindow("TunSafe-f19e092db01cbe0fb6aee132f8231e5b71c98f90", NULL);
    DWORD_PTR result;
    if (!window || !SendMessageTimeout(window, WM_USER + 10, 0, 0, SMTO_BLOCK, 3000, &result) || result != 31337) {
      MessageBoxA(NULL, "It looks like TunSafe is already running, but not responding. Please kill the old process first.", "TunSafe", MB_ICONWARNING);
    }
    return 1;
  }
  CreateNotificationWindow();

  WSADATA wsaData = {0};
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    RERROR("WSAStartup failed");
    return 1;
  }

  LoadLibrary(TEXT("Riched20.dll"));

  g_backend = new TunsafeBackendWin32();

  InitMyPostMessage();
  InitCommonControls();

  g_icons[0] = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
  g_icons[1] = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON0));
  g_ui_window = CreateDialog(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), NULL, &DlgProc);

  if (!g_ui_window)
    return 1;

  RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\TunSafe", NULL, NULL, 0, KEY_ALL_ACCESS, NULL, &g_reg_key, NULL);
  DragAcceptFiles(g_ui_window, TRUE);

  ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
  ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ADD);
  ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);

  static const int ctrls[] = {IDTXT_UDP, IDTXT_TUN, IDTXT_HANDSHAKE};
  for (int i = 0; i < 3; i++) {
    HWND w = GetDlgItem(g_ui_window, ctrls[i]);
    SetWindowLong(w, GWL_EXSTYLE, GetWindowLong(w, GWL_EXSTYLE) | WS_EX_COMPOSITED);
  }

  g_allow_pre_post = RegReadInt("AllowPrePost", 0) != 0;

  bool minimize = false;
  const char *filename = NULL;

  for (size_t i = 1; i < __argc; i++) {
    const char *arg = __argv[i];

    if (_stricmp(arg, "/minimize") == 0) {
      minimize = true;
    } else if (_stricmp(arg, "/minimize_on_connect") == 0) {
      g_minimize_on_connect = true;
    } else if (_stricmp(arg, "/allow_pre_post") == 0) {
      g_allow_pre_post = true;
    } else {
      filename = arg;
      break;
    }
  }

  if (!minimize) {
    g_ui_visible = true;
    ShowWindow(g_ui_window, SW_SHOW);
  }

  UpdateIcon(UIW_NONE);

  g_logger = &PushLine;

  EnsureConfigDirCreated();

  if (filename) {
    LoadConfigFile(filename, false, false);
  } else {
    char *conf = RegReadStr("ConfigFile", "TunSafe.conf");
    LoadConfigFile(conf, false, false);
    free(conf);
  }
  
  //  PrintCpuFeatures();

//  Benchmark();

  if (filename != NULL || RegReadInt("IsConnected", 0)) {
    StartService();
  } else {
    RINFO("Press Connect to initiate a connection to the WireGuard server.");
  }
  
  MSG msg;

  while (GetMessage(&msg, NULL, 0, 0)) {
    if (!IsDialogMessage(g_ui_window, &msg)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }
  StopService(UIW_EXITING);
  RemoveIcon();

  return 0;
}



