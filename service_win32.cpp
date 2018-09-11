// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "service_win32.h"
#include <strsafe.h>
#include "util.h"
#include "network_win32_api.h"
#include <algorithm>
#include <string>
#include <assert.h>
#include "util_win32.h"

static const uint64 kTunsafeServiceProtocolVersion = 20180809001;

static SERVICE_STATUS_HANDLE m_statusHandle;
static TunsafeServiceImpl *g_service;

#define SERVICE_NAME             L"TunSafeService"
#define SERVICE_NAMEA            "TunSafeService"
#define SERVICE_START_TYPE       SERVICE_AUTO_START
#define SERVICE_DEPENDENCIES     L"tap0901\0dhcp\0"
#define SERVICE_ACCOUNT          NULL
//L"NT AUTHORITY\\LocalService"
#define SERVICE_PASSWORD         NULL
#define PIPE_NAME "\\\\.\\pipe\\TunSafe\\ServiceControl"


enum {
  SERVICE_REQ_LOGIN = 0,
  SERVICE_REQ_START = 1,
  SERVICE_REQ_STOP = 2,
  SERVICE_REQ_GETSTATS = 4,
  SERVICE_REQ_SET_INTERNET_BLOCKSTATE = 5,
  SERVICE_REQ_RESETSTATS = 6,
  SERVICE_REQ_SET_STARTUP_FLAGS = 7,

  SERVICE_MSG_STATE = 8,
  SERVICE_MSG_LOGLINE = 9,
  SERVICE_MSG_STATS = 11,
  SERVICE_MSG_CLEARLOG = 12,
  SERVICE_MSG_STATUS_CODE = 14,

  SERVICE_REQ_GET_GRAPH = 15,
  SERVICE_MSG_GRAPH = 16,
};

struct ServiceHandles {
  SC_HANDLE manager;
  SC_HANDLE service;

  ServiceHandles() : manager(NULL), service(NULL) {}
  ~ServiceHandles() {
    if (manager)
      CloseServiceHandle(manager);
    if (service)
      CloseServiceHandle(service);
  }

  bool Open(PWSTR pszServiceName, DWORD sc_rights, DWORD service_rights);
  bool StopService();
  bool StartService();
};


static DWORD InstallService(PWSTR pszServiceName,
                    PWSTR pszDisplayName,
                    DWORD dwStartType,
                    PWSTR pszDependencies,
                    PWSTR pszAccount,
                    PWSTR pszPassword) {
  wchar_t szPath[MAX_PATH + 32];
  ServiceHandles handles;
  DWORD res;

  szPath[0] = '"';
  if (GetModuleFileNameW(NULL, szPath + 1, MAX_PATH) == 0) {
    res = GetLastError();
    goto Cleanup;
  }
  size_t len = wcslen(szPath);
  memcpy(szPath + len, L"\" --service", 12 * sizeof(wchar_t));

  // Open the local default service control manager database
  handles.manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT |
                               SC_MANAGER_CREATE_SERVICE);
  if (handles.manager == NULL) {
    res = GetLastError();
    goto Cleanup;
  }

  // Install the service into SCM by calling CreateService
  handles.service = CreateServiceW(
    handles.manager,                   // SCManager database
    pszServiceName,                 // Name of service
    pszDisplayName,                 // Name to display
    SERVICE_QUERY_STATUS,           // Desired access
    SERVICE_WIN32_OWN_PROCESS,      // Service type
    dwStartType,                    // Service start type
    SERVICE_ERROR_NORMAL,           // Error control type
    szPath,                         // Service's binary
    NULL,                           // No load ordering group
    NULL,                           // No tag identifier
    pszDependencies,                // Dependencies
    pszAccount,                     // Service running account
    pszPassword                     // Password of the account
  );
  if (handles.service == NULL) {
    res = GetLastError();
    goto Cleanup;
  }
  {
    SERVICE_DESCRIPTIONA desc;
    desc.lpDescription = "TunSafe uses this service to connect to a VPN server in the background.";
    ChangeServiceConfig2A(handles.service, SERVICE_CONFIG_DESCRIPTION, &desc);
  }
  res = 0;
Cleanup:
  if (res && res != ERROR_SERVICE_EXISTS)
    RERROR("TunSafe service installation failed: %d", res);
  return res;
}

bool ServiceHandles::Open(PWSTR pszServiceName, DWORD sc_rights, DWORD service_rights) {
  manager = OpenSCManagerW(NULL, NULL, sc_rights);
  if (manager == NULL)
    return false;
  service = OpenServiceW(manager, pszServiceName, service_rights);
  return (service != NULL);
}

bool ServiceHandles::StopService() {
  SERVICE_STATUS ssSvcStatus = {};
  // Try to stop the service
  if (ControlService(service, SERVICE_CONTROL_STOP, &ssSvcStatus)) {
    Sleep(100);
    while (QueryServiceStatus(service, &ssSvcStatus)) {
      if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING) {
        Sleep(100);
      } else {
        break;
      }
    }
  }
  return (ssSvcStatus.dwCurrentState == SERVICE_STOPPED);
}

static wchar_t *GetUsernameOfCurrentUser(bool use_thread_token) {
  HANDLE thread_token = NULL;
  wchar_t *result = NULL;
  DWORD len;
  PTOKEN_USER token_user = NULL;
  DWORD domain_len;
  WCHAR username[256], domain[256];
  SID_NAME_USE sid_type;

  if (use_thread_token) {
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &thread_token))
      goto getout;
  } else {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &thread_token))
      goto getout;

  }
  len = 0;
  token_user = NULL;
  while (!GetTokenInformation(thread_token, TokenUser, token_user, len, &len)) {
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      goto getout;
    token_user = (PTOKEN_USER)realloc(token_user, len);
    if (!token_user)
      goto getout;
  }
  if (!IsValidSid(token_user->User.Sid))
    goto getout;
  domain_len = len = 256;
  if (!LookupAccountSidW(NULL, token_user->User.Sid, username, &len, domain, &domain_len, &sid_type))
    goto getout;

  size_t alen = wcslen(username);
  size_t blen = wcslen(domain);

  result = (wchar_t*)malloc((alen + blen + 2) * sizeof(wchar_t));
  if (result) {
    result[alen] = '@';
    memcpy(result, username, alen * sizeof(wchar_t));
    memcpy(result + alen + 1, domain, (blen + 1) * sizeof(wchar_t));
  }
getout:
  free(token_user);
  CloseHandle(thread_token);
  return result;
}


static DWORD GetNonTransientServiceStatus(SC_HANDLE service) {
  SERVICE_STATUS ssSvcStatus = {};
  int delay = 100;
  for(;;) {
    if (!QueryServiceStatus(service, &ssSvcStatus))
      return 0;

    if (--delay == 0 || 
        ssSvcStatus.dwCurrentState != SERVICE_START_PENDING &&
        ssSvcStatus.dwCurrentState != SERVICE_STOP_PENDING)
      return ssSvcStatus.dwCurrentState;
    Sleep(100);
    delay--;
  }
}


bool ServiceHandles::StartService() {
  DWORD state = GetNonTransientServiceStatus(service);
  if (state == 0 || state == SERVICE_RUNNING)
    return false; // service already running, no need to start
  if (!::StartService(service, 0, NULL)) {
//    if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
//      return false;
    return false;
  }
  return GetNonTransientServiceStatus(service) == SERVICE_RUNNING;
}


static bool StartTunsafeService() {
  ServiceHandles handles;

  if (!handles.Open(SERVICE_NAME, SC_MANAGER_CONNECT, SERVICE_START | SERVICE_QUERY_STATUS)) 
    return false;
  return handles.StartService();
}

bool IsTunsafeServiceRunning() {
  ServiceHandles handles;

  if (!handles.Open(SERVICE_NAME, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS))
    return false;

  return GetNonTransientServiceStatus(handles.service) == SERVICE_RUNNING;
}


void StopTunsafeService() {
  ServiceHandles handles;
  if (!handles.Open(SERVICE_NAME, SC_MANAGER_CONNECT,
                    SERVICE_STOP | SERVICE_QUERY_STATUS))
    goto Cleanup;
  handles.StopService();
Cleanup:
  return;
}

static void SetTunsafeUserNameInRegistry() {
  wchar_t *user = GetUsernameOfCurrentUser(false);
  if (!user) {
    RERROR("Unable to get current username");
    return;
  }
  HKEY hkey = NULL;
  RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\TunSafe", NULL, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey, NULL);
  if (!hkey) {
    RERROR("Unable to open registry key");
    return;
  }
  if (RegSetValueExW(hkey, L"AllowedUsername", NULL, REG_SZ, (BYTE*)user, (DWORD)(wcslen(user) + 1) * 2) != ERROR_SUCCESS) {
    RERROR("Unable to set registry key");
  }
  RegCloseKey(hkey);
}

void InstallTunSafeWindowsService() {
  InstallService(SERVICE_NAME, L"TunSafe Service", SERVICE_START_TYPE,
                 SERVICE_DEPENDENCIES, SERVICE_ACCOUNT, SERVICE_PASSWORD);
  StartTunsafeService();
  SetTunsafeUserNameInRegistry();
}

bool UninstallTunSafeWindowsService() {
  ServiceHandles handles;

  if (!handles.Open(SERVICE_NAME, SC_MANAGER_CONNECT,
                    SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE))
    goto Cleanup;

  handles.StopService();

  if (!DeleteService(handles.service))
    goto Cleanup;
  return true;
Cleanup:
  return false;
}

bool IsTunSafeServiceInstalled() {
  ServiceHandles handles;
  return handles.Open(SERVICE_NAME, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS);
}


static void WriteServiceLog(const char *pszFunction, WORD dwError) {
  char szMessage[260];
  snprintf(szMessage, ARRAYSIZE(szMessage), "%s failed w/err 0x%08lx", pszFunction, dwError);
  HANDLE hEventSource = NULL;
  LPCSTR lpszStrings[2] = {NULL, NULL};
  hEventSource = RegisterEventSourceW(NULL, SERVICE_NAME);
  if (hEventSource) {
    lpszStrings[0] = SERVICE_NAMEA;
    lpszStrings[1] = szMessage;

    ReportEventA(hEventSource,  // Event log handle
                dwError,                 // Event type
                0,                     // Event category
                0,                     // Event identifier
                NULL,                  // No security identifier
                2,                     // Size of lpszStrings array
                0,                     // No binary data
                lpszStrings,           // Array of strings
                NULL                   // No binary data
    );
    DeregisterEventSource(hEventSource);
  }
}

static void SetServiceStatus(DWORD dwCurrentState,
                             DWORD dwWin32ExitCode = 0,
                             DWORD dwWaitHint = 0) {
  static DWORD dwCheckPoint = 1;

  SERVICE_STATUS m_status;
  m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  m_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  m_status.dwServiceSpecificExitCode = 0;
  m_status.dwCurrentState = dwCurrentState;
  m_status.dwWin32ExitCode = dwWin32ExitCode;
  m_status.dwWaitHint = dwWaitHint;
  m_status.dwCheckPoint =
    ((dwCurrentState == SERVICE_RUNNING) ||
    (dwCurrentState == SERVICE_STOPPED)) ?
    0 : dwCheckPoint++;
  // Report the status of the service to the SCM.
  ::SetServiceStatus(m_statusHandle, &m_status);
}

static void OnServiceStart(DWORD dwArgc, PWSTR *pszArgv) {
  WriteServiceLog("Service Starting", EVENTLOG_INFORMATION_TYPE);
  SetServiceStatus(SERVICE_START_PENDING);
  DWORD rv = g_service->OnStart(dwArgc, pszArgv);
  if (rv) {
    SetServiceStatus(SERVICE_STOPPED, rv);
  } else {
    SetServiceStatus(SERVICE_RUNNING);
  }
}

static void OnServiceStop() {
  WriteServiceLog("Service Stopping", EVENTLOG_INFORMATION_TYPE);
  SetServiceStatus(SERVICE_STOP_PENDING);
  g_service->OnStop();
  SetServiceStatus(SERVICE_STOPPED);
}

static void OnServiceShutdown() {
  g_service->OnShutdown();
  SetServiceStatus(SERVICE_STOPPED);
}

static void WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
  switch (dwCtrl) {
  case SERVICE_CONTROL_STOP: OnServiceStop(); break;
//  case SERVICE_CONTROL_PAUSE: OnServicePause(); break;
//  case SERVICE_CONTROL_CONTINUE: OnServiceContinue(); break;
  case SERVICE_CONTROL_SHUTDOWN: OnServiceShutdown(); break;
  case SERVICE_CONTROL_INTERROGATE: break;
  default: break;
  }
}

static void WINAPI ServiceMain(DWORD dwArgc, PWSTR *pszArgv) {
  // Register the handler function for the service
  m_statusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
  if (m_statusHandle == NULL)
    throw GetLastError();
  // Start the service.
  OnServiceStart(dwArgc, pszArgv);
}

static const SERVICE_TABLE_ENTRYW serviceTable[] = {
  {SERVICE_NAME, ServiceMain},
  {NULL, NULL}
};

PipeMessageHandler::PipeMessageHandler(const char *pipe_name, bool is_server_pipe, Delegate *delegate) {
  pipe_name_ = _strdup(pipe_name);
  is_server_pipe_ = is_server_pipe;
  delegate_ = delegate;
  pipe_ = INVALID_HANDLE_VALUE;
  wait_handles_[0] = CreateEvent(NULL, TRUE, FALSE, NULL); // for ReadFile
  wait_handles_[1] = CreateEvent(NULL, FALSE, FALSE, NULL); // For Exit
  wait_handles_[2] = CreateEvent(NULL, TRUE, FALSE, NULL); // for WriteFile
  packets_ = NULL;
  thread_ = NULL;
  packets_end_ = &packets_;
  write_overlapped_active_ = false;
  exit_thread_ = false;
  connection_established_ = false;
  thread_id_ = 0;
  state_ = kStateNone;
  tmp_packet_buf_ = NULL;
}

PipeMessageHandler::~PipeMessageHandler() {
  StopThread();
  CloseHandle(wait_handles_[0]);
  CloseHandle(wait_handles_[1]);
  CloseHandle(wait_handles_[2]);
  free(pipe_name_);
}

bool PipeMessageHandler::InitializeServerPipeAndWait() {
  int BUFSIZE = 2048;
  SECURITY_ATTRIBUTES  saPipeSecurity = {0};
  uint8 buf[SECURITY_DESCRIPTOR_MIN_LENGTH];
  PSECURITY_DESCRIPTOR pPipeSD = (PSECURITY_DESCRIPTOR)buf;

  if (!InitializeSecurityDescriptor(pPipeSD, SECURITY_DESCRIPTOR_REVISION))
    return false;

  // set NULL DACL on the SD
  if (!SetSecurityDescriptorDacl(pPipeSD, TRUE, (PACL)NULL, FALSE))
    return false;

  // now set up the security attributes
  saPipeSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
  saPipeSecurity.bInheritHandle = TRUE;
  saPipeSecurity.lpSecurityDescriptor = pPipeSD;

  pipe_ = CreateNamedPipeW(L"\\\\.\\pipe\\TunSafe\\ServiceControl",
                                 PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                 PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS | PIPE_WAIT,
                                 PIPE_UNLIMITED_INSTANCES,
                                 BUFSIZE, BUFSIZE, 0, &saPipeSecurity);
  if (pipe_ == INVALID_HANDLE_VALUE)
    return false;
  
  memset(&read_overlapped_, 0, sizeof(read_overlapped_));
  read_overlapped_.hEvent = wait_handles_[0];
  if (!ConnectNamedPipe(pipe_, &read_overlapped_)) {
    DWORD rv = GetLastError();
    if (rv != ERROR_PIPE_CONNECTED && rv != ERROR_IO_PENDING)
      return false;
  }
  return true;
}

bool PipeMessageHandler::InitializeClientPipe() {
  assert(pipe_ == INVALID_HANDLE_VALUE);
  pipe_ = CreateFile(pipe_name_, GENERIC_READ | GENERIC_WRITE, 0, NULL, 
                     OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
  if (pipe_ == INVALID_HANDLE_VALUE)
    return false;
  DWORD mode = PIPE_READMODE_MESSAGE;
  SetNamedPipeHandleState(pipe_, &mode, NULL, NULL);
  return true;
}

void PipeMessageHandler::ClosePipe() {
  if (pipe_ != INVALID_HANDLE_VALUE) {
    CancelIo(pipe_);
    CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
  }
  connection_established_ = false;
  write_overlapped_active_ = false;

  free(tmp_packet_buf_);
  tmp_packet_buf_ = NULL;

  ResetEvent(wait_handles_[0]);
  ResetEvent(wait_handles_[2]);

  packets_mutex_.Acquire();
  OutgoingPacket *packets = packets_;
  packets_ = NULL;
  packets_end_ = &packets_;
  packets_mutex_.Release();
  while (packets) {
    OutgoingPacket *p = packets;
    packets = p->next;
    free(p);
  }
}

bool PipeMessageHandler::WritePacket(int type, const uint8 *data, size_t data_size) {
  OutgoingPacket *packet = (OutgoingPacket *)malloc(offsetof(OutgoingPacket, data[data_size + 1]));
  if (packet) {
    packet->size = (uint32)(data_size + 1);
    packet->data[0] = type;
    memcpy(packet->data + 1, data, data_size);
    packet->next = NULL;

    packets_mutex_.Acquire();
    OutgoingPacket *was_empty = packets_;
    // login messages are always queued up front
    if (type == SERVICE_REQ_LOGIN) {
      packet->next = packets_;
      if (packet->next == NULL)
        packets_end_ = &packet->next;
      packets_ = packet;
    } else {
      *packets_end_ = packet;
      packets_end_ = &packet->next;
    }
    packets_mutex_.Release();

    if (was_empty == NULL) {
      // Only allow the pipe thread to invoke the send
      if (GetCurrentThreadId() == thread_id_) {
        SendNextQueuedWrite();
      } else {
        SetEvent(wait_handles_[1]);
      }
    }
  }
  return true;
}

void PipeMessageHandler::SendNextQueuedWrite() {
  assert(thread_id_ == GetCurrentThreadId());
  if (!write_overlapped_active_) {
    OutgoingPacket *p = packets_;
    if (p && connection_established_) {
      memset(&write_overlapped_, 0, sizeof(write_overlapped_));
      write_overlapped_.hEvent = wait_handles_[2];
      if (WriteFile(pipe_, p->data, p->size, NULL, &write_overlapped_) || GetLastError() == ERROR_IO_PENDING)
        write_overlapped_active_ = true;
    } else {
      ResetEvent(wait_handles_[2]);
    }
  }
}

#define TS_WAIT_BEGIN(t) switch(state_) { case t:
#define TS_WAIT_POINT(t) state_ = (t); return; case t:
#define TS_WAIT_END() }

void PipeMessageHandler::AdvanceStateMachine() {
  DWORD rv, bytes_read;

  TS_WAIT_BEGIN(kStateNone)
  for(;;) {
    // Create a named pipe and wait for connections from the UI process
    if (is_server_pipe_) {
      if (!InitializeServerPipeAndWait()) {
        if (!exit_thread_)
          ExitProcess(1);
        break;
      }
      TS_WAIT_POINT(kStateWaitConnect);
    } else {
      if (!InitializeClientPipe()) {
        RINFO("Unable to connect to the TunSafe Service. Please make sure it's running.");
        break;
      }
    }
    connection_established_ = true;
    delegate_->HandleNewConnection();
    SendNextQueuedWrite();

    for (;;) {
      memset(&read_overlapped_, 0, sizeof(read_overlapped_));
      read_overlapped_.hEvent = wait_handles_[0];
      if (!ReadFile(pipe_, NULL, 0, NULL, &read_overlapped_)) {
        rv = GetLastError();
        if (rv != ERROR_IO_PENDING && rv != ERROR_MORE_DATA)
          break;
      }
      TS_WAIT_POINT(kStateWaitReadLength);
      PeekNamedPipe(pipe_, NULL, 0, NULL, &tmp_packet_size_, NULL);
      if (tmp_packet_size_ == 0)
        break;

      free(tmp_packet_buf_);
      tmp_packet_buf_ = (uint8*)malloc(tmp_packet_size_);
      if (!tmp_packet_buf_)
        break;

      memset(&read_overlapped_, 0, sizeof(read_overlapped_));
      read_overlapped_.hEvent = wait_handles_[0];
      if (!ReadFile(pipe_, tmp_packet_buf_, tmp_packet_size_, NULL, &read_overlapped_)) {
        rv = GetLastError();
        if (rv != ERROR_IO_PENDING)
          break;
      }
      TS_WAIT_POINT(kStateWaitReadPayload);
      bytes_read = (uint32)read_overlapped_.InternalHigh;
      if (bytes_read == 0)
        break;
      if (!delegate_->HandleMessage(tmp_packet_buf_[0], tmp_packet_buf_ + 1, bytes_read - 1)) {
        ResetEvent(wait_handles_[0]);
        TS_WAIT_POINT(kStateWaitTimeout);
        break;
      }
    }
    if (exit_thread_)
      break;
    delegate_->HandleDisconnect();
    if (!is_server_pipe_)
      break;
    ClosePipe();
  }  
  TS_WAIT_END()
  ClosePipe();
}

DWORD WINAPI PipeMessageHandler::StaticThreadMain(void *x) {
  return ((PipeMessageHandler*)x)->ThreadMain();
}

bool PipeMessageHandler::VerifyThread() {
  return thread_id_ == GetCurrentThreadId();
}

DWORD PipeMessageHandler::ThreadMain() {
  assert((thread_id_ = GetCurrentThreadId()) != 0);
  assert(state_ == kStateNone);

  AdvanceStateMachine();

  for(;;) {
    DWORD rv = WaitForMultipleObjects(3, wait_handles_, FALSE, (state_ == kStateWaitTimeout) ? 1000 : INFINITE);
    
    // packet write finished?
    if (rv == WAIT_OBJECT_0 + 2) {
      assert(write_overlapped_active_);

      write_overlapped_active_ = false;

      // Remove the packet from the front of the queue, now that it was sent.
      packets_mutex_.Acquire();
      OutgoingPacket *p = packets_;
      if ((packets_ = p->next) == NULL)
        packets_end_ = &packets_;
      packets_mutex_.Release();
      free(p);
      SendNextQueuedWrite();

    // notification
    } else if (rv == WAIT_OBJECT_0 + 1) {
      if (exit_thread_ || !delegate_->HandleNotify())
        break;
      // The notification event is set when there might be new messages to send,
      // so try to send them.
      SendNextQueuedWrite();
    
    // read finished?
    } else if (rv == WAIT_OBJECT_0) {
      AdvanceStateMachine();
    } else if (rv == WAIT_TIMEOUT) {
      if (state_ == kStateWaitTimeout)
        AdvanceStateMachine();
    } else {
      assert(0);
    }
  }
  return 0;
}

bool PipeMessageHandler::StartThread() {
  DWORD thread_id;
  assert(thread_ == NULL);
  thread_ = CreateThread(NULL, 0, &StaticThreadMain, this, 0, &thread_id);
  return thread_ != NULL;
}

void PipeMessageHandler::StopThread() {
  if (thread_ != NULL) {
    exit_thread_ = true;
    SetEvent(wait_handles_[1]);
    WaitForSingleObject(thread_, INFINITE);
    CloseHandle(thread_);
    thread_ = NULL;
  }
  ClosePipe();
}

TunsafeServiceImpl::TunsafeServiceImpl() 
    : message_handler_(PIPE_NAME, true, this) {
  thread_delegate_ = CreateTunsafeBackendDelegateThreaded(this, [=] {
    SetEvent(message_handler_.notify_handle());
  });

  backend_ = CreateNativeTunsafeBackend(thread_delegate_);
  historical_log_lines_count_ = historical_log_lines_pos_ = 0;
  last_line_sent_ = 0;
  did_send_getstate_ = false;
  memset(historical_log_lines_, 0, sizeof(historical_log_lines_));
  hkey_ = NULL;
  want_graph_type_ = 0xffffffff;
  RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\TunSafe", NULL, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey_, NULL);
}

TunsafeServiceImpl::~TunsafeServiceImpl() {
  RegCloseKey(hkey_);
}

static wchar_t *RegReadStrW(HKEY hkey, const wchar_t *key, const wchar_t *def) {
  wchar_t buf[1024];
  DWORD n = sizeof(buf) - 2;
  DWORD type = 0;
  if (RegQueryValueExW(hkey, key, NULL, &type, (BYTE*)buf, &n) != ERROR_SUCCESS || type != REG_SZ)
    return def ? _wcsdup(def) : NULL;
  n >>= 1;
  if (n && buf[n - 1] == 0)
    n--;
  buf[n] = 0;
  return _wcsdup(buf);
}

unsigned TunsafeServiceImpl::OnStart(int argc, wchar_t **argv) {
  uint32 service_flags = RegReadInt(hkey_, "ServiceStartupFlags", 0);
  if ( (service_flags & kStartupFlag_BackgroundService) && (service_flags & kStartupFlag_ConnectWhenWindowsStarts) ) {
    char *conf = RegReadStr(hkey_, "LastUsedConfigFile", "");
    if (conf && *conf) {
      current_filename_ = (char*)conf;
      backend_->Start((char*)conf);
    }
    free(conf);
  }

  message_handler_.StartThread();
  return 0;
}

bool TunsafeServiceImpl::AuthenticateUser() {
  did_authenticate_user_ = true;

  if (!ImpersonateNamedPipeClient(message_handler_.pipe_handle()))
    return false;
  wchar_t *user = GetUsernameOfCurrentUser(true);
  RevertToSelf();
  if (!user)
    return false;
  wchar_t *valid_user = RegReadStrW(hkey_, L"AllowedUsername", L"");
  bool rv = valid_user && wcscmp(user, valid_user) == 0;

  free(user);
  free(valid_user);
  return rv;
}

bool TunsafeServiceImpl::HandleMessage(int type, uint8 *data, size_t size) {
  if (!did_authenticate_user_) {
    if (type != SERVICE_REQ_LOGIN || size < 8 || *(uint64*)data != kTunsafeServiceProtocolVersion) {
      const char *s = "Versioning Problem: The TunSafe service is a different version than the UI.";
      message_handler_.WritePacket(SERVICE_MSG_LOGLINE, (uint8*)s, strlen(s));
      return false;
    }
    if (!AuthenticateUser()) {
      const char *s = "Permission Problem: Your Windows account is different from the account\r\nthat installed the TunSafe Service. Please reinstall it.\r\n";
      message_handler_.WritePacket(SERVICE_MSG_LOGLINE, (uint8*)s, strlen(s));
      return false;
    }
  }
  
  switch (type) {
  case SERVICE_REQ_START:
    if (data[size - 1] != 0)
      return false;

    // Don't allow reading arbitrary files on disk
    if (!EnsureValidConfigPath((char*)data)) {
      char buf[MAX_PATH];
      GetConfigPath(buf, sizeof(buf));
      char *s = str_cat_alloc("Permission Problem: The Config file is in an unsafe location.\r\n   Must be in:", buf, "\r\n");
      message_handler_.WritePacket(SERVICE_MSG_LOGLINE, (uint8*)s, strlen(s));
      free(s);
      return false;
    }

    g_allow_pre_post = RegReadInt(hkey_, "AllowPrePost", 0) != 0;

    current_filename_ = (char*)data;
    backend_->Start((char*)data);
    RegWriteStr(hkey_, "LastUsedConfigFile", (char*)data);

    break;

  case SERVICE_REQ_STOP:
    backend_->Stop();
    RegWriteStr(hkey_, "LastUsedConfigFile", "");
    OnStateChanged();
    break;

  case SERVICE_REQ_LOGIN:
    did_send_getstate_ = true;
    OnStatusCode(backend_->status());
    OnStateChanged();
    SendQueuedLogLines();
    break;

  case SERVICE_REQ_GETSTATS:
    if (size < 1) return false;
    backend_->RequestStats(data[0] != 0);
    break;

  case SERVICE_REQ_SET_INTERNET_BLOCKSTATE:
    if (size < 1)
      return false;
    backend_->SetInternetBlockState((InternetBlockState)data[0]);
    OnStateChanged();
    break;

  case SERVICE_REQ_RESETSTATS:
    backend_->ResetStats();
    break;

  case SERVICE_REQ_GET_GRAPH:
    if (size < 4) return false;
    want_graph_type_ = *(int*)data;
    TunsafeServiceImpl::OnGraphAvailable();
    break;

  case SERVICE_REQ_SET_STARTUP_FLAGS:
    if (size < 4)
      return false;
    RegSetValueEx(hkey_, "ServiceStartupFlags", NULL, REG_DWORD, (BYTE*)data, 4);
    break;
    
  default:
    return false;
  }
  return true;
}

bool TunsafeServiceImpl::HandleNotify() {
  thread_delegate_->DoWork();
  return true;
}

void TunsafeServiceImpl::HandleNewConnection() {
  did_send_getstate_ = false;
  did_authenticate_user_ = false;
  last_line_sent_ = 0;
}

void TunsafeServiceImpl::HandleDisconnect() {
  want_graph_type_ = 0xffffffff;
  backend_->RequestStats(false);
  uint32 service_flags = RegReadInt(hkey_, "ServiceStartupFlags", 0);
  if (!(service_flags & kStartupFlag_BackgroundService))
    backend_->Stop();
}

void TunsafeServiceImpl::OnGraphAvailable() {
  if (want_graph_type_ != 0xffffffff) {
    LinearizedGraph *graph = backend_->GetGraph(want_graph_type_);
    if (graph)
      message_handler_.WritePacket(SERVICE_MSG_GRAPH, (uint8*)graph, graph->total_size);
  }
}

void TunsafeServiceImpl::SendQueuedLogLines() {
  assert(message_handler_.VerifyThread());
  uint32 maxi = std::min<uint32>(historical_log_lines_count_, historical_log_lines_pos_ - last_line_sent_);
  last_line_sent_ = historical_log_lines_pos_;
  for (uint32 i = 0; i < maxi; i++) {
    const char *s = historical_log_lines_[(historical_log_lines_pos_ - maxi + i) & (LOGLINE_COUNT - 1)];
    if (s)
      message_handler_.WritePacket(SERVICE_MSG_LOGLINE, (uint8*)s, strlen(s));
  }
}

void TunsafeServiceImpl::OnClearLog() {
  historical_log_lines_pos_ = 0;
  historical_log_lines_count_ = 0;
  message_handler_.WritePacket(SERVICE_MSG_CLEARLOG, NULL, 0);
}

void TunsafeServiceImpl::OnLogLine(const char **s) {
  assert(message_handler_.VerifyThread());
  char *ss = (char*)*s;
  *s = NULL;
  char *&x = historical_log_lines_[historical_log_lines_pos_++ & (LOGLINE_COUNT - 1)];
  std::swap(x, ss);
  if (historical_log_lines_count_ < LOGLINE_COUNT)
    historical_log_lines_count_++;
  free(ss);
  if (did_send_getstate_)
    SendQueuedLogLines();
}

void TunsafeServiceImpl::OnGetStats(const WgProcessorStats &stats) {
  message_handler_.WritePacket(SERVICE_MSG_STATS, (uint8*)&stats, sizeof(stats));
}

void TunsafeServiceImpl::OnStateChanged() {
  uint8 *temp = new uint8[current_filename_.size() + 1 + sizeof(ServiceState)];
  bool is_activated;

  memset(temp, 0, sizeof(ServiceState));

  ServiceState *ss = (ServiceState *)temp;
  ss->is_started = backend_->is_started();
  ss->internet_block_state = backend_->GetInternetBlockState(&is_activated);
  ss->internet_block_state_active = is_activated;
  ss->ipv4_ip = backend_->GetIP();
  memcpy(ss->public_key, backend_->public_key(), 32);

  memcpy(temp + sizeof(ServiceState), current_filename_.c_str(), current_filename_.size() + 1);
  message_handler_.WritePacket(SERVICE_MSG_STATE, temp, current_filename_.size() + 1 + sizeof(ServiceState));
  delete[] temp;
}

void TunsafeServiceImpl::OnStatusCode(TunsafeBackend::StatusCode status) {
  if (status == TunsafeBackend::kStatusConnected)
    OnStateChanged(); // ensure we know the ip first
  uint32 v32 = (uint32)status;
  message_handler_.WritePacket(SERVICE_MSG_STATUS_CODE, (uint8*)&v32, 4);
}

void TunsafeServiceImpl::OnStop() {
  message_handler_.StopThread();
  backend_->Stop();
}

void TunsafeServiceImpl::OnShutdown() {

}

static void PushServiceLine(const char *s) {
  if (g_service) {
    char buf[64];
    SYSTEMTIME t;

    size_t l = strlen(s);
    GetLocalTime(&t);
    snprintf(buf, sizeof(buf), "[%.2d:%.2d:%.2d] ", t.wHour, t.wMinute, t.wSecond);
    size_t tl = strlen(buf);

    char *x = (char*) malloc(tl + l + 3);
    memcpy(x, buf, tl);
    memcpy(x + tl, s, l);
    x[l + tl] = '\r';
    x[l + tl + 1] = '\n';
    x[l + tl + 2] = '\0';
    g_service->delegate()->OnLogLine((const char**)&x);
    free(x);
  } else {
    size_t l = strlen(s);
    char buf[1024];
    SYSTEMTIME t;
    GetLocalTime(&t);

    snprintf(buf, sizeof(buf), "[%.2d:%.2d:%.2d] ", t.wHour, t.wMinute, t.wSecond);
    size_t tl = strlen(buf);

    if (l >= ARRAYSIZE(buf) - tl - 1)
      l = ARRAYSIZE(buf) - tl - 1;

    memcpy(buf + tl, s, l);
    buf[l + tl] = '\0';

    WriteServiceLog(buf, EVENTLOG_INFORMATION_TYPE);
  }
}

BOOL RunProcessAsTunsafeServiceProcess() {
  g_service = new TunsafeServiceImpl;
  g_logger = &PushServiceLine;
  
  //g_service->OnStart(NULL, 0);

  //MessageBoxA(0, "Service running", "Service running", 0);
  //return TRUE;
//  while (true)Sleep(1000);

  // Connects the main thread of a service process to the service control 
  // manager, which causes the thread to be the service control dispatcher 
  // thread for the calling process. This call returns when the service has 
  // stopped. The process should simply terminate when the call returns.
  return StartServiceCtrlDispatcherW(serviceTable);
}
TunsafeServiceClient::TunsafeServiceClient(TunsafeBackend::Delegate *delegate) 
    : message_handler_(PIPE_NAME, false, this) {
  is_remote_ = true;
  got_state_from_control_ = false;
  delegate_ = delegate;
  cached_graph_ = 0;
  last_graph_type_ = 0xffffffff;
  memset(&service_state_, 0, sizeof(service_state_));
}

TunsafeServiceClient::~TunsafeServiceClient() {
  message_handler_.StopThread();
}

bool TunsafeServiceClient::Initialize() {
  // Wait for the service to start
  last_graph_type_ = 0xffffffff;
  return message_handler_.StartThread();
}

void TunsafeServiceClient::Start(const char *config_file) {
  message_handler_.WritePacket(SERVICE_REQ_START, (uint8*)config_file, strlen(config_file) + 1);
}

void TunsafeServiceClient::Stop() {
  message_handler_.WritePacket(SERVICE_REQ_STOP, NULL, 0);
}

void TunsafeServiceClient::RequestStats(bool enable) {
  want_stats_ = enable;
  if (message_handler_.is_connected())
    message_handler_.WritePacket(SERVICE_REQ_GETSTATS, &want_stats_, 1);
}

void TunsafeServiceClient::ResetStats() {
  message_handler_.WritePacket(SERVICE_REQ_RESETSTATS, NULL, 0);
}

InternetBlockState TunsafeServiceClient::GetInternetBlockState(bool *is_activated) {
  if (is_activated)
    *is_activated = service_state_.internet_block_state_active;
  return (InternetBlockState)service_state_.internet_block_state;
}

void TunsafeServiceClient::SetInternetBlockState(InternetBlockState s) {
  uint8 v = (uint8)s;
  message_handler_.WritePacket(SERVICE_REQ_SET_INTERNET_BLOCKSTATE, &v, 1);
}

void TunsafeServiceClient::SetServiceStartupFlags(uint32 flags) {
  message_handler_.WritePacket(SERVICE_REQ_SET_STARTUP_FLAGS, (uint8*)&flags, 4);
}

LinearizedGraph *TunsafeServiceClient::GetGraph(int type) {
  if (type != last_graph_type_) {
    last_graph_type_ = type;
    message_handler_.WritePacket(SERVICE_REQ_GET_GRAPH, (uint8*)&type, 4);
  }
  mutex_.Acquire();
  LinearizedGraph *graph = cached_graph_;
  LinearizedGraph *new_graph = (graph && graph->graph_type == type) ? (LinearizedGraph*)memdup(graph, graph->total_size) : NULL;
  mutex_.Release();
  return new_graph;
}


std::string TunsafeServiceClient::GetConfigFileName() {
  mutex_.Acquire();
  std::string rv = config_file_;
  mutex_.Release();
  return rv;
}

bool TunsafeServiceClient::HandleMessage(int type, uint8 *data, size_t data_size) {
  switch(type) {
  case SERVICE_MSG_STATE:
    if (data_size <= sizeof(service_state_) || data[data_size - 1])
      return false;
    got_state_from_control_ = true;

    mutex_.Acquire();
    config_file_.assign((char*)data + sizeof(service_state_), data_size - 1 - sizeof(service_state_));
    memcpy(&service_state_, data, sizeof(service_state_));
    memcpy(public_key_, service_state_.public_key, 32);
    is_started_ = service_state_.is_started;
    ipv4_ip_ = service_state_.ipv4_ip;
    mutex_.Release();
    delegate_->OnStateChanged();
    return true;
  case SERVICE_MSG_LOGLINE: {
    if (data_size == 0)
      return false;
    char *s = my_strndup((char*)data, data_size);
    delegate_->OnLogLine((const char **)&s);
    free(s);
    return true;
  }
  case SERVICE_MSG_STATS: {
    WgProcessorStats stats;
    if (data_size != sizeof(WgProcessorStats))
      return false;
    memcpy(&stats, data, sizeof(WgProcessorStats));
    delegate_->OnGetStats(stats);
    return true;
  }
  case SERVICE_MSG_CLEARLOG:
    delegate_->OnClearLog();
    return true;

  case SERVICE_MSG_STATUS_CODE:
    if (data_size < 4)
      return false;
    status_ = (StatusCode)*(uint32*)data;
    delegate_->OnStatusCode(status_);
    return true;

  case SERVICE_MSG_GRAPH:
    if (data_size < 4 || data_size != *(uint32*)data)
      return false;

    LinearizedGraph *graph = (LinearizedGraph*)memdup(data, data_size);
    mutex_.Acquire();
    std::swap(graph, cached_graph_);
    mutex_.Release(); 
    free(graph);
    delegate_->OnGraphAvailable();
    return true;
  }

  return false;
}

bool TunsafeServiceClient::HandleNotify() {
  return true;
}


void TunsafeServiceClient::HandleNewConnection() {
  message_handler_.WritePacket(SERVICE_REQ_LOGIN, (uint8*)&kTunsafeServiceProtocolVersion, 8);
  if (want_stats_)
    message_handler_.WritePacket(SERVICE_REQ_GETSTATS, &want_stats_, 1);
}

void TunsafeServiceClient::HandleDisconnect() {
  status_ = TunsafeBackend::kErrorServiceLost;
  delegate_->OnStatusCode(TunsafeBackend::kErrorServiceLost);
}

void TunsafeServiceClient::Teardown() {
  message_handler_.StopThread();
}

TunsafeBackend *CreateTunsafeServiceClient(TunsafeBackend::Delegate *delegate) {
  TunsafeServiceClient *client = new TunsafeServiceClient(delegate);
  if (client && !client->Initialize()) {
    delete client;
    client = NULL;
  }
  return client;
}


