// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "network_win32.h"
#include "wireguard_config.h"
#include "netapi.h"
#include <Iphlpapi.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <Iphlpapi.h>
#include <ws2ipdef.h>
#include <assert.h>
#include <exdisp.h>
#include "tunsafe_endian.h"
#include "wireguard.h"
#include "util.h"
#include <algorithm>
#include "network_win32_dnsblock.h"

enum {
  HARD_MAXIMUM_QUEUE_SIZE = 102400,
  MAX_BYTES_IN_UDP_OUT_QUEUE = 256 * 1024,
  MAX_BYTES_IN_UDP_OUT_QUEUE_SMALL = (256 + 64) * 1024,
};

enum {
  ROUTE_BLOCK_UNKNOWN = 0,
  ROUTE_BLOCK_OFF = 1,
  ROUTE_BLOCK_ON = 2,
  ROUTE_BLOCK_PENDING = 3,
};
static uint8 internet_route_blocking_state;
static SLIST_HEADER freelist_head;

bool g_allow_pre_post;

static InternetBlockState GetInternetBlockState(bool *is_activated);

Packet *AllocPacket() {
  Packet *packet = (Packet*)InterlockedPopEntrySList(&freelist_head);
  if (packet == NULL)
    packet = (Packet *)_aligned_malloc(kPacketAllocSize, 16);
  packet->data = packet->data_buf + Packet::HEADROOM_BEFORE;
  packet->size = 0;
  return packet;
}

void FreePacket(Packet *packet) {
  InterlockedPushEntrySList(&freelist_head, &packet->list_entry);
}

void OsGetRandomBytes(uint8 *data, size_t data_size) {
  static BOOLEAN(APIENTRY *pfn)(void*, ULONG);
  static bool resolved;
  if (!resolved) {
    pfn = (BOOLEAN(APIENTRY *)(void*, ULONG))GetProcAddress(LoadLibrary("ADVAPI32.DLL"), "SystemFunction036");
    resolved = true;
  }
  if (pfn && pfn(data, (ULONG)data_size))
    return;
  size_t r = 0;
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

extern "C"
PSLIST_ENTRY __fastcall InterlockedPushListSList(
  IN PSLIST_HEADER ListHead,
  IN PSLIST_ENTRY List,
  IN PSLIST_ENTRY ListEnd,
  IN ULONG Count
);

void FreePackets(Packet *packet, Packet **end, int count) {
  InterlockedPushListSList(&freelist_head, &packet->list_entry, (PSLIST_ENTRY)end, count);
}

void FreeAllPackets() {
  Packet *p;
  p = (Packet*)InterlockedFlushSList(&freelist_head);
  while (Packet *r = p) {
    p = p->next;
    _aligned_free(r);
  }
}

void InitPacketMutexes() {
  static bool mutex_inited;
  if (!mutex_inited) {
    mutex_inited = true;
    InitializeSListHead(&freelist_head);
  }
}

int tpq_last_qsize;
int g_tun_reads, g_tun_writes;

struct {
  uint32 pad1[3];
  uint32 udp_qsize1;
  uint32 pad2[3];
  uint32 udp_qsize2;
} qs;


#define kConcurrentReadUdp 16
#define kConcurrentWriteUdp 16
#define kConcurrentReadTap 16
#define kConcurrentWriteTap 16

#define kAdapterKeyName "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define kTapComponentId "tap0901"

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE(4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE(7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE(8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE(9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE(10, METHOD_BUFFERED)

static bool RunNetsh(const char *cmdline) {
  wchar_t path[MAX_PATH + 20];
  size_t size = GetSystemDirectoryW(path, MAX_PATH);
  bool result = false;
  if (!size) {
    RERROR("GetSystemDirectory failed");
    return false;
  }
  memcpy(path + size, L"\\netsh.exe", 11 * sizeof(path[0]));

  size_t cmdline_size = strlen(cmdline);
  wchar_t *cmdlinew = new wchar_t[cmdline_size + 1];
  for (size_t i = 0; i <= cmdline_size; i++)
    cmdlinew[i] = cmdline[i];

  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};

  GetStartupInfoW(&si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
   if (CreateProcessW(path, cmdlinew, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    DWORD exit_code = -1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code != 0)
      RERROR("Netsh failed (%d) : %s", exit_code, cmdline);
    else {
      RINFO("Run: %s", cmdline);
      result = true;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    RERROR("CreateProcess failed: %s", cmdline);
  }
  delete[]cmdlinew;
  return result;
}

// Retrieve the device path to the TAP adapter.
static bool GetTapAdapterGuid(char guid[64]) {
  LONG err;
  HKEY adapter_key, device_key;
  bool retval = false;
  err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, kAdapterKeyName, 0, KEY_READ, &adapter_key);
  if (err != ERROR_SUCCESS) {
    RERROR("GetTapAdapterName: RegOpenKeyEx failed: 0x%X", GetLastError());
    return false;
  }
  for (int i = 0; !retval; i++) {
    char keyname[64 + sizeof(kAdapterKeyName) + 1];
    char value[64];
    DWORD len = sizeof(value), type;
    err = RegEnumKeyEx(adapter_key, i, value, &len, NULL, NULL, NULL, NULL);
    if (err == ERROR_NO_MORE_ITEMS)
      break;
    if (err != ERROR_SUCCESS) {
      RERROR("GetTapAdapterName: RegEnumKeyEx failed: 0x%X", GetLastError());
      return false;
    }
    snprintf(keyname, sizeof(keyname), "%s\\%s", kAdapterKeyName, value);
    err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, KEY_READ, &device_key);
    if (err == ERROR_SUCCESS) {
      len = sizeof(value);
      err = RegQueryValueEx(device_key, "ComponentId", NULL, &type, (LPBYTE)value, &len);
      if (err == ERROR_SUCCESS && type == REG_SZ && !memcmp(value, kTapComponentId, sizeof(kTapComponentId))) {
        len = 64;
        err = RegQueryValueEx(device_key, "NetCfgInstanceId", NULL, &type, (LPBYTE)guid, &len);
        if (err == ERROR_SUCCESS && type == REG_SZ) {
          guid[63] = 0;
          retval = true;
        }
      }
      RegCloseKey(device_key);
    }
  }
  RegCloseKey(adapter_key);
  return retval;
}

// Open the TAP adapter
static HANDLE OpenTunAdapter(char guid[64], int retry_count, uint32 *exit_thread, DWORD open_flags) {
  char path[128];
  HANDLE h;
  int retries = 0;
  if (!GetTapAdapterGuid(guid)) {
    RERROR("Unable to find ID of TAP adapter");
    RERROR("  Please ensure that TunSafe-TAP is properly installed.");
    return NULL;
  }
  snprintf(path, sizeof(path), "\\\\.\\Global\\%s.tap", guid);
RETRY:
  h = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
                 FILE_ATTRIBUTE_SYSTEM | open_flags, 0);
  if (h == INVALID_HANDLE_VALUE) {
    int error_code = GetLastError();
    
    // Sometimes if you close the device right before, it will fail to open with errorcode 31.
    // When resuming from sleep in my VM, the error code is ERROR_FILE_NOT_FOUND
    if ((error_code == ERROR_FILE_NOT_FOUND || error_code == ERROR_GEN_FAILURE) && retry_count != 0 && !*exit_thread) {
      RERROR("OpenTapAdapter: CreateFile failed: 0x%X... retrying", error_code);
      retry_count--;

      int sleep_amount = 250 * ++retries;
      for(;;) {
        if (*exit_thread)
          return NULL;
        if (sleep_amount == 0)
          break;
        Sleep(50);
        sleep_amount -= 50;
      }
      goto RETRY;
    }
    
    RERROR("OpenTapAdapter: CreateFile failed: 0x%X", error_code);
    if (error_code == ERROR_FILE_NOT_FOUND) {
      RERROR("  Please ensure that TunSafe-TAP is properly installed.");
    } else if (error_code == 0x1f) {
      RERROR("  Please ensure that the TAP device is not in use.");
    }
    return NULL;
  }
  return h;
}

static bool AddRoute(int family,
                     const void *dest, int dest_prefix,
                     const void *gateway, const NET_LUID *interface_luid,
                     std::vector<MIB_IPFORWARD_ROW2> *undo_array) {
  MIB_IPFORWARD_ROW2 row = {0};
  char buf1[kSizeOfAddress], buf2[kSizeOfAddress];

  row.InterfaceLuid = *interface_luid;
  row.DestinationPrefix.PrefixLength = dest_prefix;
  row.DestinationPrefix.Prefix.si_family = family;
  row.NextHop.si_family = family;
  if (family == AF_INET) {
    memcpy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr, dest, 4);
    memcpy(&row.NextHop.Ipv4.sin_addr, gateway, 4);
  } else if (family == AF_INET6) {
    memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, dest, 16);
    memcpy(&row.NextHop.Ipv6.sin6_addr, gateway, 16);
  } else {
    return false;
  }
  row.ValidLifetime = 0xffffffff;
  row.PreferredLifetime = 0xffffffff;
  row.Metric = 100;
  row.Protocol = MIB_IPPROTO_NETMGMT;

  DWORD error = CreateIpForwardEntry2(&row);
  if (error == NO_ERROR || error == ERROR_OBJECT_ALREADY_EXISTS) {

    if (undo_array)
      undo_array->push_back(row);

    RINFO("Added Route %s  =>  %s", print_ip_prefix(buf1, family, dest, dest_prefix),
          print_ip_prefix(buf2, family, gateway, -1));
    return true;
  }
  RINFO("AddRoute failed (%d) %s  =>  %s", error, print_ip_prefix(buf1, family, dest, dest_prefix),
        print_ip_prefix(buf2, family, gateway, -1));
  return false;
}

static bool DeleteRoute(MIB_IPFORWARD_ROW2 *row) {
  char buf1[kSizeOfAddress], buf2[kSizeOfAddress];
  DWORD error = DeleteIpForwardEntry2(row);
  
  print_ip_prefix(buf1, row->DestinationPrefix.Prefix.si_family,
    (row->DestinationPrefix.Prefix.si_family == AF_INET) ? (uint8*) &row->DestinationPrefix.Prefix.Ipv4.sin_addr : (uint8*) &row->DestinationPrefix.Prefix.Ipv6.sin6_addr, row->DestinationPrefix.PrefixLength);

  print_ip_prefix(buf2, row->NextHop.si_family,
    (row->NextHop.si_family == AF_INET) ? (uint8*)&row->NextHop.Ipv4.sin_addr : (uint8*)&row->NextHop.Ipv6.sin6_addr, -1);

  if (error == NO_ERROR) {
    RINFO("Deleted Route %s  =>  %s", buf1, buf2);
    return true;
  }
  RINFO("DeleteRoute failed (%d) %s  =>  %s", error, buf1, buf2);
  return false;
}


static uint32 CidrToNetmaskV4(int cidr) {
  return cidr == 32 ? 0xffffffff : 0xffffffff << (32 - cidr);
}

struct RouteInfo {
  uint8 default_gw[16];
  NET_LUID default_adapter;
  bool found_default_adapter;
  uint8 found_null_routes;
};

static inline bool IsRouteOriginatingFromNullRoute(MIB_IPFORWARD_ROW2 *row) {
  if (!(row->InterfaceLuid.Info.IfType == 24 && row->Protocol == MIB_IPPROTO_NETMGMT && row->DestinationPrefix.PrefixLength == 1))
    return false;
  if (row->NextHop.si_family == AF_INET) {
    return (row->NextHop.Ipv4.sin_addr.S_un.S_addr == 0);
  } else if (row->NextHop.si_family == AF_INET6) {
    static const uint32 nulladdr[4];
    return memcmp(&row->NextHop.Ipv6.sin6_addr, nulladdr, 16) == 0;
  }
  return false;
}

static inline bool IsRouteTheAddressOfTheServer(int family, MIB_IPFORWARD_ROW2 *row, uint8 *old_endpoint_to_delete) {
  if (!(row->Protocol == MIB_IPPROTO_NETMGMT && row->DestinationPrefix.Prefix.si_family == family))
    return false;
  if (family == AF_INET) {
    return (row->DestinationPrefix.PrefixLength == 32 && memcmp(&row->DestinationPrefix.Prefix.Ipv4.sin_addr, old_endpoint_to_delete, 4) == 0);
  } else if (family == AF_INET6) {
    return (row->DestinationPrefix.PrefixLength == 128 && memcmp(&row->DestinationPrefix.Prefix.Ipv6.sin6_addr, old_endpoint_to_delete, 16) == 0);
  }
  return false;
}

static void DeleteRouteOrPrintErr(MIB_IPFORWARD_ROW2 *row) {
  char buf1[kSizeOfAddress];
  UINT32 r = DeleteIpForwardEntry2(row);
  if (r)
    RERROR("Unable to delete old route (%d): %s", r,
           print_ip_prefix(buf1, row->DestinationPrefix.Prefix.si_family, row->DestinationPrefix.Prefix.si_family == AF_INET ?
              (void*)&row->DestinationPrefix.Prefix.Ipv4.sin_addr :
              (void*)&row->DestinationPrefix.Prefix.Ipv6.sin6_addr, row->DestinationPrefix.PrefixLength));
}

static bool GetDefaultRouteAndDeleteOldRoutes(int family, const NET_LUID *InterfaceLuid, bool keep_null_routes, uint8 *old_endpoint_to_delete, RouteInfo *ri) {
  MIB_IPFORWARD_TABLE2 *table = NULL;

  assert(family == AF_INET || family == AF_INET6);

  if (GetIpForwardTable2(family, &table))
    return false;
  DWORD rv = 0;
  DWORD gw_metric = 0xffffffff;
  ri->found_default_adapter = false;
  ri->found_null_routes = 0;
  for (unsigned i = 0; i < table->NumEntries; i++) {
    MIB_IPFORWARD_ROW2 *row = &table->Table[i];
    if (InterfaceLuid && memcmp(&row->InterfaceLuid, InterfaceLuid, sizeof(NET_LUID)) == 0) {
      if (row->Protocol == MIB_IPPROTO_NETMGMT && !row->AutoconfigureAddress)
        DeleteRouteOrPrintErr(row);
    } else if (IsRouteOriginatingFromNullRoute(row)) {
      ri->found_null_routes++;
      if (!keep_null_routes)
        DeleteRouteOrPrintErr(row);
    } else if (row->DestinationPrefix.PrefixLength == 0 && row->Metric < gw_metric) {
      gw_metric = row->Metric;
      if (family == AF_INET) {
        memcpy(&ri->default_gw, &row->NextHop.Ipv4.sin_addr, 4);
      } else {
        memcpy(&ri->default_gw, &row->NextHop.Ipv6.sin6_addr, 16);
      }
      ri->default_adapter = row->InterfaceLuid;
      ri->found_default_adapter = true;
    }
  }

  if (old_endpoint_to_delete && ri->found_default_adapter) {
    for (unsigned i = 0; i < table->NumEntries; i++) {
      MIB_IPFORWARD_ROW2 *row = &table->Table[i];
      if (memcmp(&row->InterfaceLuid, &ri->default_adapter, sizeof(NET_LUID)) == 0) {
        if (IsRouteTheAddressOfTheServer(family, row, old_endpoint_to_delete))
          DeleteRouteOrPrintErr(row);
      }
    }
  }

  FreeMibTable(table);
  return (rv == 0);
}

static inline bool NoMoreAllocationRetry(volatile bool *exit_flag) {
  if (*exit_flag)
    return true;
  Sleep(1000);
  return *exit_flag;
}

static inline bool AllocPacketFrom(Packet **list, int *counter, bool *exit_flag, Packet **res) {
   Packet *p;
   if (p = *list) {
     *list = p->next;
     (*counter)--;
     p->data = p->data_buf + Packet::HEADROOM_BEFORE;
   } else {
     while ((p = AllocPacket()) == NULL) {
      if (NoMoreAllocationRetry(exit_flag))
        return false;
    }
   }
  *res = p;
  return true;
}

static void FreePacketList(Packet *pp) {
  while (Packet *p = pp) {
    pp = p->next;
    FreePacket(p);
  }
}

UdpSocketWin32::UdpSocketWin32() {
  wqueue_end_ = &wqueue_;
  wqueue_ = NULL;
  exit_thread_ = false;
  socket_ = INVALID_SOCKET;
  thread_ = NULL;
  socket_ipv6_ = INVALID_SOCKET;
  completion_port_handle_ = NULL;
}

UdpSocketWin32::~UdpSocketWin32() {
  assert(thread_ == NULL);
  closesocket(socket_);
  closesocket(socket_ipv6_);
  CloseHandle(completion_port_handle_);
  FreePacketList(wqueue_);
}

bool UdpSocketWin32::Initialize(int listen_on_port) {
  SOCKET s = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
  if (s == INVALID_SOCKET) {
    RERROR("UdpSocketWin32::Initialize WSASocket failed");
    return false;
  }
  completion_port_handle_ = CreateIoCompletionPort((HANDLE)s, NULL, NULL, 0);
  if (!completion_port_handle_) {
    closesocket(s);
    return false;
  }
  socket_ = s;

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(listen_on_port);
  if (bind(s, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
    RERROR("UdpSocketWin32::Initialize bind failed");
    return false;
  }

  // Also open up a socket for ipv6
  s = WSASocket(AF_INET6, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
  if (s != INVALID_SOCKET) {
    if (!CreateIoCompletionPort((HANDLE)s, completion_port_handle_, 1, 0)) {
      RERROR("IPv6 Socket completion port failed.");
      closesocket(s);
    } else {
      socket_ipv6_ = s;
      sockaddr_in6 sin6 = {0};
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons(listen_on_port);
      if (bind(s, (struct sockaddr*)&sin6, sizeof(sin6)) != 0) {
        RERROR("UdpSocketWin32::Initialize bind failed IPv6");
      }
    }
  } else {
    RERROR("IPv6 Socket creation failed.");
  }
  return true;
}

enum {
  kUdpGetQueuedCompletionStatusSize = kConcurrentWriteTap + kConcurrentReadTap + 1
};

static inline void ClearOverlapped(OVERLAPPED *o) {
  memset(o, 0, sizeof(*o));
}

#ifndef STATUS_PORT_UNREACHABLE
#define STATUS_PORT_UNREACHABLE 0xC000023F
#endif

static inline bool IsIgnoredUdpError(DWORD err) {
  return err == WSAEMSGSIZE || err == WSAECONNRESET || err == WSAENETRESET || err == STATUS_PORT_UNREACHABLE;
}

void UdpSocketWin32::ThreadMain() {
  OVERLAPPED_ENTRY entries[kUdpGetQueuedCompletionStatusSize];
  Packet *pending_writes = NULL;
  int num_reads[2] = {0,0}, num_writes = 0;
  enum { IPV4, IPV6 };
  Packet *finished_reads = NULL, **finished_reads_end = &finished_reads;
  Packet *freed_packets = NULL, **freed_packets_end = &freed_packets;
  int freed_packets_count = 0;
  int max_read_ipv6 = socket_ipv6_ != INVALID_SOCKET ? 1 : 0;

  while (!exit_thread_) {
    // Listen with multiple ipv6 packets only if we ever sent an ipv6 packet.
    for (int i = num_reads[IPV6]; i < max_read_ipv6; i++) {
      Packet *p;
      if (!AllocPacketFrom(&freed_packets, &freed_packets_count, &exit_thread_, &p))
        break;
restart_read_udp6:
      ClearOverlapped(&p->overlapped);
      p->post_target = ThreadedPacketQueue::TARGET_PROCESSOR_UDP;
      WSABUF wsabuf = {(ULONG)kPacketCapacity, (char*)p->data};
      DWORD flags = 0;
      p->sin_size = sizeof(p->addr.sin6);
      if (WSARecvFrom(socket_ipv6_, &wsabuf, 1, NULL, &flags, (struct sockaddr*)&p->addr, &p->sin_size, &p->overlapped, NULL) != 0) {
        DWORD err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
          if (err == WSAEMSGSIZE || err == WSAECONNRESET || err == WSAENETRESET)
            goto restart_read_udp6;
          RERROR("UdpSocketWin32:WSARecvFrom failed 0x%X", err);
          FreePacket(p);
          break;
        }
      }
      num_reads[IPV6]++;
    }

    // Initiate more reads, reusing the Packet structures in |finished_writes|.
    for (int i = num_reads[IPV4]; i < kConcurrentReadTap; i++) {
      Packet *p;
      if (!AllocPacketFrom(&freed_packets, &freed_packets_count, &exit_thread_, &p))
        break;
restart_read_udp:
      ClearOverlapped(&p->overlapped);
      p->post_target = ThreadedPacketQueue::TARGET_PROCESSOR_UDP;
      WSABUF wsabuf = {(ULONG)kPacketCapacity, (char*)p->data};
      DWORD flags = 0;
      p->sin_size = sizeof(p->addr.sin);
      if (WSARecvFrom(socket_, &wsabuf, 1, NULL, &flags, (struct sockaddr*)&p->addr, &p->sin_size, &p->overlapped, NULL) != 0) {
        DWORD err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
          if (err == WSAEMSGSIZE || err == WSAECONNRESET || err == WSAENETRESET)
            goto restart_read_udp;
          RERROR("UdpSocketWin32:WSARecvFrom failed 0x%X", err);
          FreePacket(p);
          break;
        }
      }
      num_reads[IPV4]++;
    }

    assert(freed_packets_count >= 0);
    if (freed_packets_count >= 32) {
      FreePackets(freed_packets, freed_packets_end, freed_packets_count);
      freed_packets_count = 0;
      freed_packets_end = &freed_packets;
    } else if (freed_packets == NULL) {
      assert(freed_packets_count == 0);
      freed_packets_end = &freed_packets;
    }

    ULONG num_entries = 0;
    if (!GetQueuedCompletionStatusEx(completion_port_handle_, entries, kUdpGetQueuedCompletionStatusSize, &num_entries, INFINITE, FALSE)) {
      RINFO("GetQueuedCompletionStatusEx failed.");
      break;
    }
    finished_reads_end = &finished_reads;

    int finished_reads_count = 0;
    // Go through the finished entries and determine which ones are reads, and which ones are writes.
    for (ULONG i = 0; i < num_entries; i++) {
      if (!entries[i].lpOverlapped)
        continue; // This is the dummy entry from |PostQueuedCompletionStatus|
      Packet *p = (Packet*)((byte*)entries[i].lpOverlapped - offsetof(Packet, overlapped));
      if (p->post_target == ThreadedPacketQueue::TARGET_PROCESSOR_UDP) {
        num_reads[entries[i].lpCompletionKey]--;
        if ((DWORD)p->overlapped.Internal != 0) {
          if (!IsIgnoredUdpError((DWORD)p->overlapped.Internal))
            RERROR("UdpSocketWin32::Read error 0x%X", (DWORD)p->overlapped.Internal);
          FreePacket(p);
          continue;
        }
        p->size = (int)p->overlapped.InternalHigh;
        *finished_reads_end = p;
        finished_reads_end = &p->next;
        finished_reads_count++;
      } else {
        num_writes--;
        if ((DWORD)p->overlapped.Internal != 0) {
          RERROR("UdpSocketWin32::Write error 0x%X", (DWORD)p->overlapped.Internal);
          FreePacket(p);
          continue;
        }
        *freed_packets_end = p;
        freed_packets_end = &p->next;
        freed_packets_count++;
      }
    }
    *finished_reads_end = NULL;
    *freed_packets_end = NULL;
    assert(num_writes >= 0);

    // Push all the finished reads to the packet handler
    if (finished_reads != NULL) {
      packet_handler_->Post(finished_reads, finished_reads_end, finished_reads_count);
    }
    // Initiate more writes from |wqueue_|
    while (num_writes < kConcurrentWriteTap) {
      // Refill from queue if empty, avoid taking the mutex if it looks empty
      if (!pending_writes) {
        if (!wqueue_)
          break;
        mutex_.Acquire();
        pending_writes = wqueue_;
        wqueue_end_ = &wqueue_;
        wqueue_ = NULL;
        mutex_.Release();
        if (!pending_writes)
          break;
      }

      qs.udp_qsize1+= pending_writes->size;

      // Then issue writes
      Packet *p = pending_writes;
      pending_writes = p->next;
      ClearOverlapped(&p->overlapped);
      p->post_target = ThreadedPacketQueue::TARGET_UDP_DEVICE;
      WSABUF wsabuf = {(ULONG)p->size, (char*)p->data};

      int rv;
      if (p->addr.sin.sin_family == AF_INET) {
        rv = WSASendTo(socket_, &wsabuf, 1, NULL, 0, (struct sockaddr*)&p->addr.sin, sizeof(p->addr.sin), &p->overlapped, NULL);
      } else {
        if (socket_ipv6_ == INVALID_SOCKET) {
          RERROR("UdpSocketWin32: unavailable ipv6 socket");
          FreePacket(p);
          continue;
        }
        max_read_ipv6 = kConcurrentReadTap;
        rv = WSASendTo(socket_ipv6_, &wsabuf, 1, NULL, 0, (struct sockaddr*)&p->addr.sin6, sizeof(p->addr.sin6), &p->overlapped, NULL);
      }
      if (rv != 0) {
        DWORD err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
          RERROR("UdpSocketWin32: WSASendTo failed 0x%X", err);
          FreePacket(p);
          continue;
        }
      }
      num_writes++;
    }
  }
  FreePacketList(freed_packets);
  FreePacketList(pending_writes);

  // Cancel all IO and wait for all completions
  CancelIo((HANDLE)socket_);
  CancelIo((HANDLE)socket_ipv6_);

  while (num_reads[IPV4] + num_reads[IPV6] + num_writes) {
    ULONG num_entries = 0;
    if (!GetQueuedCompletionStatusEx(completion_port_handle_, entries, 1, &num_entries, INFINITE, FALSE)) {
      RINFO("GetQueuedCompletionStatusEx failed.");
      break;
    }
    if (!entries[0].lpOverlapped)
      continue; // This is the dummy entry from |PostQueuedCompletionStatus|
    Packet *p = (Packet*)((byte*)entries[0].lpOverlapped - offsetof(Packet, overlapped));
    if (p->post_target == ThreadedPacketQueue::TARGET_PROCESSOR_UDP) {
      num_reads[entries[0].lpCompletionKey]--;
    } else {
      num_writes--;
    }
    FreePacket(p);
  }
}



// Called on another thread to queue up a udp packet
void UdpSocketWin32::WriteUdpPacket(Packet *packet) {
  if (qs.udp_qsize2 - qs.udp_qsize1 >= (unsigned)(packet->size < 576 ? MAX_BYTES_IN_UDP_OUT_QUEUE_SMALL : MAX_BYTES_IN_UDP_OUT_QUEUE)) {
    FreePacket(packet);
    return;
  }
  packet->next = NULL;
  qs.udp_qsize2 += packet->size;
  
  mutex_.Acquire();
  Packet *was_empty = wqueue_;
  *wqueue_end_ = packet;
  wqueue_end_ = &packet->next;
  mutex_.Release();

  if (was_empty == NULL) {
    // Notify the worker thread that it should attempt more writes
    PostQueuedCompletionStatus(completion_port_handle_, NULL, NULL, NULL);
  }
}

DWORD WINAPI UdpSocketWin32::UdpThread(void *x) {
  UdpSocketWin32 *udp = (UdpSocketWin32 *)x;
  udp->ThreadMain();
  return 0;
}

void UdpSocketWin32::StartThread() {
  DWORD thread_id;
  thread_ = CreateThread(NULL, 0, &UdpThread, this, 0, &thread_id);
  SetThreadPriority(thread_, ABOVE_NORMAL_PRIORITY_CLASS);
}

void UdpSocketWin32::StopThread() {
  exit_thread_ = true;
  PostQueuedCompletionStatus(completion_port_handle_, NULL, NULL, NULL);
  WaitForSingleObject(thread_, INFINITE);
  CloseHandle(thread_);
  thread_ = NULL;
}

ThreadedPacketQueue::ThreadedPacketQueue(WireguardProcessor *wg, TunsafeBackendWin32 *backend) {
  wg_ = wg;
  backend_ = backend;
  event_ = CreateEvent(NULL, FALSE, FALSE, NULL);

  last_ptr_ = &first_;
  first_ = NULL;
  handle_ = NULL;
  timer_handle_ = NULL;
  exit_flag_ = false;
  timer_interrupt_ = false;
  packets_in_queue_ = 0;
  need_notify_ = 0;
}

ThreadedPacketQueue::~ThreadedPacketQueue() {
  assert(handle_ == NULL);
  assert(timer_handle_ == NULL);
  first_ = NULL;
  last_ptr_ = &first_;
  CloseHandle(event_);
}

DWORD WINAPI ThreadedPacketQueue::ThreadedPacketQueueLauncher(VOID *x) {
  ThreadedPacketQueue *pq = (ThreadedPacketQueue *)x;
  return pq->ThreadMain();
}

DWORD ThreadedPacketQueue::ThreadMain() {
  int free_packets_ctr = 0;
  int overload = 0;
  Packet *packet;

  wg_->dev().SetCurrentThreadAsMainThread();

  mutex_.Acquire();
  while (!exit_flag_) {
    if (timer_interrupt_) {
      timer_interrupt_ = false;
      need_notify_ = 0;
      mutex_.Release();
      wg_->SecondLoop();
      backend_->stats_mutex_.Acquire();
      backend_->stats_ = wg_->GetStats();
      float data[2] = {
        // unit is megabits/second
        backend_->stats_.tun_bytes_in_per_second * (1.0f / 125000),
        backend_->stats_.tun_bytes_out_per_second * (1.0f / 125000),
      };
      backend_->stats_collector_.AddSamples(data);
      backend_->stats_mutex_.Release();

      backend_->delegate_->OnGraphAvailable();
      backend_->PushStats();

      // Conserve memory every 10s
      if (free_packets_ctr++ == 10) {
        free_packets_ctr = 0;
        FreeAllPackets();
      }
      if (overload)
        overload -= 1;
    } else if ((packet = first_) == NULL) {
      need_notify_ = 1;
      mutex_.Release();
      WaitForSingleObject(event_, INFINITE);
    } else {
      // Steal the whole work queue
      first_ = NULL;
      last_ptr_ = &first_;
      int packets_in_queue = packets_in_queue_;
      packets_in_queue_ = 0;
      need_notify_ = 0;
      mutex_.Release();

      tpq_last_qsize = packets_in_queue;
      if (packets_in_queue >= 1024)
        overload = 2;
      bool is_overload = (overload != 0);

      WireguardProcessor *procint = wg_;
      do {
        Packet *next = packet->next;
        if (packet->post_target == TARGET_PROCESSOR_UDP)
          procint->HandleUdpPacket(packet, is_overload);
        else
          procint->HandleTunPacket(packet);
        packet = next;
      } while (packet);
    }
    wg_->RunAllMainThreadScheduled();
    mutex_.Acquire();
  }
  mutex_.Release();
  return 0;
}

void ThreadedPacketQueue::Start() {
  if (handle_ == NULL) {
    exit_flag_ = false;
    DWORD thread_id;
    handle_ = CreateThread(NULL, 0, &ThreadedPacketQueueLauncher, this, 0, &thread_id);
  }

  assert(timer_handle_ == NULL);
  timer_handle_ = CreateWaitableTimer(NULL, FALSE, NULL);
  long long due_time = 10000000;
  SetWaitableTimer(timer_handle_, (LARGE_INTEGER*)&due_time, 1000, &TimerRoutine, this, FALSE);
}

void ThreadedPacketQueue::Stop() {
  mutex_.Acquire();
  exit_flag_ = true;
  mutex_.Release();

  SetEvent(event_);

  if (timer_handle_ != NULL) {
    // Not sure if just CloseHandle will close any outstanding APCs
    CancelWaitableTimer(timer_handle_);
    CloseHandle(timer_handle_);
    timer_handle_ = NULL;
  }

  if (handle_ != NULL) {
    WaitForSingleObject(handle_, INFINITE);
    CloseHandle(handle_);
    handle_ = NULL;
  }

}

void ThreadedPacketQueue::AbortingDriver() {
  mutex_.Acquire();
  exit_flag_ = true;
  mutex_.Release();
}

void ThreadedPacketQueue::Post(Packet *packet, Packet **end, int count) {
  mutex_.Acquire();
  if (packets_in_queue_ >= HARD_MAXIMUM_QUEUE_SIZE) {
    mutex_.Release();
    FreePackets(packet, end, count);
    return;
  }
  assert(packet != NULL);
  if (!first_) {
    assert(last_ptr_ == &first_);
  }
  packets_in_queue_ += count;
  *last_ptr_ = packet;
  last_ptr_ = end;
  if (!first_) {
    assert(last_ptr_ == &first_);
  }
  if (need_notify_) {
    need_notify_ = 0;
    mutex_.Release();
    SetEvent(event_);
    return;
  }
  mutex_.Release();
}

void CALLBACK ThreadedPacketQueue::TimerRoutine(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue) {
  ((ThreadedPacketQueue*)lpArgToCompletionRoutine)->PostTimerInterrupt();
}

void ThreadedPacketQueue::PostTimerInterrupt() {
  mutex_.Acquire();
  timer_interrupt_ = true;
  if (need_notify_) {
    need_notify_ = 0;
    mutex_.Release();
    SetEvent(event_);
    return;
  }
  mutex_.Release();
}

bool GetNetLuidFromGuid(const char *adapter_guid, NET_LUID *luid) {
  char buffer[64];
  UUID uuid;
  size_t len = strlen(adapter_guid);
  if (adapter_guid[0] != '{' || adapter_guid[len - 1] != '}' || len >= 64) return false;
  buffer[len - 2] = 0;
  memcpy(buffer, adapter_guid + 1, len - 2);
  RPC_STATUS status = UuidFromStringA((RPC_CSTR)buffer, &uuid);
  if (status != 0)
    return false;
  return ConvertInterfaceGuidToLuid((GUID*)&uuid, luid) == 0;
}

DWORD SetMtuOnNetworkAdapter(NET_LUID *InterfaceLuid, ADDRESS_FAMILY family, int new_mtu) {
  MIB_IPINTERFACE_ROW row;
  DWORD err;
  InitializeIpInterfaceEntry(&row);
  row.Family = family;
  row.InterfaceLuid = *InterfaceLuid;
  if ((err = GetIpInterfaceEntry(&row)) == 0) {
    row.NlMtu = new_mtu;
    if (row.Family == AF_INET)
      row.SitePrefixLength = 0;
    err = SetIpInterfaceEntry(&row);
  }
  return err;
}

DWORD SetMetricOnNetworkAdapter(NET_LUID *InterfaceLuid, ADDRESS_FAMILY family, int new_metric) {
  MIB_IPINTERFACE_ROW row;
  DWORD err;
  InitializeIpInterfaceEntry(&row);
  row.Family = family;
  row.InterfaceLuid = *InterfaceLuid;
  if ((err = GetIpInterfaceEntry(&row)) == 0) {
    row.Metric = new_metric;
    row.UseAutomaticMetric = (new_metric == 0);
    if (row.Family == AF_INET)
      row.SitePrefixLength = 0;
    err = SetIpInterfaceEntry(&row);
  }
  return err;
}

static const char *PrintIPV6(const uint8 new_address[16]) {
  sockaddr_in6 sin6 = {0};
  static char buf[100];
  if (!inet_ntop(PF_INET6, (void*)new_address, buf, 100))
    memcpy(buf, "unknown", 8);
  return buf;
}

static bool SetIPV6AddressOnInterface(NET_LUID *InterfaceLuid, const uint8 new_address[16], int new_cidr) {
  NETIO_STATUS Status;
  PMIB_UNICASTIPADDRESS_TABLE table = NULL;
  Status = GetUnicastIpAddressTable(AF_INET6, &table);
  if (Status != 0) {
    RERROR("GetUnicastAddressTable Failed. Error %d\n", Status);
    return false;
  }

  bool found_row = false;
  for (int i = 0; i < (int)table->NumEntries; i++) {
    MIB_UNICASTIPADDRESS_ROW *row = &table->Table[i];
    if (!memcmp(&row->InterfaceLuid, InterfaceLuid, sizeof(NET_LUID))) {
      if (row->PrefixOrigin == 1 && row->SuffixOrigin == 1) {
        if (row->OnLinkPrefixLength == new_cidr && !memcmp(&row->Address.Ipv6.sin6_addr, new_address, 16)) {
          found_row = true;
          continue;
        }
        Status = DeleteUnicastIpAddressEntry(row);
        if (Status)
          RERROR("Error %d deleting IPv6 address: %s/%d", Status, PrintIPV6((uint8*)&row->Address.Ipv6.sin6_addr), row->OnLinkPrefixLength);
        else
          RINFO("Deleted IPv6 address: %s/%d", PrintIPV6((uint8*)&row->Address.Ipv6.sin6_addr), row->OnLinkPrefixLength);
      }
    }
  }
  FreeMibTable(table);

  if (found_row) {
    RINFO("Using IPv6 address: %s/%d", PrintIPV6(new_address), new_cidr);
    return true;
  }

  MIB_UNICASTIPADDRESS_ROW Row;
  InitializeUnicastIpAddressEntry(&Row);
  Row.OnLinkPrefixLength = new_cidr;
  Row.Address.si_family = AF_INET6;
  memcpy(&Row.Address.Ipv6.sin6_addr, new_address, 16);
  Row.InterfaceLuid = *InterfaceLuid;
  Status = CreateUnicastIpAddressEntry(&Row);
  if (Status != 0) {
    RERROR("Error %d setting IPv6 address: %s/%d", Status, PrintIPV6(new_address), new_cidr);
    return false;
  }
  RINFO("Set IPV6 Address to: %s/%d", PrintIPV6(new_address), new_cidr);
  return true;
}

static bool IsIpv6AddressSet(const void *p) {
  return (ReadLE64(p) | ReadLE64((char*)p + 8)) != 0;
}


static bool SetIPV6DnsOnInterface(NET_LUID *InterfaceLuid, const uint8 new_address[16]) {
  char buf[128];
  char ipv6[128];
  NET_IFINDEX InterfaceIndex;
  if (ConvertInterfaceLuidToIndex(InterfaceLuid, &InterfaceIndex))
    return false;
  if (IsIpv6AddressSet(new_address)) {
    if (!inet_ntop(AF_INET6, new_address, ipv6, sizeof(ipv6)))
      return false;

    snprintf(buf, sizeof(buf), "netsh interface ipv6 set dns name=%d static %s validate=no", InterfaceIndex, ipv6);
  } else {
    snprintf(buf, sizeof(buf), "netsh interface ipv6 delete dns name=%d all", InterfaceIndex);
  }
  return RunNetsh(buf);
}

static uint32 ComputeIpv4DefaultRoute(uint32 ip, uint32 netmask) {
  uint32 default_route_v4 = (ip & netmask) | 1;
  if (default_route_v4 == ip)
    default_route_v4++;
  return default_route_v4;
}

static void ComputeIpv6DefaultRoute(const uint8 *ipv6_address, uint8 ipv6_cidr, uint8 *default_route_v6) {
  memcpy(default_route_v6, ipv6_address, 16);
  // clear the last bits of the ipv6 address to match the cidr.
  size_t n = (ipv6_cidr + 7) >> 3;
  memset(&default_route_v6[n], 0, 16 - n);
  if (n == 0)
    return;
  // adjust the final byte
  default_route_v6[n - 1] &= ~(0xff >> (ipv6_cidr & 7));
  // set the very last byte to something
  default_route_v6[15] |= 1;
  // ensure it doesn't collide
  if (memcmp(default_route_v6, ipv6_address, 16) == 0)
    default_route_v6[15] ^= 3;
}


static bool AddMultipleCatchallRoutes(int inet, int bits, const uint8 *target, const NET_LUID &luid, std::vector<MIB_IPFORWARD_ROW2> *undo_array) {
  uint8 tmp[16] = {0};
  bool success = true;
  for (int i = 0; i < (1 << bits); i++) {
    tmp[0] = i << (8 - bits);
    success &= AddRoute(inet, tmp, bits, target, &luid, undo_array);
  }
  return success;
}

TunWin32Adapter::TunWin32Adapter(DnsBlocker *dns_blocker) {
  handle_ = NULL;
  dns_blocker_ = dns_blocker;
}

TunWin32Adapter::~TunWin32Adapter() {

}

bool TunWin32Adapter::OpenAdapter(uint32 *exit_thread, DWORD open_flags) {
  assert(handle_ == NULL);
  int retry_count = 20;
  handle_ = OpenTunAdapter(guid_, retry_count, exit_thread, open_flags);
  return (handle_ != NULL);
}

bool TunWin32Adapter::InitAdapter(const TunInterface::TunConfig &&config, TunInterface::TunConfigOut *out) {
  ULONG info[3];
  DWORD len;
  out->enable_neighbor_discovery_spoofing = false;

  if (!RunPrePostCommand(config.pre_post_commands.pre_up)) {
    RERROR("Pre command failed!");
    return false;
  }
  
  memset(info, 0, sizeof(info));
  if (DeviceIoControl(handle_, TAP_IOCTL_GET_VERSION, &info, sizeof(info),
                      &info, sizeof(info), &len, NULL)) {
    RINFO("TAP Driver Version %d.%d %s", (int)info[0], (int)info[1], (info[2] ? "(DEBUG)" : ""));
  }

  if (info[0] < 9 || info[0] == 9 && info[1] <= 8) {
    RERROR("TAP is too old. Go to https://tunsafe.com/download to upgrade the driver");
    return false;
  }

  //  ULONG mtu = 0;
  //  if (DeviceIoControl(handle_, TAP_IOCTL_GET_MTU, &mtu, sizeof(mtu), &mtu, sizeof(mtu), &len, NULL))
  //    RINFO("TAP-Win32 MTU=%d", (int)mtu);
  //  mtu_ = mtu;

  uint32 netmask = CidrToNetmaskV4(config.cidr);

  // Set TAP-Windows TUN subnet mode
  if (1) {
    uint32 v[3];

    v[0] = htonl(config.ip);
    v[1] = htonl(config.ip & netmask);
    v[2] = htonl(netmask);
    if (!DeviceIoControl(handle_, TAP_IOCTL_CONFIG_TUN, v, sizeof(v), v, sizeof(v), &len, NULL)) {
      RERROR("DeviceIoControl(TAP_IOCTL_CONFIG_TUN) failed");
      return false;
    }
  }

  // Set DHCP IP/netmask
  {
    uint32 v[4];
    v[0] = htonl(config.ip);
    v[1] = htonl(netmask);
    v[2] = htonl((config.ip | ~netmask) - 1); // x.x.x.254
    v[3] = 31536000;                         // One year
    if (!DeviceIoControl(handle_, TAP_IOCTL_CONFIG_DHCP_MASQ, v, sizeof(v), v, sizeof(v), &len, NULL)) {
      RERROR("DeviceIoControl(TAP_IOCTL_CONFIG_DHCP_MASQ) failed");
      return false;
    }
  }

  bool has_dns_setting = false;

  // Set DHCP config string
  if (config.dhcp_options_size != 0) {
    byte output[10];
    if (!DeviceIoControl(handle_, TAP_IOCTL_CONFIG_DHCP_SET_OPT,
      (void*)config.dhcp_options, (DWORD)config.dhcp_options_size, output, sizeof(output), &len, NULL)) {
      RERROR("DeviceIoControl(TAP_IOCTL_CONFIG_DHCP_SET_OPT) failed");
      return false;
    }
    has_dns_setting = true;
  }

  // Get device MAC address
  if (!DeviceIoControl(handle_, TAP_IOCTL_GET_MAC, mac_adress_, 6, mac_adress_, sizeof(mac_adress_), &len, NULL)) {
    RERROR("DeviceIoControl(TAP_IOCTL_GET_MAC) failed");
  } else {
    out->enable_neighbor_discovery_spoofing = true;
    memcpy(out->neighbor_discovery_spoofing_mac, mac_adress_, sizeof(out->neighbor_discovery_spoofing_mac));
  }

  // Set driver media status to 'connected'
  ULONG status = TRUE;
  if (!DeviceIoControl(handle_, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status),
                       &status, sizeof(status), &len, NULL)) {
    RERROR("DeviceIoControl(TAP_IOCTL_SET_MEDIA_STATUS) failed");
    return false;
  }

  NET_LUID InterfaceLuid = {0};
  bool has_interface_luid = GetNetLuidFromGuid(guid_, &InterfaceLuid);

  if (!has_interface_luid) {
    RERROR("Unable to determine interface luid for %s.", guid_);
    return false;
  }

  DWORD err;

  if (config.mtu) {
    err = SetMtuOnNetworkAdapter(&InterfaceLuid, AF_INET, config.mtu);
    if (err)
      RERROR("SetMtuOnNetworkAdapter IPv4 failed: %d", err);
    if (config.ipv6_cidr) {
      err = SetMtuOnNetworkAdapter(&InterfaceLuid, AF_INET6, config.mtu);
      if (err)
        RERROR("SetMtuOnNetworkAdapter IPv6 failed: %d", err);
    }
  }

  if (config.ipv6_cidr) {
    SetIPV6AddressOnInterface(&InterfaceLuid, config.ipv6_address, config.ipv6_cidr);
    if (config.set_ipv6_dns) {
      has_dns_setting |= IsIpv6AddressSet(config.dns_server_v6);
      if (!SetIPV6DnsOnInterface(&InterfaceLuid, config.dns_server_v6)) {
        RERROR("SetIPV6DnsOnInterface: failed");
      }
    }
  }

  if (has_dns_setting && config.block_dns_on_adapters) {
    RINFO("Blocking standard DNS on all adapters");
    dns_blocker_->BlockDnsExceptOnAdapter(InterfaceLuid, config.ipv6_cidr != 0);

    err = SetMetricOnNetworkAdapter(&InterfaceLuid, AF_INET, 2);
    if (err)
      RERROR("SetMetricOnNetworkAdapter IPv4 failed: %d", err);

    if (config.ipv6_cidr) {
      err = SetMetricOnNetworkAdapter(&InterfaceLuid, AF_INET6, 2);
      if (err)
        RERROR("SetMetricOnNetworkAdapter IPv6 failed: %d", err);
    }
  } else {
    dns_blocker_->RestoreDns();
  }

  uint8 ibs = config.internet_blocking;
  if (ibs == kBlockInternet_Default || ibs == kBlockInternet_DefaultOn) {
    uint8 new_ibs = GetInternetBlockState(NULL);
    ibs = (new_ibs == kBlockInternet_Off && ibs == kBlockInternet_DefaultOn) ? kBlockInternet_Firewall : new_ibs;
  }

  bool block_all_traffic_route = (ibs & kBlockInternet_Route) != 0;

  RouteInfo ri, ri6;

  uint32 default_route_endpoint_v4 = ToBE32(config.default_route_endpoint_v4);

  // Delete any current /1 default routes and read some stuff from the routing table.
  if (!GetDefaultRouteAndDeleteOldRoutes(AF_INET, &InterfaceLuid, block_all_traffic_route, config.use_ipv4_default_route ? (uint8*)&default_route_endpoint_v4 : NULL, &ri)) {
    RERROR("Unable to read old default gateway and delete old default routes.");
    return false;
  }

  if (config.ipv6_cidr) {
    // Delete any current /1 default routes and read some stuff from the routing table.
    if (!GetDefaultRouteAndDeleteOldRoutes(AF_INET6, &InterfaceLuid, block_all_traffic_route, config.use_ipv6_default_route ? (uint8*)config.default_route_endpoint_v6 : NULL, &ri6)) {
      RERROR("Unable to read old default gateway and delete old default routes for IPv6.");
      return false;
    }
  }

  uint32 default_route_v4 = ComputeIpv4DefaultRoute(config.ip, netmask);
  uint8 default_route_v6[16];

  if (block_all_traffic_route) {
    RINFO("Blocking all regular Internet traffic using routing rules");
    NET_LUID localhost_luid;
    if (ConvertInterfaceIndexToLuid(1, &localhost_luid) || localhost_luid.Info.IfType != 24) {
      RERROR("Unable to get localhost luid - while adding route based blocking.");
    } else {
      uint32 dst[4] = {0};
      if (!AddMultipleCatchallRoutes(AF_INET, 1, (uint8*)&dst, localhost_luid, NULL))
        RERROR("Unable to add routes for route based blocking.");
      if (config.ipv6_cidr) {
        if (!AddMultipleCatchallRoutes(AF_INET6, 1, (uint8*)&dst, localhost_luid, NULL))
          RERROR("Unable to add IPv6 routes for route based blocking.");
      }
    }
  }

  internet_route_blocking_state = block_all_traffic_route + ROUTE_BLOCK_OFF;

  if (ibs & kBlockInternet_Firewall) {
    RINFO("Blocking all regular Internet traffic%s", ri.found_default_adapter ? " (except DHCP)" : "");
    AddPersistentInternetBlocking(ri.found_default_adapter ? &ri.default_adapter : NULL, InterfaceLuid, config.ipv6_cidr != 0);
  } else {
    SetInternetFwBlockingState(false);
  }

  // Configure default route?
  if (config.use_ipv4_default_route) {
    // Add a bypass route to the original gateway?
    if (config.default_route_endpoint_v4 != 0) {
      if (!ri.found_default_adapter) {
        RERROR("Unable to read old ipv4 default gateway");
        return false;
      }
      if (!AddRoute(AF_INET, &default_route_endpoint_v4, 32, ri.default_gw, &ri.default_adapter, &routes_to_undo_)) {
        RERROR("Unable to add ipv4 gateway bypass route.");
        return false;
      }
    }
    // Either add 4 routes or 2 routes, depending on if we use route blocking.
    uint32 be = ToBE32(default_route_v4);
    if (!AddMultipleCatchallRoutes(AF_INET, block_all_traffic_route ? 2 : 1, (uint8*)&be, InterfaceLuid, &routes_to_undo_))
      RERROR("Unable to add new default ipv4 route.");
  }

  if (config.ipv6_cidr) {
    ComputeIpv6DefaultRoute(config.ipv6_address, config.ipv6_cidr, default_route_v6);

    // Configure default route?
    if (config.use_ipv6_default_route) {
      if (IsIpv6AddressSet(config.default_route_endpoint_v6)) {
        if (!ri6.found_default_adapter) {
          RERROR("Unable to read old ipv6 default gateway");
          return false;
        }
        if (!AddRoute(AF_INET6, config.default_route_endpoint_v6, 128, ri.default_gw, &ri6.default_adapter, &routes_to_undo_)) {
          RERROR("Unable to add ipv6 gateway bypass route.");
          return false;
        }
      }
      if (!AddMultipleCatchallRoutes(AF_INET6, block_all_traffic_route ? 2 : 1, default_route_v6, InterfaceLuid, &routes_to_undo_))
        RERROR("Unable to add new default ipv6 route.");
    }
  }

  // Add all the extra routes
  for (auto it = config.extra_routes.begin(); it != config.extra_routes.end(); ++it) {
    if (it->size == 32) {
      uint32 be = ToBE32(default_route_v4);
      AddRoute(AF_INET, it->addr, it->cidr, &be, &InterfaceLuid, &routes_to_undo_);
    } else if (it->size == 128 && config.ipv6_cidr) {
      AddRoute(AF_INET6, it->addr, it->cidr, default_route_v6, &InterfaceLuid, &routes_to_undo_);
    }
  }

  // Add all the routes that should bypass vpn
  for (auto it = config.excluded_ips.begin(); it != config.excluded_ips.end(); ++it) {
    if (it->size == 32) {
      if (ri.found_default_adapter)
        AddRoute(AF_INET, it->addr, it->cidr, ri.default_gw, &ri.default_adapter, &routes_to_undo_);
    } else if (it->size == 128 && config.ipv6_cidr) {
      if (ri6.found_default_adapter)
        AddRoute(AF_INET6, it->addr, it->cidr, ri6.default_gw, &ri6.default_adapter, &routes_to_undo_);
    }
  }

  NET_IFINDEX InterfaceIndex;
  if (ConvertInterfaceLuidToIndex(&InterfaceLuid, &InterfaceIndex)) {
    RERROR("Unable to get index of adapter");
    return false;
  }
  if ((err = FlushIpNetTable2(AF_INET, InterfaceIndex)) != NO_ERROR) {
    RERROR("FlushIpNetTable failed: 0x%X", err);
    return false;
  }
  if (config.ipv6_cidr) {
    if ((err = FlushIpNetTable2(AF_INET6, InterfaceIndex)) != NO_ERROR) {
      RERROR("FlushIpNetTable failed: 0x%X", err);
      return false;
    }
  }

  RunPrePostCommand(config.pre_post_commands.post_up);

  pre_down_ = std::move(config.pre_post_commands.pre_down);
  post_down_ = std::move(config.pre_post_commands.post_down);

  return true;
}

void TunWin32Adapter::CloseAdapter() {
  RunPrePostCommand(pre_down_);

  if (handle_ != NULL) {
    ULONG status = FALSE;
    DWORD len;
    DeviceIoControl(handle_, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status),
                    &status, sizeof(status), &len, NULL);
    CloseHandle(handle_);
    handle_ = NULL;
  }

  for (auto it = routes_to_undo_.begin(); it != routes_to_undo_.end(); ++it)
    DeleteRoute(&*it);
  routes_to_undo_.clear();

  if (dns_blocker_)
    dns_blocker_->RestoreDns();
  
  RunPrePostCommand(post_down_);
}

static bool RunOneCommand(const std::string &cmd) {
  std::string command = "cmd.exe /C " + cmd;

  STARTUPINFOA si = {0};
  PROCESS_INFORMATION pi = {0};

  HANDLE hstdout_wr = NULL, hstdout_rd = NULL;
  HANDLE hstdin_wr = NULL, hstdin_rd = NULL;

  bool result = false;

  SECURITY_ATTRIBUTES saAttr;
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  if (!CreatePipe(&hstdout_rd, &hstdout_wr, &saAttr, 0) ||
      !CreatePipe(&hstdin_rd, &hstdin_wr, &saAttr, 0) ||
      !SetHandleInformation(hstdout_rd, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(hstdin_wr, HANDLE_FLAG_INHERIT, 0)) {
    goto out;
  }

  CloseHandle(hstdin_wr);
  hstdin_wr = NULL;
  
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdError = hstdout_wr;
  si.hStdOutput = hstdout_wr;
  si.hStdInput = hstdin_rd;

  RINFO("Run: %s", cmd.c_str());
  if (CreateProcessA(NULL, &command[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    DWORD exit_code = -1;
    char buf[1024];
    DWORD bufend = 0, bufstart = 0;
    
    CloseHandle(hstdout_wr);
    hstdout_wr = NULL;

    for (;;) {
      DWORD bytes_read = 0;
      bool foundeof = (!ReadFile(hstdout_rd, buf + bufend, sizeof(buf) - bufend, &bytes_read, NULL) || bytes_read == 0);
      bufend += bytes_read;
      for(;;) {
        char *nl = (char*)memchr(buf + bufstart, '\n', bufend - bufstart);
        if (!nl)
          break;
        char *st = buf + bufstart;
        char *nl2 = nl;
        if (nl != buf + bufstart && nl[-1] == '\r')
          nl--;
        bufstart = (DWORD)(nl2 - buf + 1);
        RINFO("%.*s", nl - st, st);
      }
      if (bufend - bufstart == sizeof(buf) || foundeof) {
        if (bufend - bufstart)
          RINFO("%.*s", buf + bufstart, bufend - bufstart);
        bufstart = bufend = 0;
      }
      if (foundeof)
        break;
      if (bufstart) {
        bufend -= bufstart;
        memmove(buf, buf + bufstart, bufend);
        bufstart = 0;
      }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != 0) {
      RERROR("Command line failed (%d) : %s", exit_code, cmd.c_str());
    } else {
      result = true;
    }
  } else {
    RERROR("CreateProcess failed: %s", cmd.c_str());
  }
  CloseHandle(hstdout_rd);
  CloseHandle(hstdout_wr);
  CloseHandle(hstdin_rd);
  CloseHandle(hstdin_wr);
out:
  return result;
}

bool TunWin32Adapter::RunPrePostCommand(const std::vector<std::string> &vec) {
  bool success = true;
  for (auto it = vec.begin(); it != vec.end(); ++it) {
    if (!g_allow_pre_post) {
      RERROR("Pre/Post commands are disabled. Ignoring: %s", it->c_str());
    } else {
      success &= RunOneCommand(*it);
    }
  }
  return success;
}


//////////////////////////////////////////////////////////////////////////////

TunWin32Iocp::TunWin32Iocp(DnsBlocker *blocker, TunsafeBackendWin32 *backend) : adapter_(blocker), backend_(backend) {
  wqueue_end_ = &wqueue_;
  wqueue_ = NULL;

  thread_ = NULL;
  completion_port_handle_ = NULL;
  packet_handler_ = NULL;
  exit_thread_ = false;
}

TunWin32Iocp::~TunWin32Iocp() {
  //assert(num_reads_ == 0 && num_writes_ == 0);
  assert(thread_ == NULL);
  CloseTun();
}

bool TunWin32Iocp::Initialize(const TunConfig &&config, TunConfigOut *out) {
  assert(thread_ == NULL);

  if (!adapter_.OpenAdapter(&backend_->stop_mode_, FILE_FLAG_OVERLAPPED))
    return false;
  
  completion_port_handle_ = CreateIoCompletionPort(adapter_.handle(), NULL, NULL, 0);
  if (completion_port_handle_ == NULL)
    return false;

  return adapter_.InitAdapter(std::move(config), out);
}

void TunWin32Iocp::CloseTun() {
  assert(thread_ == NULL);

  adapter_.CloseAdapter();
  
  if (completion_port_handle_) {
    CloseHandle(completion_port_handle_);
    completion_port_handle_ = NULL;
  }
  
  FreePacketList(wqueue_);
  wqueue_ = NULL;
  wqueue_end_ = &wqueue_;
}

enum {
  kTunGetQueuedCompletionStatusSize = kConcurrentWriteTap + kConcurrentReadTap + 1
};

void TunWin32Iocp::ThreadMain() {
  OVERLAPPED_ENTRY entries[kTunGetQueuedCompletionStatusSize];
  Packet *pending_writes = NULL;
  int num_reads = 0, num_writes = 0;
  Packet *finished_reads = NULL, **finished_reads_end;
  Packet *freed_packets = NULL, **freed_packets_end;
  int freed_packets_count = 0;
  DWORD err;

  while (!exit_thread_) {
    // Initiate more reads, reusing the Packet structures in |finished_writes|.
    for (int i = num_reads; i < kConcurrentReadTap; i++) {
      Packet *p;
      if (!AllocPacketFrom(&freed_packets, &freed_packets_count, &exit_thread_, &p))
        break;
      memset(&p->overlapped, 0, sizeof(p->overlapped));
      p->post_target = ThreadedPacketQueue::TARGET_PROCESSOR_TUN;
      if (!ReadFile(adapter_.handle(), p->data, kPacketCapacity, NULL, &p->overlapped) && (err = GetLastError()) != ERROR_IO_PENDING) {
        FreePacket(p);

        RERROR("TunWin32: ReadFile failed 0x%X", err);

        if (err == ERROR_OPERATION_ABORTED || err == ERROR_FILE_NOT_FOUND) {
          packet_handler_->AbortingDriver(); 
          RERROR("TAP driver stopped communicating. Attempting to restart.", err);
          // This can happen if we reinstall the TAP driver while there's an active connection. Wait a bit, then attempt to
          // restart.
          Sleep(1000);
          backend_->TunAdapterFailed();
          goto EXIT;
        }
      } else {
        num_reads++;
      }
    }
    g_tun_reads = num_reads;

    assert(freed_packets_count >= 0);
    if (freed_packets_count >= 32) {
      FreePackets(freed_packets, freed_packets_end, freed_packets_count);
      freed_packets_count = 0;
      freed_packets_end = &freed_packets;
    } else if (freed_packets == NULL) {
      assert(freed_packets_count == 0);
      freed_packets_end = &freed_packets;
    }

    ULONG num_entries = 0;
    if (!GetQueuedCompletionStatusEx(completion_port_handle_, entries, kTunGetQueuedCompletionStatusSize, &num_entries, INFINITE, FALSE)) {
      RINFO("GetQueuedCompletionStatusEx failed.");
      break;
    }
    finished_reads_end = &finished_reads;
    int finished_reads_count = 0;

    // Go through the finished entries and determine which ones are reads, and which ones are writes.
    for (ULONG i = 0; i < num_entries; i++) {
      if (!entries[i].lpOverlapped)
        continue; // This is the dummy entry from |PostQueuedCompletionStatus|
      Packet *p = (Packet*)((byte*)entries[i].lpOverlapped - offsetof(Packet, overlapped));
      if (p->post_target == ThreadedPacketQueue::TARGET_PROCESSOR_TUN) {
        num_reads--;
        if ((int)p->overlapped.Internal != 0) {
          RERROR("TunWin32::ReadComplete error 0x%X", (int)p->overlapped.Internal);
          FreePacket(p);
          continue;
        }
        p->size = (int)p->overlapped.InternalHigh;

        *finished_reads_end = p;
        finished_reads_end = &p->next;
        finished_reads_count++;
      } else {
        num_writes--;
        if ((int)p->overlapped.Internal != 0) {
          RERROR("TunWin32::WriteComplete error 0x%X", (int)p->overlapped.Internal);
          FreePacket(p);
          continue;
        }
        freed_packets_count++;
        *freed_packets_end = p;
        freed_packets_end = &p->next;
      }
    }
    *finished_reads_end = NULL;
    *freed_packets_end = NULL;

    if (finished_reads != NULL)
      packet_handler_->Post(finished_reads, finished_reads_end, finished_reads_count);

    // Initiate more writes from |wqueue_|
    while (num_writes < kConcurrentWriteTap) {
      // Refill from queue if empty, avoid taking the mutex if it looks empty 
      if (!pending_writes) {
        if (!wqueue_)
          break;
        mutex_.Acquire();
        pending_writes = wqueue_;
        wqueue_end_ = &wqueue_;
        wqueue_ = NULL;
        mutex_.Release();
        if (!pending_writes)
          break;
      }
      // Then issue writes
      Packet *p = pending_writes;
      pending_writes = p->next;
      memset(&p->overlapped, 0, sizeof(p->overlapped));
      p->post_target = ThreadedPacketQueue::TARGET_TUN_DEVICE;
      if (!WriteFile(adapter_.handle(), p->data, p->size, NULL, &p->overlapped) && (err = GetLastError()) != ERROR_IO_PENDING) {
        RERROR("TunWin32: WriteFile failed 0x%X", err);
        FreePacket(p);
      } else {
        num_writes++;
      }
    }
    g_tun_writes = num_writes;
  }

EXIT:
  // Cancel all IO and wait for all completions
  CancelIo(adapter_.handle());
  while (num_reads + num_writes) {
    ULONG num_entries = 0;
    if (!GetQueuedCompletionStatusEx(completion_port_handle_, entries, 1, &num_entries, INFINITE, FALSE)) {
      RINFO("GetQueuedCompletionStatusEx failed.");
      break;
    }
    if (!entries[0].lpOverlapped)
      continue; // This is the dummy entry from |PostQueuedCompletionStatus|
    Packet *p = (Packet*)((byte*)entries[0].lpOverlapped - offsetof(Packet, overlapped));
    if (p->post_target == ThreadedPacketQueue::TARGET_PROCESSOR_TUN) {
      num_reads--;
    } else {
      num_writes--;
    }
    FreePacket(p);
  }

  FreePacketList(freed_packets);
  FreePacketList(pending_writes);
}

DWORD WINAPI TunWin32Iocp::TunThread(void *x) {
  TunWin32Iocp *xx = (TunWin32Iocp *)x;
  xx->ThreadMain();
  return 0;
}

void TunWin32Iocp::StartThread() {
  DWORD thread_id;
  thread_ = CreateThread(NULL, 0, &TunThread, this, 0, &thread_id);
  SetThreadPriority(thread_, ABOVE_NORMAL_PRIORITY_CLASS);
}

void TunWin32Iocp::StopThread() {
  exit_thread_ = true;
  PostQueuedCompletionStatus(completion_port_handle_, NULL, NULL, NULL);
  WaitForSingleObject(thread_, INFINITE);
  CloseHandle(thread_);
  thread_ = NULL;
}

void TunWin32Iocp::WriteTunPacket(Packet *packet) {
  packet->next = NULL;
  mutex_.Acquire();
  Packet *was_empty = wqueue_;
  *wqueue_end_ = packet;
  wqueue_end_ = &packet->next;
  mutex_.Release();
  if (was_empty == NULL) {
    // Notify the worker thread that it should attempt more writes
    PostQueuedCompletionStatus(completion_port_handle_, NULL, NULL, NULL);
  }
}



//////////////////////////////////////////////////////////////////////////////

TunWin32Overlapped::TunWin32Overlapped(DnsBlocker *blocker, TunsafeBackendWin32 *backend) : adapter_(blocker), backend_(backend) {
  wqueue_end_ = &wqueue_;
  wqueue_ = NULL;

  thread_ = NULL;

  read_event_ = CreateEvent(NULL, TRUE, FALSE, NULL);
  write_event_ = CreateEvent(NULL, TRUE, FALSE, NULL);
  wake_event_ = CreateEvent(NULL, FALSE, FALSE, NULL);
  
  packet_handler_ = NULL;
  exit_thread_ = false;
}

TunWin32Overlapped::~TunWin32Overlapped() {
  CloseTun();
  CloseHandle(read_event_);
  CloseHandle(write_event_);
  CloseHandle(wake_event_);
}

bool TunWin32Overlapped::Initialize(const TunConfig &&config, TunConfigOut *out) {
  CloseTun();
  return adapter_.OpenAdapter(&backend_->stop_mode_, FILE_FLAG_OVERLAPPED) &&
         adapter_.InitAdapter(std::move(config), out);
}

void TunWin32Overlapped::CloseTun() {
  assert(thread_ == NULL);
  adapter_.CloseAdapter();
  FreePacketList(wqueue_);
  wqueue_ = NULL;
  wqueue_end_ = &wqueue_;
}

void TunWin32Overlapped::ThreadMain() {
  Packet *pending_writes = NULL;
  DWORD err;
  Packet *read_packet = NULL, *write_packet = NULL;

  HANDLE h[3];
  while (!exit_thread_) {
    if (read_packet == NULL) {
      Packet *p = AllocPacket();
      memset(&p->overlapped, 0, sizeof(p->overlapped));
      p->overlapped.hEvent = read_event_;
      p->post_target = ThreadedPacketQueue::TARGET_PROCESSOR_TUN;
      if (!ReadFile(adapter_.handle(), p->data, kPacketCapacity, NULL, &p->overlapped) && (err = GetLastError()) != ERROR_IO_PENDING) {
        FreePacket(p);
        RERROR("TunWin32: ReadFile failed 0x%X", err);
      } else {
        read_packet = p;
      }
    }

    int n = 0;
    if (write_packet)
      h[n++] = write_event_;
    if (read_packet != NULL)
      h[n++] = read_event_;
    h[n++] = wake_event_;

    DWORD res = WaitForMultipleObjects(n, h, FALSE, INFINITE);

    if (res >= WAIT_OBJECT_0 && res <= WAIT_OBJECT_0 + 2) {
      HANDLE hx = h[res - WAIT_OBJECT_0];
      if (hx == read_event_) {
        read_packet->size = (int)read_packet->overlapped.InternalHigh;
        read_packet->next = NULL;
        packet_handler_->Post(read_packet, &read_packet->next, 1);
        read_packet = NULL;
      } else if (hx == write_event_) {
        FreePacket(write_packet);
        write_packet = NULL;
      }
    } else {
      RERROR("Wait said %d", res);
    }
    
    if (write_packet == NULL) {
      if (!pending_writes) {
        mutex_.Acquire();
        pending_writes = wqueue_;
        wqueue_end_ = &wqueue_;
        wqueue_ = NULL;
        mutex_.Release();
      }
      if (pending_writes) {
        // Then issue writes
        Packet *p = pending_writes;
        pending_writes = p->next;
        memset(&p->overlapped, 0, sizeof(p->overlapped));
        p->overlapped.hEvent = write_event_;
        p->post_target = ThreadedPacketQueue::TARGET_TUN_DEVICE;
        if (!WriteFile(adapter_.handle(), p->data, p->size, NULL, &p->overlapped) && (err = GetLastError()) != ERROR_IO_PENDING) {
          RERROR("TunWin32: WriteFile failed 0x%X", err);
          FreePacket(p);
        } else {
          write_packet = p;
        }
      }
    }
  }

  // TODO: Free memory
  CancelIo(adapter_.handle());
  FreePacketList(pending_writes);
}

DWORD WINAPI TunWin32Overlapped::TunThread(void *x) {
  TunWin32Overlapped *xx = (TunWin32Overlapped *)x;
  xx->ThreadMain();
  return 0;
}

void TunWin32Overlapped::StartThread() {
  DWORD thread_id;
  thread_ = CreateThread(NULL, 0, &TunThread, this, 0, &thread_id);
  SetThreadPriority(thread_, ABOVE_NORMAL_PRIORITY_CLASS);
}

void TunWin32Overlapped::StopThread() {
  exit_thread_ = true;
  SetEvent(wake_event_);
  WaitForSingleObject(thread_, INFINITE);
  CloseHandle(thread_);
  thread_ = NULL;
}

void TunWin32Overlapped::WriteTunPacket(Packet *packet) {
  packet->next = NULL;
  mutex_.Acquire();
  Packet *was_empty = wqueue_;
  *wqueue_end_ = packet;
  wqueue_end_ = &packet->next;
  mutex_.Release();
  if (was_empty == NULL)
    SetEvent(wake_event_);
}

void TunsafeBackendWin32::SetPublicKey(const uint8 key[32]) {
  memcpy(public_key_, key, 32);
  delegate_->OnStateChanged();
}

DWORD WINAPI TunsafeBackendWin32::WorkerThread(void *bk) {
  TunsafeBackendWin32 *backend = (TunsafeBackendWin32*)bk;
  int stop_mode;

  for(;;) {
    TunWin32Iocp tun(&backend->dns_blocker_, backend);
    UdpSocketWin32 udp;
    WireguardProcessor wg_proc(&udp, &tun, backend);

    ThreadedPacketQueue queues_for_processor(&wg_proc, backend);

    qs.udp_qsize1 = qs.udp_qsize2 = 0;

    udp.SetPacketHandler(&queues_for_processor);
    tun.SetPacketHandler(&queues_for_processor);

    wg_proc.dev().SetCurrentThreadAsMainThread();

    if (!ParseWireGuardConfigFile(&wg_proc, backend->config_file_, &backend->dns_resolver_))
      goto getout_fail;

    if (!wg_proc.Start())
      goto getout_fail;

    // only for use in callbacks from wg
    backend->wg_processor_ = &wg_proc;

    queues_for_processor.Start();
    udp.StartThread();
    tun.StartThread();

    backend->SetPublicKey(wg_proc.dev().public_key());

    while ((stop_mode = InterlockedExchange(&backend->stop_mode_, MODE_NONE)) == MODE_NONE) {
      SleepEx(INFINITE, TRUE);
    }

    // Keep DNS alive
    if (stop_mode != MODE_EXIT)
      tun.adapter().DisassociateDnsBlocker();
    else
      backend->dns_resolver_.ClearCache();

    udp.StopThread();
    tun.StopThread();
    queues_for_processor.Stop();

    backend->wg_processor_ = NULL;

    FreeAllPackets();

    if (stop_mode != MODE_TUN_FAILED)
      return 0;
    
    uint32 last_fail = GetTickCount();
    bool permanent_fail = (last_fail - backend->last_tun_adapter_failed_) < 5000;
    backend->last_tun_adapter_failed_ = last_fail;

    backend->status_ = permanent_fail ? TunsafeBackend::kErrorTunPermanent : TunsafeBackend::kStatusTunRetrying;
    backend->delegate_->OnStatusCode(backend->status_);
    
    if (permanent_fail) {
      RERROR("Too many automatic restarts...");
      goto getout_fail;
    }
  }
getout_fail:
  backend->dns_blocker_.RestoreDns();
  backend->status_ = TunsafeBackend::kErrorInitialize;
  backend->delegate_->OnStatusCode(TunsafeBackend::kErrorInitialize);
  return 0;
}

static void WINAPI ExitServiceAPC(ULONG_PTR a) {
}

TunsafeBackend::TunsafeBackend() {
  is_started_ = false;
  is_remote_ = false;
  ipv4_ip_ = 0;
  status_ = kStatusStopped;
  memset(public_key_, 0, sizeof(public_key_));
}

TunsafeBackend::~TunsafeBackend() {
  
}


TunsafeBackendWin32::TunsafeBackendWin32(Delegate *delegate) : delegate_(delegate), dns_resolver_(&dns_blocker_) {
  memset(&stats_, 0, sizeof(stats_));
  wg_processor_ = NULL;
  InitPacketMutexes();
  worker_thread_ = NULL;
  stop_mode_ = MODE_NONE;
  last_tun_adapter_failed_ = 0;
  want_periodic_stats_ = false;

  internet_route_blocking_state = ROUTE_BLOCK_UNKNOWN;
  ClearInternetFwBlockingStateCache();

  delegate_->OnStateChanged();
}

TunsafeBackendWin32::~TunsafeBackendWin32() {
  StopInner(false);
}

bool TunsafeBackendWin32::Initialize() {
  // it's always initialized
  
  return true;
}

void TunsafeBackendWin32::Teardown() {

}


void TunsafeBackendWin32::RequestStats(bool enable) {
  want_periodic_stats_ = enable;
  PushStats();
}

void TunsafeBackendWin32::PushStats() {
  if (want_periodic_stats_) {
    stats_mutex_.Acquire();
    WgProcessorStats stats = stats_;
    stats_mutex_.Release();
    delegate_->OnGetStats(stats);
  }
}

void TunsafeBackendWin32::Stop() {
  StopInner(false);
  delegate_->OnStatusCode(status_);
  delegate_->OnStateChanged();
}

void TunsafeBackendWin32::Start(const char *config_file) {
  StopInner(true);
  stop_mode_ = MODE_NONE; // this needs to be here cause it's not reset on config file errors
  dns_resolver_.SetAbortFlag(false);
  is_started_ = true;
  memset(public_key_, 0, sizeof(public_key_));
  status_ = kStatusInitializing;
  delegate_->OnStatusCode(kStatusInitializing);
  delegate_->OnClearLog();
  DWORD thread_id;
  config_file_ = _strdup(config_file);
  worker_thread_ = CreateThread(NULL, 0, &WorkerThread, this, 0, &thread_id);
  SetThreadPriority(worker_thread_, THREAD_PRIORITY_ABOVE_NORMAL);
  delegate_->OnStateChanged();
}

void TunsafeBackendWin32::TunAdapterFailed() {
  InterlockedExchange(&stop_mode_, MODE_TUN_FAILED);
  QueueUserAPC(&ExitServiceAPC, worker_thread_, NULL);
}

void TunsafeBackendWin32::StopInner(bool is_restart) {
  if (worker_thread_) {
    ipv4_ip_ = 0;
    dns_resolver_.SetAbortFlag(true);
    InterlockedExchange(&stop_mode_, is_restart ? MODE_RESTART : MODE_EXIT);
    QueueUserAPC(&ExitServiceAPC, worker_thread_, NULL);
    WaitForSingleObject(worker_thread_, INFINITE);
    CloseHandle(worker_thread_);
    worker_thread_ = NULL;
    free(config_file_);
    config_file_ = NULL;
    is_started_ = false;
    status_ = kStatusStopped;
  }
}

void TunsafeBackendWin32::ResetStats() {
}

LinearizedGraph *TunsafeBackendWin32::GetGraph(int type) {
  if (type < 0 || type >= 4)
    return NULL;
  
  size_t size = sizeof(LinearizedGraph) + 2 * (sizeof(uint32) + sizeof(float) * 120);
  LinearizedGraph *graph = (LinearizedGraph *)malloc(size);
  if (graph) {
    graph->total_size = (uint32)size;
    graph->num_charts = 2;
    graph->graph_type = type;
    memset(graph->reserved, 0, sizeof(graph->reserved));
    stats_mutex_.Acquire();

    uint8 *ptr = (uint8*)(graph + 1);
    for (size_t i = 0; i < 2; i++) {
      *(uint32*)ptr = 120;
      ptr += 4;
      const StatsCollector::TimeSeries *series = stats_collector_.GetTimeSeries((int)i, type);
      memcpy(postinc(ptr, (series->size - series->shift) * sizeof(float)),
             series->data + series->shift,
             (series->size - series->shift) * sizeof(float));
      memcpy(postinc(ptr, series->shift * sizeof(float)), series->data, series->shift * sizeof(float));
    }
    stats_mutex_.Release();
  }
  return graph;
}


static uint8 GetInternetRouteBlockingState() {
  if (internet_route_blocking_state == ROUTE_BLOCK_UNKNOWN) {
    RouteInfo ri;
    internet_route_blocking_state =
      (GetDefaultRouteAndDeleteOldRoutes(AF_INET, NULL, TRUE, NULL, &ri) && ri.found_null_routes == 2) + ROUTE_BLOCK_OFF;
  }
  return internet_route_blocking_state;
}

static void SetInternetRouteBlockingState(bool want) {
  if (want) {
    internet_route_blocking_state = ROUTE_BLOCK_PENDING;
  } else if (internet_route_blocking_state != ROUTE_BLOCK_OFF) {
    RouteInfo ri;
    GetDefaultRouteAndDeleteOldRoutes(AF_INET, NULL, FALSE, NULL, &ri);
    GetDefaultRouteAndDeleteOldRoutes(AF_INET6, NULL, FALSE, NULL, &ri);
    internet_route_blocking_state = ROUTE_BLOCK_OFF;
  }
}

static InternetBlockState GetInternetBlockState(bool *is_activated) {
  int a = GetInternetRouteBlockingState();
  int b = GetInternetFwBlockingState();

  if (is_activated)
    *is_activated = (a == ROUTE_BLOCK_ON || b == IBS_ACTIVE);

  return (InternetBlockState)(
    (a >= ROUTE_BLOCK_ON) * kBlockInternet_Route +
    (b >= IBS_ACTIVE) * kBlockInternet_Firewall);
}

InternetBlockState TunsafeBackendWin32::GetInternetBlockState(bool *is_activated) {
  return ::GetInternetBlockState(is_activated);
}

void TunsafeBackendWin32::SetInternetBlockState(InternetBlockState s) {
  SetInternetRouteBlockingState((s & kBlockInternet_Route) != 0);
  SetInternetFwBlockingState((s & kBlockInternet_Firewall) != 0);
}

void TunsafeBackendWin32::SetServiceStartupFlags(uint32 flags) {
  // not used
}

std::string TunsafeBackendWin32::GetConfigFileName() {
  return std::string();
}

void TunsafeBackendWin32::OnConnected() {
  if (status_ != TunsafeBackend::kStatusConnected) {
    ipv4_ip_ = ReadBE32(wg_processor_->tun_addr().addr);
    if (status_ != TunsafeBackend::kStatusReconnecting) {
      char buf[kSizeOfAddress];
      RINFO("Connection established. IP %s", print_ip_prefix(buf, AF_INET, wg_processor_->tun_addr().addr, -1));
    }
    status_ = TunsafeBackend::kStatusConnected;
    delegate_->OnStatusCode(TunsafeBackend::kStatusConnected);
  }
}

void TunsafeBackendWin32::OnConnectionRetry(uint32 attempts) {
  if (status_ == TunsafeBackend::kStatusInitializing) {
    status_ = TunsafeBackend::kStatusConnecting;
    delegate_->OnStatusCode(TunsafeBackend::kStatusConnecting);
  } else if (attempts >= 3 && status_ == TunsafeBackend::kStatusConnected) {
    status_ = TunsafeBackend::kStatusReconnecting;
    delegate_->OnStatusCode(TunsafeBackend::kStatusReconnecting);
  }
}

void TunsafeBackend::Delegate::DoWork() {
  // implemented by subclasses
}

TunsafeBackendDelegateThreaded::TunsafeBackendDelegateThreaded(TunsafeBackend::Delegate *delegate, const std::function<void(void)> &callback) {
  callback_ = callback;
  delegate_ = delegate;
}

TunsafeBackendDelegateThreaded::~TunsafeBackendDelegateThreaded() {
  for (auto it = incoming_entry_.begin(); it != incoming_entry_.end(); ++it)
    FreeEntry(&*it);
}

void TunsafeBackendDelegateThreaded::FreeEntry(Entry *e) {
  if (e->lparam) {
    free((void*)e->lparam);
    e->lparam = NULL;
  }
}

void TunsafeBackendDelegateThreaded::DoWork() {
  mutex_.Acquire();
  std::swap(incoming_entry_, processing_entry_);
  mutex_.Release();
  TunsafeBackend::Delegate *delegate = delegate_;
  for (auto it = processing_entry_.begin(); it != processing_entry_.end(); ++it) {
    switch (it->which) {
      case Id_OnGetStats:         delegate->OnGetStats(*(WgProcessorStats*)it->lparam); break;
      case Id_OnStateChanged:     delegate->OnStateChanged(); break;
      case Id_OnLogLine:          delegate->OnLogLine((const char**)&it->lparam); break;
      case Id_OnStatusCode:       delegate->OnStatusCode((TunsafeBackend::StatusCode)it->wparam); break;
      case Id_OnClearLog:         delegate->OnClearLog(); break;
      case Id_OnGraphAvailable:   delegate->OnGraphAvailable(); break;
    }
    FreeEntry(&*it);
  } 
  processing_entry_.clear();
}

void TunsafeBackendDelegateThreaded::AddEntry(Which which, intptr_t lparam, uint32 wparam) {
  mutex_.Acquire();
  bool was_empty = incoming_entry_.empty();
  incoming_entry_.emplace_back(which, wparam, lparam);
  mutex_.Release();
  if (was_empty)
    callback_();
}

void TunsafeBackendDelegateThreaded::OnGetStats(const WgProcessorStats &stats) {
  AddEntry(Id_OnGetStats, (intptr_t)memdup(&stats, sizeof(stats)));
}

void TunsafeBackendDelegateThreaded::OnGraphAvailable() {
  AddEntry(Id_OnGraphAvailable);
}

void TunsafeBackendDelegateThreaded::OnStateChanged() {
  AddEntry(Id_OnStateChanged);
}

void TunsafeBackendDelegateThreaded::OnLogLine(const char **s) {
  const char *ss = *s;
  *s = NULL;
  AddEntry(Id_OnLogLine, (intptr_t)ss);
}

void TunsafeBackendDelegateThreaded::OnStatusCode(TunsafeBackend::StatusCode status) {
  AddEntry(Id_OnStatusCode, 0, status);
}

void TunsafeBackendDelegateThreaded::OnClearLog() {
  AddEntry(Id_OnClearLog);
}

TunsafeBackend::Delegate::~Delegate() {
}

TunsafeBackend *CreateNativeTunsafeBackend(TunsafeBackend::Delegate *delegate) {
  return new TunsafeBackendWin32(delegate);
}
 
TunsafeBackend::Delegate *CreateTunsafeBackendDelegateThreaded(TunsafeBackend::Delegate *delegate, const std::function<void(void)> &callback) {
  return new TunsafeBackendDelegateThreaded(delegate, callback);
}

///////////////////////////////////////////////////

void StatsCollector::Init() {
  Accumulator *acc = &accum_[0][0];
  static const int kAccMax[TIMEVALS] = {5, 6, 10, 0};

  // Initialize all stats channels
  for (uint32 channel = 0; channel != CHANNELS; channel++) {
    for (uint32 timeval = 0; timeval != TIMEVALS; timeval++, acc++) {
      acc->acc = 0;
      acc->dirty = false;
      acc->acc_count = 0;
      acc->acc_max = kAccMax[timeval];
      acc->data.size = 120;
      acc->data.data = (float*)calloc(sizeof(float), acc->data.size);
      acc->data.shift = 0;
    }
  }
}

void StatsCollector::AddToGraphDataSource(StatsCollector::TimeSeries *ts, float value) {
  ts->data[ts->shift] = value;
  if (++ts->shift == ts->size)
    ts->shift = 0;
}

void StatsCollector::AddToAccumulators(StatsCollector::Accumulator *acc, float rval) {
  for (;;) {
    AddToGraphDataSource(&acc->data, rval);
    acc->dirty = true;
    acc->acc += rval;
    if (acc->acc_max == 0 || ++acc->acc_count < acc->acc_max)
      break;
    rval = acc->acc / (float)acc->acc_count;
    acc->acc_count = 0;
    acc->acc = 0.0f;
    acc++;
  }
}

void StatsCollector::AddSamples(float data[CHANNELS]) {
  for (size_t i = 0; i < CHANNELS; i++)
    AddToAccumulators(&accum_[i][0], data[i]);
}

