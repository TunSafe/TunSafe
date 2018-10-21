#ifndef TUNSAFE_IPADDR_H_
#define TUNSAFE_IPADDR_H_

#include "tunsafe_types.h"

#if !defined(OS_WIN)
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

union IpAddr {
  sockaddr_in sin;
  sockaddr_in6 sin6;
};

struct WgCidrAddr {
  uint8 addr[16];
  uint8 size;
  uint8 cidr;
};

class DnsResolver;

#define kSizeOfAddress 64
const char *print_ip_prefix(char buf[kSizeOfAddress], int family, const void *ip, int prefixlen);
char *PrintIpAddr(const IpAddr &addr, char buf[kSizeOfAddress]);
char *PrintWgCidrAddr(const WgCidrAddr &addr, char buf[kSizeOfAddress]);

bool ParseCidrAddr(const char *s, WgCidrAddr *out);

enum {
  kParseSockaddrDontDoNAT64 = 1,
};
bool ParseSockaddrInWithPort(const char *s, IpAddr *sin, DnsResolver *resolver, int flags = 0);
bool ParseSockaddrInWithoutPort(char *s, IpAddr *sin, DnsResolver *resolver, int flags = 0);


#endif  // TUNSAFE_IPADDR_H_
