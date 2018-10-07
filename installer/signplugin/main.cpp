#include <Windows.h>
extern "C" {
#include "tiny/edsign.h"
#include "nsis/pluginapi.h"
#include "tiny/sha512.h"
}

// To work with Unicode version of NSIS, please use TCHAR-type
// functions for accessing the variables and the stack.
unsigned char buffer[4096];

#include "../../../misc/config/installer_signing_key_pub.h"

int CheckFile(char *file) {
  sha512_state ctx;
  int ret;
  HANDLE h;
  unsigned char out[64];
  unsigned char signature[64];

  h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 1;
  DWORD n;
  sha512_init(&ctx);

  size_t total_size = 0;
  size_t p = 0;
  while (ReadFile(h, buffer, sizeof(buffer), &n, NULL) && n) {
    total_size += n;
    p = 0;
    while (p + 128 <= n) {
      sha512_block(&ctx, buffer + p);
      p += 128;
    }
    if (p != n)
      break;
  }
  sha512_final(&ctx, buffer + p, total_size);
  sha512_get(&ctx, out, 0, 64);
  CloseHandle(h);
  /*
  for (size_t i = 0; i < 64; i++) {
    buffer[i * 2 + 0] = "0123456789abcdef"[out[i] >> 4];
    buffer[i * 2 + 1] = "0123456789abcdef"[out[i] & 0xF];
  }
  buffer[128] = 0;
  MessageBoxA(0, (char*)buffer, "sha", 0);
  */
  char *x = file;
  while (*x)x++;
  memcpy(x, ".sig", 5);

  h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 2;
  n = 0;
  ReadFile(h, buffer, sizeof(buffer), &n, NULL);
  CloseHandle(h);
  if (n < 128)
    return 3;

  memset(signature, 0, sizeof(signature));
  
  for (int i = 0; i < 128; i++) {
    unsigned char c = buffer[i];
    if (c >= '0' && c <= '9')
      c -= '0';
    else if ((c |= 32), c >= 'a' && c <= 'f')
      c -= 'a' - 10;
    else
      return 4;
    signature[i >> 1] = (signature[i >> 1] << 4) + c;
  }

  /* create a random seed, and a keypair out of that seed */
  //ed25519_create_seed(seed);
  //ed25519_create_keypair(public_key, private_key, seed);

  /* create signature on the message with the keypair */
  //ed25519_sign(signature, message, message_len, public_key, private_key);

  /* verify the signature */
  return edsign_verify(signature, pk, out, sizeof(out)) ? 0 : 5;
}

extern "C" void __declspec(dllexport) myFunction(HWND hwndParent, int string_size,
                                      LPTSTR variables, stack_t **stacktop,
                                      extra_parameters *extra, ...) {
  EXDLL_INIT();

  int rv = 10;

  // note if you want parameters from the stack, pop them off in order.
  // i.e. if you are called via exdll::myFunction file.dat read.txt
  // calling popstring() the first time would give you file.dat,
  // and the second time would give you read.txt. 
  // you should empty the stack of your parameters, and ONLY your
  // parameters.

  // do your stuff here
  {
    LPTSTR msgbuf = (LPTSTR)GlobalAlloc(GPTR, (string_size + 1 + 10) * sizeof(*msgbuf));
    if (msgbuf) {
      if (!popstring(msgbuf)) {
        rv = CheckFile(msgbuf);
      }
      GlobalFree(msgbuf);
    }
  }

  pushint(rv);
}


BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ul_reason_for_call, LPVOID lpReserved) {
  return TRUE;
}
