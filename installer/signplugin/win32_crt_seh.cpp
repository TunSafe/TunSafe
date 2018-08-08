extern "C"
{
#if _M_IX86

EXCEPTION_DISPOSITION
_except_handler3(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    void* EstablisherFrame,
    struct _CONTEXT* ContextRecord,
    void* DispatcherContext)
{
  typedef EXCEPTION_DISPOSITION Function(struct _EXCEPTION_RECORD*, void*, struct _CONTEXT*, void*);
  static Function* FunctionPtr;

  if (!FunctionPtr)
  {
      HMODULE Library = LoadLibraryA("msvcrt.dll");
      FunctionPtr = (Function*)GetProcAddress(Library, "_except_handler3");
  }

  return FunctionPtr(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

UINT_PTR __security_cookie = 0xBB40E64E;

extern PVOID __safe_se_handler_table[];
extern BYTE  __safe_se_handler_count;

typedef struct {
    DWORD       Size;
    DWORD       TimeDateStamp;
    WORD        MajorVersion;
    WORD        MinorVersion;
    DWORD       GlobalFlagsClear;
    DWORD       GlobalFlagsSet;
    DWORD       CriticalSectionDefaultTimeout;
    DWORD       DeCommitFreeBlockThreshold;
    DWORD       DeCommitTotalFreeThreshold;
    DWORD       LockPrefixTable;
    DWORD       MaximumAllocationSize;
    DWORD       VirtualMemoryThreshold;
    DWORD       ProcessHeapFlags;
    DWORD       ProcessAffinityMask;
    WORD        CSDVersion;
    WORD        Reserved1;
    DWORD       EditList;
    PUINT_PTR   SecurityCookie;
    PVOID       *SEHandlerTable;
    DWORD       SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32_2;

const
IMAGE_LOAD_CONFIG_DIRECTORY32_2 _load_config_used = {
    sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32_2),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    &__security_cookie,
    __safe_se_handler_table,
    (DWORD)(DWORD_PTR) &__safe_se_handler_count
};

#elif _M_AMD64

EXCEPTION_DISPOSITION
__C_specific_handler(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    void* EstablisherFrame,
    struct _CONTEXT* ContextRecord,
    struct _DISPATCHER_CONTEXT* DispatcherContext)
{
  typedef EXCEPTION_DISPOSITION Function(struct _EXCEPTION_RECORD*, void*, struct _CONTEXT*, _DISPATCHER_CONTEXT*);
  static Function* FunctionPtr;

  if (!FunctionPtr)
  {
      HMODULE Library = LoadLibraryA("msvcrt.dll");
      FunctionPtr = (Function*)GetProcAddress(Library, "__C_specific_handler");
  }

  return FunctionPtr(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

#endif

}
