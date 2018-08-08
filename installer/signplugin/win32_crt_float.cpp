extern "C"
{
    int _fltused;

#ifdef _M_IX86 // following functions are needed only for 32-bit architecture

    __declspec(naked) void _ftol2()
    {
        __asm
        {
            fistp qword ptr [esp-8]
            mov   edx,[esp-4]
            mov   eax,[esp-8]
            ret
        }
    }

    __declspec(naked) void _ftol2_sse()
    {
        __asm
        {
            fistp dword ptr [esp-4]
            mov   eax,[esp-4]
            ret
        }
    }

#if 0 // these functions are needed for SSE code for 32-bit arch, TODO: implement them
    __declspec(naked) void _dtol3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _dtoui3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _dtoul3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _ftol3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _ftoui3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _ftoul3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _ltod3()
    {
        __asm
        {
        }
    }
       

    __declspec(naked) void _ultod3()
    {
        __asm
        {
        }
    }
#endif

#endif

}