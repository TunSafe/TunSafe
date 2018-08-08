#include <string.h>
extern "C"
{
    #pragma function(memset)
    void *memset(void *dest, int c, size_t count)
    {
        char *bytes = (char *)dest;
        while (count--)
        {
            *bytes++ = (char)c;
        }
        return dest;
    }

    #pragma function(memcpy)
    void *memcpy(void *dest, const void *src, size_t count)
    {
        char *dest8 = (char *)dest;
        const char *src8 = (const char *)src;
        while (count--)
        {
            *dest8++ = *src8++;
        }
        return dest;
    }
}
