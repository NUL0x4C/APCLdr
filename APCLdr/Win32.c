#include <Windows.h>
#include "Structs.h"
#include "Common.h"

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
    for (volatile int i = 0; i < Size; i++) {
        ((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
    }
    return Destination;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


VOID _ZeroMemory(PVOID Destination, SIZE_T Size) 
{

    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0)
    {
        *Dest = 0;
        Dest++;
        Count--;
    }

    return;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


CHAR _ToUpper(CHAR C) 
{
    if (C >= 'a' && C <= 'z') 
        return C - 'a' + 'A';

    return C;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


UINT32 _CopyDotStr(PCHAR String) 
{
    for (UINT32 i = 0; i < _StrlenA(String); i++)
    {
        if (String[i] == '.')
            return i;
    }
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


SIZE_T _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed) 
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0) {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


SIZE_T _StrlenA(LPCSTR String) 
{

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


SIZE_T _StrlenW(LPCWSTR String)
{

    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

uint32_t _CRC32b(uint8_t* str) {

    uint32_t    byte    = 0x0,
                mask    = 0x0,
                crc     = 0xFFFFFFFF;
    int         i       = 0x0,
                j       = 0x0;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


