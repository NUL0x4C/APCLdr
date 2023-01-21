#include <Windows.h>



typedef uint32_t UINT32_T;              // im boojie


#ifndef HELLHALL_H
#define HELLHALL_H


typedef struct _SysFunc {

    PVOID       pInst;          // address of a 'syscall' instruction in ntdll.dll
    PBYTE       pAddress;       // address of the syscall 
    WORD        wSSN;           // syscall number
    UINT32_T    uHash;          // syscall name hash value

}SysFunc, * PSysFunc;


// FROM HellsHall.c
BOOL InitilizeSysFunc(IN UINT32_T uSysFuncHash);
VOID getSysFuncStruct(OUT PSysFunc psF);

// FROM AsmHell.asm
extern VOID SetConfig(WORD wSystemCall, PVOID pSyscallInst);
extern HellHall();


//  A MACRO TO MAKE STUFF CLEANER
#define SYSCALL(sF)(SetConfig(sF.wSSN, sF.pInst))


#endif // !HELLHALL_H







