#include <stdio.h>
#include <Windows.h>
#include <time.h>
#include <stdlib.h>

#include "structs.h"

extern PVOID Spoof(PSTACK_INFO);

typedef struct _EXCEPTION_INFO {

	UINT64 hModule;
	UINT64 pExceptionDirectory;
	DWORD dwRuntimeFunctionCount;

}EXCEPTION_INFO, *PEXCEPTION_INFO;

VOID RetExceptionAddress(PEXCEPTION_INFO pExceptionInfo) {

	UINT64 pImgNtHdr, hModule;
	PIMAGE_OPTIONAL_HEADER64 pImgOptHdr;

	hModule = pExceptionInfo->hModule;

	pImgNtHdr = hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew;
	pImgOptHdr = &((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader;

	pExceptionInfo->pExceptionDirectory = hModule + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	pExceptionInfo->dwRuntimeFunctionCount = pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);

}

UINT64 RetStackSize(UINT64 hModule, UINT64 pFuncAddr) {

	EXCEPTION_INFO sExceptionInfo = { 0 };
	sExceptionInfo.hModule = hModule;

	RetExceptionAddress(&sExceptionInfo);

	PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)sExceptionInfo.pExceptionDirectory;
	DWORD dwFuncOffset = pFuncAddr - hModule;
	PUNWIND_INFO pUnwindInfo;
	PUNWIND_CODE pUnwindCode;
	UINT64 dwStackSize = 0;
	

	// Loop Through RunTimeFunction structures until we find the structure for our target function
	for (int i = 0; i < sExceptionInfo.dwRuntimeFunctionCount; i++) {
		if (dwFuncOffset >= pRuntimeFunction->BeginAddress && dwFuncOffset <= pRuntimeFunction->EndAddress) {
			break;
		}

		pRuntimeFunction++;
	}

	// From the RunTimeFunction structure we need the offset to UnwindInfo structure

	pUnwindInfo = ((PUNWIND_INFO)(hModule + pRuntimeFunction->UnwindInfoAddress));

	// Loop Through the UnwindCodes 
	pUnwindCode = pUnwindInfo->UnwindCode; // UnwindCode Array

	for (int i = 0; i < pUnwindInfo->CountOfUnwindCodes; i++) {

		UBYTE bUnwindCode = pUnwindCode[i].UnwindOp;

		switch (bUnwindCode)
		{
		case UWOP_ALLOC_SMALL:
			dwStackSize += (pUnwindCode[i].OpInfo + 1) * 8;
			break;
		case UWOP_PUSH_NONVOL:
			if (pUnwindCode[i].OpInfo == 4)
				return 0;
			dwStackSize += 8;
			break;
		case UWOP_ALLOC_LARGE:
			if (pUnwindCode[i].OpInfo == 0) {
				dwStackSize += pUnwindCode[i + 1].FrameOffset * 8;
				i++;
			}
			else {

				dwStackSize += *(ULONG*)(&pUnwindCode[i + 1]);
				i += 2;

			}
			break;
		case UWOP_PUSH_MACHFRAME:
			if (pUnwindCode[i].OpInfo == 0)
				dwStackSize += 40;
			else
				dwStackSize += 48;
		case UWOP_SAVE_NONVOL:
			i++;
			break;
		case UWOP_SAVE_NONVOL_FAR:
			i += 2;
			break;
		default:
			break;
		}


	}

	return dwStackSize;

}



PVOID RetGadget(UINT64 hModule) {

	PVOID pGadget = NULL;
	int r = rand() % 2, count = 0;
	
	DWORD dwSize = ((PIMAGE_NT_HEADERS64)(hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;

	for (int i = 0; i < dwSize - 1; i++) {

		if (((PBYTE)hModule)[i] == 0xff && ((PBYTE)hModule)[i+1] == 0x23) {
			pGadget = hModule + i;
			if (count >= r) {
				break;
			}
			count ++;
		}
	}
	return pGadget;
}

PVOID CallStackSpoof(UINT64 pTargetFunction, DWORD dwNumberOfArgs, ...) {

	srand((time(0)));
	va_list va_args;
	STACK_INFO sStackInfo = { 0 };
	UINT64 pGadget, pRtlUserThreadStart, pBaseThreadInitThunk;
	UINT64 pNtdll, pKernel32;

	pNtdll = GetModuleHandleA("ntdll");
	pKernel32 = GetModuleHandleA("kernel32");

	pGadget = RetGadget(pKernel32);
	pRtlUserThreadStart = GetProcAddress(pNtdll, "RtlUserThreadStart");
	pBaseThreadInitThunk = GetProcAddress(pKernel32, "BaseThreadInitThunk");

	sStackInfo.pGadgetAddress = pGadget;
	sStackInfo.dwGadgetSize = RetStackSize(pKernel32, pGadget);
	sStackInfo.pRtlUserThreadStart = pRtlUserThreadStart + 0x21;
	sStackInfo.dwRtlUserThreadStartSize = RetStackSize(pNtdll, pRtlUserThreadStart);
	sStackInfo.pBaseThreadInitThunk = pBaseThreadInitThunk + 0x14;
	sStackInfo.dwBaseThreadInitThunk = RetStackSize(pKernel32, pBaseThreadInitThunk);
	sStackInfo.pTargetFunction = pTargetFunction;

	if (dwNumberOfArgs <= 4)
		sStackInfo.dwNumberOfArguments = 4;
	else if (dwNumberOfArgs % 2 != 0)
		sStackInfo.dwNumberOfArguments = dwNumberOfArgs + 1;
	else
		sStackInfo.dwNumberOfArguments = dwNumberOfArgs;

	sStackInfo.pArgs = malloc(8 * sStackInfo.dwNumberOfArguments);

	va_start(va_args, dwNumberOfArgs);
	for (int i = 0; i < dwNumberOfArgs; i++) {

		(&sStackInfo.pArgs)[i] = va_arg(va_args, UINT64);

	}
	va_end(va_args);
	return Spoof(&sStackInfo);

}

