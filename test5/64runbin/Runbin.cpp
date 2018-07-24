// Runbin.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <intrin.h>
#include "../64hhl_ring3_utility/64shellcode.h"


static _ShellData  ShellData4;
typedef void (*FUNCPTR)(); 
int main(int argc, char **argv)
{
	FUNCPTR func;
	void *buf;
	int fd, len;
	int debug;
	char *filename;
	DWORD oldProtect;

	if (argc == 3 && strlen(argv[1]) == 2 && strncmp(argv[1], "-d", 2) == 0) {
		debug = 1;
		filename = argv[2];
	} else if (argc == 2) {
		debug = 0;
		filename = argv[1];
	} else {
		fprintf(stderr, "usage: runbin [-d] <filename>\n");
		fprintf(stderr, "  -d    insert debugger breakpoint\n");
		return 1;
	}

	fd = _open(filename, _O_RDONLY | _O_BINARY);

	if (-1 == fd) {
		perror("Error opening file");
		return 1;
	}

	len = _filelength(fd);

	if (-1 == len) {
		perror("Error getting file size");
		return 1;
	}
//PVOID pData = VirtualAlloc(NULL,iFun1Size,MEM_COMMIT,PAGE_EXECUTE_READWRITE);  
//	buf = malloc(len);

	buf = VirtualAlloc(NULL,len,MEM_COMMIT,PAGE_EXECUTE_READWRITE);  

	if (NULL == buf) {
		perror("Error allocating memory");
		return 1;
	}

	if (0 == VirtualProtect(buf, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "Error setting memory executable: error code %d\n", GetLastError());
		return 1;
	}        

	if (len != _read(fd, buf, len)) {
		perror("error reading from file");
		return 1;
	}

	func = (FUNCPTR)buf;

	if (debug) {
		__debugbreak();
	}
//	DebugBreak();
	func();
	while(true)
	{
		Sleep(3600);
	}
	

	return 0;
}
