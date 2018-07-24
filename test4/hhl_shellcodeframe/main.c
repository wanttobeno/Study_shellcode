#include "shellcode.h"
#include "shellcode_ntapi_utility.h"
#include "nativeapi.h"


#pragma comment(linker, "/section:.data,RWE")

extern TShellData  ShellData;

void main()
{

#ifdef  HHL_DEBUG
	InitApiHashToStruct();
	ShellCode_Start();

#else
	InitApiHashToStruct();
#endif
}

