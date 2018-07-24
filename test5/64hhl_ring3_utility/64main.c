

#include "64shellcode.h"
#include "64shellcode_ntapi_utility.h"
#include "64nativeapi.h"









void main()
{
#ifdef  HHL_DEBUG
	InitApiHashToStruct();
	AlignRSPAndCallShEntry();
#else
	InitApiHashToStruct();
#endif
}









