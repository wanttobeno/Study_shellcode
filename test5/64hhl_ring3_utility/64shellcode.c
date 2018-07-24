#include "64shellcode.h"
#include "64shellcode_ntapi_utility.h"
#include "64nativeapi.h"



TShellData  ShellData;

#define	 Shellcode_Final_Start		ShellCode_Start
#define  Shellcode_Final_End		MyShellCodeFinalEnd



#ifdef HHL_DEBUG
PShellData lpData=  (PShellData)(&ShellData); //调试模式要指向我们初始化好了的静态全局结构体 ShellData
#else

#endif



void ShellCode_Start()
{
	AlignRSPAndCallShEntry();
}


PVOID ShellCode_Entry()
{
	char hhl[]={'h','e','l','l','o','h','h','l',0};
#ifndef HHL_DEBUG
	PShellData 	lpData= (PShellData)((ULONG64)Shellcode_Final_End);//生成shellcode时候恢复回来
#endif
	GetRing3ApiAddr();
	lpData->xOutputDebugStringA(hhl);


	return (PVOID)lpData;
}





DWORD GetRolHash(char *lpszBuffer)
{
	DWORD dwHash = 0;
	while(*lpszBuffer)
	{
		dwHash = (	(dwHash <<25 ) | (dwHash>>7) );
		dwHash = dwHash+*lpszBuffer;
		lpszBuffer++;
	}
	return dwHash;
}


FARPROC Hash_GetProcAddress(HMODULE hModuleBase,DWORD dwNameHash,PVOID lpGetAddr)
{
	FARPROC							pRet = NULL;
	TGetProcAddress 				xGetProcAddress;
	PIMAGE_DOS_HEADER				lpDosHeader;
	PIMAGE_NT_HEADERS				lpNtHeaders;
	PIMAGE_EXPORT_DIRECTORY			lpExports;
	PWORD							lpwOrd;
	PDWORD							lpdwFunName;
	PDWORD							lpdwFunAddr;
	DWORD							dwLoop;

	lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
	if(lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return pRet;

	lpNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)hModuleBase + lpDosHeader->e_lfanew);

	if(lpNtHeaders->Signature != IMAGE_NT_SIGNATURE) return pRet;

	if(!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) return pRet;
	if(!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return pRet;

	lpExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)hModuleBase + (DWORD)lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if(!lpExports->NumberOfNames) return pRet;

	lpdwFunName = (PDWORD)((DWORD64)hModuleBase + (DWORD)lpExports->AddressOfNames);

	lpwOrd = (PWORD)((DWORD64)hModuleBase + (DWORD)lpExports->AddressOfNameOrdinals);

	lpdwFunAddr = (PDWORD)((DWORD64)hModuleBase + (DWORD)lpExports->AddressOfFunctions);

	for(dwLoop=0;dwLoop<lpExports->NumberOfNames - 1;dwLoop++)
	{


		if(GetRolHash( (char *)(lpdwFunName[dwLoop] + (DWORD64)hModuleBase)) == dwNameHash )
		{
			if(lpGetAddr)
			{
				xGetProcAddress = (TGetProcAddress)lpGetAddr;
				pRet = xGetProcAddress(hModuleBase, (char *)(lpwOrd[dwLoop] + (DWORD)lpExports->Base));
			}
			else
			{

				pRet = (FARPROC)(lpdwFunAddr[lpwOrd[dwLoop]] + (DWORD64)hModuleBase);
			}
			break;
		}
	}
	return pRet;
}




void GetRing3ApiAddr()
{
	HMODULE 	hModuleBase;
	HMODULE		hNtdllBase;
	HANDLE      hPsapiBase;
	HANDLE		hAdvapi32;
	DWORD   dw_temp_hash=0;
	char advapi32[]={'a','d','v','a','p','i','3','2','.','d','l','l',0};
	char psapi[]={'p','s','a','p','i','.','d','l','l',0};
#ifndef HHL_DEBUG
	PShellData 	lpData= (PShellData)((ULONG64)Shellcode_Final_End);//生成shellcode时候恢复回来
#endif

	hModuleBase = (HMODULE)get_kernel32_peb_64();
	lpData->base_ker32=hModuleBase;
	hNtdllBase	=(HMODULE)get_ntdll_peb_64();
	lpData->base_ntdll=hNtdllBase;



	lpData->xGetProcAddress = (TGetProcAddress) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xGetProcAddress, NULL);
	lpData->xLoadLibraryA =(TLoadLibraryA) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xLoadLibraryA, lpData->xGetProcAddress);
	hPsapiBase=(lpData->xLoadLibraryA)(psapi);// Get Psapi.dll Module Base   如果注入的时机太早这里可能会出问题 load psapi 加载不进来
	hAdvapi32=(lpData->xLoadLibraryA)(advapi32);// Get advapi32.dll Module Base   如果注入的时机太早这里可能会出问题 load psapi 加载不进来	
	lpData->base_psapi=hPsapiBase;
	lpData->base_advapi32=hAdvapi32;
	lpData->xRegCreateKeyExW=(TRegCreateKeyExW)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegCreateKeyExW,lpData->xGetProcAddress);
	lpData->xRegSetValueExW=(TRegSetValueExW)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegSetValueExW,lpData->xGetProcAddress);
	lpData->xRegSetValueExA=(TRegSetValueExA)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegSetValueExA,lpData->xGetProcAddress);
	lpData->xRegCloseKey=(TRegCloseKey)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegCloseKey,lpData->xGetProcAddress);
	lpData->xRegOpenKeyA=(TRegOpenKeyA)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegOpenKeyA,lpData->xGetProcAddress);
	lpData->xRegOpenKeyExA=(TRegOpenKeyExA)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegOpenKeyExA,lpData->xGetProcAddress);
	lpData->xRegQueryValueExA=(TRegQueryValueExA)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegQueryValueExA,lpData->xGetProcAddress);
	lpData->xRegQueryValueExW=(TRegQueryValueExW)Hash_GetProcAddress(hAdvapi32,(DWORD)lpData->xRegQueryValueExW,lpData->xGetProcAddress);


	lpData->xGetProcessImageFileNameA=(TGetProcessImageFileNameA)Hash_GetProcAddress(hPsapiBase,(DWORD)lpData->xGetProcessImageFileNameA,lpData->xGetProcAddress);

	lpData->xCreateFileA=(TCreateFileA)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xCreateFileA,lpData->xGetProcAddress);
	lpData->xCreateFileW=(TCreateFileW)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xCreateFileW,lpData->xGetProcAddress);
	lpData->xCreateFileMappingA=(TCreateFileMappingA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateFileMappingA,lpData->xGetProcAddress);
	lpData->xCloseHandle=(TCloseHandle)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCloseHandle,lpData->xGetProcAddress);
	lpData->xCreateToolhelp32Snapshot=(TCreateToolhelp32Snapshot)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateToolhelp32Snapshot,lpData->xGetProcAddress);
	lpData->xCheckRemoteDebuggerPresent=(TCheckRemoteDebuggerPresent)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCheckRemoteDebuggerPresent,lpData->xGetProcAddress);
	lpData->xCreateHardLinkA=(TCreateHardLinkA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateHardLinkA,lpData->xGetProcAddress);
	lpData->xCreateHardLinkW=(TCreateHardLinkW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateHardLinkW,lpData->xGetProcAddress);
	lpData->xCreateDirectoryA=(TCreateDirectoryA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateDirectoryA,lpData->xGetProcAddress);
	lpData->xCreateDirectoryW=(TCreateDirectoryW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateDirectoryW,lpData->xGetProcAddress);


	lpData->xCopyFileA=(TCopyFileA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCopyFileA,lpData->xGetProcAddress);
	lpData->xCopyFileW=(TCopyFileW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCopyFileW,lpData->xGetProcAddress);

	lpData->xDeleteFileA=(TDeleteFileA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xDeleteFileA,lpData->xGetProcAddress);
	lpData->xDeleteFileW=(TDeleteFileW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xDeleteFileW,lpData->xGetProcAddress);

	lpData->xFindResourceA=(TFindResourceA)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xFindResourceA,lpData->xGetProcAddress);

	lpData->xGlobalFree=(TGlobalFree)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xGlobalFree,lpData->xGetProcAddress);
	lpData->xGetCurrentProcess=(TGetCurrentProcess)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetCurrentProcess,lpData->xGetProcAddress);	
	lpData->xGetFileSize=(TGetFileSize)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetFileSize,lpData->xGetProcAddress);
	lpData->xGetProcessHeap=(TGetProcessHeap)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetProcessHeap,lpData->xGetProcAddress);
	lpData->xGetSystemDirectoryA=(TGetSystemDirectoryA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetSystemDirectoryA,lpData->xGetProcAddress);
	lpData->xGetSystemDirectoryW=(TGetSystemDirectoryW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetSystemDirectoryW,lpData->xGetProcAddress);
	lpData->xGetModuleHandleA=(TGetModuleHandleA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetModuleHandleA,lpData->xGetProcAddress);
	lpData->xGetLastError=(TGetLastError)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetLastError,lpData->xGetProcAddress);
	lpData->xGetStartupInfoA=(TGetStartupInfoA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetStartupInfoA,lpData->xGetProcAddress);
	lpData->xGetTickCount=(TGetTickCount)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetTickCount,lpData->xGetProcAddress);
	lpData->xGetCurrentProcessId=(TGetCurrentProcessId)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetCurrentProcessId,lpData->xGetProcAddress);
	lpData->xGetNativeSystemInfo=(TGetNativeSystemInfo)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetNativeSystemInfo,lpData->xGetProcAddress);
	lpData->xGetModuleFileNameA=(TGetModuleFileNameA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetModuleFileNameA,lpData->xGetProcAddress);
	lpData->xGetShortPathNameA=(TGetShortPathNameA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetShortPathNameA,lpData->xGetProcAddress);
	lpData->xGetEnvironmentVariableA=(TGetEnvironmentVariableA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetEnvironmentVariableA,lpData->xGetProcAddress);
	lpData->xGetEnvironmentVariableW=(TGetEnvironmentVariableW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetEnvironmentVariableW,lpData->xGetProcAddress);
	lpData->xGetPrivateProfileStringA=(TGetPrivateProfileStringA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetPrivateProfileStringA,lpData->xGetProcAddress);
	lpData->xGetPrivateProfileStringW=(TGetPrivateProfileStringW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetPrivateProfileStringW,lpData->xGetProcAddress);

	lpData->xHeapAlloc=(THeapAlloc)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xHeapAlloc,lpData->xGetProcAddress);
	lpData->xHeapFree=(THeapFree)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xHeapFree,lpData->xGetProcAddress);

	lpData->xIsDebuggerPresent=(TIsDebuggerPresent)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xIsDebuggerPresent,lpData->xGetProcAddress);

	lpData->xLoadResource=(TLoadResource)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xLoadResource,lpData->xGetProcAddress);
	lpData->xLockResource=(TLockResource)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xLockResource,lpData->xGetProcAddress);

	lpData->xMoveFileA=(TMoveFileA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMoveFileA,lpData->xGetProcAddress);
	lpData->xMoveFileW=(TMoveFileW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMoveFileW,lpData->xGetProcAddress);
	lpData->xMoveFileExA=(TMoveFileExA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMoveFileExA,lpData->xGetProcAddress);
	lpData->xMoveFileExW=(TMoveFileExW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMoveFileExW,lpData->xGetProcAddress);

	lpData->xMapViewOfFile=(TMapViewOfFile)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMapViewOfFile,lpData->xGetProcAddress);
	lpData->xMultiByteToWideChar=(TMultiByteToWideChar)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xMultiByteToWideChar,lpData->xGetProcAddress);

	lpData->xNtCreateFile=(TNtCreateFile)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xNtCreateFile,lpData->xGetProcAddress);

	lpData->xOutputDebugStringA =(TOutputDebugStringA) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xOutputDebugStringA,lpData->xGetProcAddress);
	lpData->xOpenProcess =(TOpenProcess) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xOpenProcess,lpData->xGetProcAddress);

	lpData->xProcess32First =(TProcess32First) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xProcess32First,lpData->xGetProcAddress);
	lpData->xProcess32Next =(TProcess32Next) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xProcess32Next,lpData->xGetProcAddress);

	lpData->xReadFile=(TReadFile)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xReadFile,lpData->xGetProcAddress);
	lpData->xRtlInitAnsiString=(TRtlInitAnsiString)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlInitAnsiString,lpData->xGetProcAddress);
	lpData->xRtlAnsiStringToUnicodeString=(TRtlAnsiStringToUnicodeString)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlAnsiStringToUnicodeString,lpData->xGetProcAddress);
	lpData->xRtlAllocateHeap=(TRtlAllocateHeap)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlAllocateHeap,lpData->xGetProcAddress);
	lpData->xRtlFreeHeap=(TRtlFreeHeap)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlFreeHeap,lpData->xGetProcAddress);
	lpData->xRtlGetVersion=(TRtlGetVersion)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlGetVersion,lpData->xGetProcAddress);//xRtlFreeUnicodeString
	lpData->xRtlFreeUnicodeString=(TRtlFreeUnicodeString)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlFreeUnicodeString,lpData->xGetProcAddress);
	lpData->xRtlZeroMemory=(TRtlZeroMemory)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlZeroMemory,lpData->xGetProcAddress);
	lpData->xRtlImageDirectoryEntryToData=(TRtlImageDirectoryEntryToData)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlImageDirectoryEntryToData,lpData->xGetProcAddress);

	lpData->xRtlFormatCurrentUserKeyPath=(TRtlFormatCurrentUserKeyPath)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xRtlFormatCurrentUserKeyPath,lpData->xGetProcAddress);
	lpData->xReadProcessMemory=(TReadProcessMemory)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xReadProcessMemory,lpData->xGetProcAddress);

	lpData->xSizeofResource=(TSizeofResource)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xSizeofResource,lpData->xGetProcAddress);
	lpData->xSleep=(TSleep)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xSleep,lpData->xGetProcAddress);
	lpData->xSetFilePointer=(TSetFilePointer)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xSetFilePointer,lpData->xGetProcAddress);

	lpData->xUnmapViewOfFile=(TUnmapViewOfFile)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xUnmapViewOfFile,lpData->xGetProcAddress);

	lpData->xVirtualAlloc=(TVirtualAlloc)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualAlloc,lpData->xGetProcAddress);
	lpData->xVirtualFree=(TVirtualFree)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualFree,lpData->xGetProcAddress);

	lpData->xVirtualAllocEx=(TVirtualAllocEx)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualAllocEx,lpData->xGetProcAddress);
	lpData->xVirtualFreeEx=(TVirtualFreeEx)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualFreeEx,lpData->xGetProcAddress);
	lpData->xVirtualProtectEx=(TVirtualProtectEx)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualProtectEx,lpData->xGetProcAddress);
	lpData->xVirtualProtect=(TVirtualProtect)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xVirtualProtect,lpData->xGetProcAddress);

	lpData->xWideCharToMultiByte=(TWideCharToMultiByte)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xWideCharToMultiByte,lpData->xGetProcAddress);
	lpData->xWriteFile=(TWriteFile)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xWriteFile,lpData->xGetProcAddress);
	lpData->xWinExec=(TWinExec)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xWinExec,lpData->xGetProcAddress);
	lpData->xWriteProcessMemory=(TWriteProcessMemory)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xWriteProcessMemory,lpData->xGetProcAddress);

	lpData->xZwQuerySystemInformation=(TZwQuerySystemInformation)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xZwQuerySystemInformation,lpData->xGetProcAddress);
}


void InitApiHashToStruct()
{

	HANDLE hFile;
	DWORD dwBytes, dwSize,dwShellCodeSize,dwsize2;
	PUCHAR lpBuffer;
	DWORD dw_error=0;
	BOOL   b1=0;


	ZeroMemory(&ShellData,sizeof(TShellData));

	//填充函数名字字符串的hash到 ShellData全局结构体里面  
	ShellData.xCreateFileA=(TCreateFileA)0x94e43293;//
	ShellData.xCreateFileW=(TCreateFileW)0x94e432a9;
	ShellData.xCreateFileMappingA=(TCreateFileMappingA)0x014b19c2;
	ShellData.xCloseHandle=(TCloseHandle)0xff0d6657;//
	ShellData.xCreateToolhelp32Snapshot=(TCreateToolhelp32Snapshot)0x3cc0153d;
	ShellData.xCheckRemoteDebuggerPresent=(TCheckRemoteDebuggerPresent)0x1a2789fe;
	ShellData.xCreateHardLinkA=(TCreateHardLinkA)0x77a742b;
	ShellData.xCreateHardLinkW=(TCreateHardLinkW)0x77a7441;
	ShellData.xCopyFileA=(TCopyFileA)0x7eb0fb1;
	ShellData.xCopyFileW=(TCopyFileW)0x7eb0fc7;
	ShellData.xCreateDirectoryA=(TCreateDirectoryA)0xa66b05d4;
	ShellData.xCreateDirectoryW=(TCreateDirectoryW)0xa66b05ea;

	ShellData.xDeleteFileA=(TDeleteFileA)0x98e63979;
	ShellData.xDeleteFileW=(TDeleteFileW)0x98e6398f;

	ShellData.xFindResourceA=(TFindResourceA)0x83ceca69;

	ShellData.xGlobalFree=(TGlobalFree)0x048223c0;
	ShellData.xGetProcAddress = (TGetProcAddress)0xbbafdf85;
	ShellData.xGetCurrentProcess=(TGetCurrentProcess)0x3a2fe6bb;
	ShellData.xGetFileSize=(TGetFileSize)0xac0a138e;
	ShellData.xGetProcessHeap=(TGetProcessHeap)0x80ae9074;
	ShellData.xGetSystemDirectoryA=(TGetSystemDirectoryA)0x8e6902b2;
	ShellData.xGetSystemDirectoryW=(TGetSystemDirectoryW)0x8e6902c8;
	ShellData.xGetModuleHandleA=(TGetModuleHandleA)0xf4e2f2b2;
	ShellData.xGetProcessImageFileNameA=(TGetProcessImageFileNameA)0x34ef0e5a;
	ShellData.xGetLastError=(TGetLastError)0x12f461bb;
	ShellData.xGetStartupInfoA=(TGetStartupInfoA)0x8fb53455;
	ShellData.xGetTickCount=(TGetTickCount)0xed04519b;
	ShellData.xGetCurrentProcessId=(TGetCurrentProcessId)0x2cece924;
	ShellData.xGetNativeSystemInfo=(TGetNativeSystemInfo)0x8a1fb2a8;
	ShellData.xGetModuleFileNameA=(TGetModuleFileNameA)0xb4ffafed;
	ShellData.xGetShortPathNameA=(TGetShortPathNameA)0xe72d6895;
	ShellData.xGetEnvironmentVariableA=(TGetEnvironmentVariableA)0xec496a9e;
	ShellData.xGetEnvironmentVariableW=(TGetEnvironmentVariableW)0xec496ab4;
	ShellData.xGetPrivateProfileStringA=(TGetPrivateProfileStringA)0x8f9ded68;
	ShellData.xGetPrivateProfileStringW=(TGetPrivateProfileStringW)0x8f9ded7e;


	ShellData.xHeapAlloc=(THeapAlloc)0xf8262c81;
	ShellData.xHeapFree=(THeapFree)0x052e3772;
	
	ShellData.xIsDebuggerPresent=(TIsDebuggerPresent)0xb483154;

	ShellData.xLoadResource=(TLoadResource)0xff951427;
	ShellData.xLockResource=(TLockResource)0xff951b2b;
	ShellData.xLoadLibraryA = (TLoadLibraryA)0x0c917432;

	ShellData.xMapViewOfFile=(TMapViewOfFile)0x9aa5f07d;
	ShellData.xMultiByteToWideChar=(TMultiByteToWideChar)0x70229207;
	ShellData.xMoveFileA=(TMoveFileA)0x896b19ae;
	ShellData.xMoveFileW=(TMoveFileW)0x896b19c4;
	ShellData.xMoveFileExA=(TMoveFileExA)0x56ca25ee;
	ShellData.xMoveFileExW=(TMoveFileExW)0x56ca2604;

	ShellData.xNtCreateFile=(TNtCreateFile)0x4489294c;

	ShellData.xOutputDebugStringA = (TOutputDebugStringA)0x354c31f2;
	ShellData.xOpenProcess=(TOpenProcess)0x77ce8553;

	ShellData.xProcess32First=(TProcess32First)0xc4446aa6;
	ShellData.xProcess32Next=(TProcess32Next)0x2e255963;

	ShellData.xRtlGetVersion=(TRtlGetVersion)0x4907252b;
	ShellData.xRtlFreeUnicodeString=(TRtlFreeUnicodeString)0x07d63e06;
	ShellData.xRtlZeroMemory=(TRtlZeroMemory)0x555df489;
	ShellData.xRtlInitAnsiString=(TRtlInitAnsiString)0x65c26f71;
	ShellData.xRtlAnsiStringToUnicodeString=(TRtlAnsiStringToUnicodeString)0x199548c2;
	ShellData.xRtlAllocateHeap=(TRtlAllocateHeap)0x8e17053d;
	ShellData.xRtlFreeHeap=(TRtlFreeHeap)0xc839b3b6;
	ShellData.xRtlImageDirectoryEntryToData=(TRtlImageDirectoryEntryToData)0xc1eb7ae3;
	ShellData.xReadFile=(TReadFile)0x130f36b2;
	ShellData.xReadProcessMemory=(TReadProcessMemory)0xd5206133;


	ShellData.xRtlFormatCurrentUserKeyPath=(TRtlFormatCurrentUserKeyPath)0x29640660;
	ShellData.xRegCreateKeyExW=(TRegCreateKeyExW)0xb4b0ad31;
	ShellData.xRegSetValueExW=(TRegSetValueExW)0xd8c0fec0;
	ShellData.xRegCloseKey=(TRegCloseKey)0xe511783;
	ShellData.xRegOpenKeyA=(TRegOpenKeyA)0xf7be46f9;
	ShellData.xRegOpenKeyExA=(TRegOpenKeyExA)0xbf7df3b;
	ShellData.xRegSetValueExA=(TRegSetValueExA)0xd8c0feaa;
	ShellData.xRegQueryValueExA=(TRegQueryValueExA)0x8a2fc67e;
	ShellData.xRegQueryValueExW=(TRegQueryValueExW)0x8a2fc694;

	ShellData.xSizeofResource=(TSizeofResource)0xd90bb0a3;
	ShellData.xSleep=(TSleep)0xcb9765a0;
	ShellData.xSetFilePointer=(TSetFilePointer)0xdbacbe43;

	ShellData.xUnmapViewOfFile=(TUnmapViewOfFile)0xdaa7fe52;

	ShellData.xVirtualAllocEx=(TVirtualAllocEx)0xef9c7bf1;
	ShellData.xVirtualFreeEx=(TVirtualFreeEx)0x3215858b;
	ShellData.xVirtualProtectEx=(TVirtualProtectEx)0x1a7bbe0b;
	ShellData.xVirtualAlloc=(TVirtualAlloc)0x1ede5967;
	ShellData.xVirtualFree=(TVirtualFree)0x6144aa05;
	ShellData.xVirtualProtect=(TVirtualProtect)0xef64a41e;

	ShellData.xWideCharToMultiByte=(TWideCharToMultiByte)0xcb9bd550;
	ShellData.xWriteFile=(TWriteFile)0x741f8dc4;
	ShellData.xWinExec=(TWinExec)0x1a22f51;
	ShellData.xWriteProcessMemory=(TWriteProcessMemory)0x97410f58;

	ShellData.xZwQuerySystemInformation=(TZwQuerySystemInformation)0xeffc1cf8;

#ifndef HHL_DEBUG
	dwSize = (ULONG64)Shellcode_Final_End - (ULONG64)Shellcode_Final_Start;

	dwShellCodeSize = dwSize + sizeof(TShellData);

	lpBuffer = (PUCHAR)GlobalAlloc(GMEM_FIXED,dwShellCodeSize);
	if(lpBuffer)
	{
		CopyMemory(lpBuffer,Shellcode_Final_Start,dwSize);
		CopyMemory(lpBuffer+dwSize,&ShellData,sizeof(TShellData));

		hFile = CreateFileA("64shellcode.bin", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

		if(hFile != INVALID_HANDLE_VALUE)
		{
			if(WriteFile(hFile,lpBuffer,dwShellCodeSize,&dwBytes,NULL))
			{
				printf("Save ShellCode Success.\n");
			}
			CloseHandle(hFile);
		}
		GlobalFree(lpBuffer);
	}
#endif
}


void InitApiAddrToStruct()
{
	InitApiHashToStruct();
	AlignRSPAndCallShEntry();

}

