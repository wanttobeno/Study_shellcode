﻿#include "shellcode.h"
#include "shellcode_ntapi_utility.h"
#include "nativeapi.h"










TShellData  ShellData;


#define  shellcode_final_end	hellohhl
#define  shellcode_final_start	ShellCode_Start

#ifdef HHL_DEBUG
PShellData lpData=  (PShellData)(&ShellData); //调试模式要指向我们初始化好了的静态全局结构体 ShellData
#else

#endif


__declspec(naked) void ShellCode_Start()
{
	__asm
	{
		jmp ShellCodeEntry
	}
}


__declspec(naked) DWORD get_ntdllbase_peb()
{
	__asm
	{
			mov   eax, fs:[030h]		;	
			test  eax,eax				;   
			js    finished				;
			mov   eax, [eax + 0ch]		;	
			mov   eax, [eax + 14h]		;	
			mov   eax, [eax]			;	
			mov   eax, [eax + 10h]
finished:
		ret
	}
}



__declspec(naked) DWORD get_k32base_peb()
{
	__asm
	{
			mov   eax, fs:[030h]		;	
			test  eax,eax				;  
			js    finished				;	
			mov   eax, [eax + 0ch]		;	
			mov   eax, [eax + 14h]		;	
			mov   eax, [eax]			;	
			mov   eax, [eax]
			mov   eax, [eax + 10h]
finished:
		ret
	}
}


DWORD GetRolHash(char *lpszBuffer)
{
	DWORD dwHash = 0;
	while(*lpszBuffer)
	{
		//		dwHash = ((dwHash << 3) & 0xFFFFFFFF) | (dwHash >> (32 - 3)) ^ (DWORD)(*lpszBuffer);
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
	PIMAGE_NT_HEADERS32				lpNtHeaders;
	PIMAGE_EXPORT_DIRECTORY			lpExports;
	PWORD							lpwOrd;
	PDWORD							lpdwFunName;
	PDWORD							lpdwFunAddr;
	DWORD							dwLoop;
	//检查DOS 的MZ头是不是4D5A
	lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
	if(lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return pRet;

	//获取PE文件头的指针
	lpNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hModuleBase + lpDosHeader->e_lfanew);

	//检查PE的标志 PE头是不是4550
	if(lpNtHeaders->Signature != IMAGE_NT_SIGNATURE) return pRet;

	//用DWORD 强制转换下 免得 不让指针相加
	if(!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) return pRet;
	if(!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return pRet;

	//获得kernel32.dll的导出表的VA  VA=IB+RVA
	lpExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModuleBase + (DWORD)lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//如果没有函数以名字导出就失败了
	if(!lpExports->NumberOfNames) return pRet;

	//指向函数名字符串地址表 是一个dword数组 数组中的每一项指向一个函数名称字符串的RVA
	//数组的项数等于NumberOfNames字段的值   
	lpdwFunName = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNames);

	//指向一个word类型的数组 数组项目与 AddressOfNames中的数组一一对应 项目值代表函数入口地址表的索引
	lpwOrd = (PWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNameOrdinals);

	//一个rva值 指向包含全部导出函数入口地址的dword数组 数组中的每一项都是一个rva值
	//数组的项数等于NumberOfFunctions字段的值
	lpdwFunAddr = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfFunctions);

	for(dwLoop=0;dwLoop<lpExports->NumberOfNames - 1;dwLoop++)
	{


		if(GetRolHash( (char *)(lpdwFunName[dwLoop] + (DWORD)hModuleBase)) == dwNameHash )
		{
			if(lpGetAddr)
			{
				xGetProcAddress = (TGetProcAddress)lpGetAddr;
			//	pRet = xGetProcAddress(hModuleBase, (char *)(lpwOrd[dwLoop] + (DWORD)lpExports->Base));//这里是通过ordinal来取函数地址
			pRet = xGetProcAddress(hModuleBase, (char *)((lpdwFunName[dwLoop] + (DWORD)hModuleBase)));//这里是通过函数名字来取函数地址
			}
			else
			{
				pRet = (FARPROC)(lpdwFunAddr[lpwOrd[dwLoop]] + (DWORD)hModuleBase);
			}
			break;
		}
	}
	return pRet;
}


DWORD ReleaseRebaseShellCode()
{
	DWORD 	dwOffset;
	__asm
	{
		call  GetEIP
GetEIP:
		pop   eax					
			sub   eax, offset GetEIP
			mov   dwOffset, eax
	}
	return dwOffset;
}





PVOID ShellCodeEntry()
{
	char hhl[]={'h','e','l','l','o','g','i','r','l',0};

#ifndef HHL_DEBUG
	//进行shellcode的重定位
	DWORD		offset=ReleaseRebaseShellCode();
	PShellData 	lpData= (PShellData)((DWORD)AsmShellData+offset);//生成shellcode时候恢复回来
#endif
	GetRing3ApiAddr();

	lpData->xOutputDebugStringA(hhl);
	Is64Os();

	return (PVOID)lpData;
}

void GetRing3ApiAddr()
{
	HMODULE 	hModuleBase;
	HMODULE		hNtdllBase;
	HANDLE      hPsapiBase;
	HANDLE		hAdvapi32;
	HANDLE      hUser32;

	DWORD   dw_temp_hash=0;
	char advapi32[]={'a','d','v','a','p','i','3','2','.','d','l','l',0};
	char psapi[]={'p','s','a','p','i','.','d','l','l',0};
	char user32[11] = {
		0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00
	};//user32.dll
#ifndef HHL_DEBUG
	//进行shellcode的重定位
	DWORD		offset=ReleaseRebaseShellCode();
	PShellData 	lpData= (PShellData)((DWORD)AsmShellData+offset);//生成shellcode时候恢复回来
#endif

	hModuleBase = (HMODULE)get_k32base_peb();
	lpData->base_ker32=hModuleBase;
	hNtdllBase	=(HMODULE)get_ntdllbase_peb();
	lpData->base_ntdll=(HMODULE)get_ntdllbase_peb();

	

	lpData->xGetProcAddress = (TGetProcAddress) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xGetProcAddress, NULL);
	lpData->xLoadLibraryA =(TLoadLibraryA) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xLoadLibraryA, lpData->xGetProcAddress);
	hPsapiBase=(lpData->xLoadLibraryA)(psapi);// Get Psapi.dll Module Base   如果注入的时机太早这里可能会出问题 load psapi 加载不进来
	hAdvapi32=(lpData->xLoadLibraryA)(advapi32);// Get advapi32.dll Module Base   如果注入的时机太早这里可能会出问题 load psapi 加载不进来	
	hUser32=(lpData->xLoadLibraryA)(user32);

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

	lpData->xCreateProcessA=(TCreateProcessA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateProcessA,lpData->xGetProcAddress);
	lpData->xCreateProcessW=(TCreateProcessW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCreateProcessW,lpData->xGetProcAddress);

	lpData->xCreateDesktopA=(TCreateDesktopA)Hash_GetProcAddress(hUser32,(DWORD)lpData->xCreateDesktopA,lpData->xGetProcAddress);
	lpData->xCreateDesktopW=(TCreateDesktopW)Hash_GetProcAddress(hUser32,(DWORD)lpData->xCreateDesktopW,lpData->xGetProcAddress);

	lpData->xCopyFileA=(TCopyFileA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCopyFileA,lpData->xGetProcAddress);
	lpData->xCopyFileW=(TCopyFileW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xCopyFileW,lpData->xGetProcAddress);

	lpData->xDeleteFileA=(TDeleteFileA)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xDeleteFileA,lpData->xGetProcAddress);
	lpData->xDeleteFileW=(TDeleteFileW)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xDeleteFileW,lpData->xGetProcAddress);

	lpData->xExitProcess=(TExitProcess)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xExitProcess,lpData->xGetProcAddress);
	//ExitProcess这里是 VS2008 显示的bug
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

	lpData->xGetThreadContext=(TGetThreadContext)Hash_GetProcAddress(hModuleBase,(DWORD)lpData->xGetThreadContext,lpData->xGetProcAddress);


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
	lpData->xOpenThread =(TOpenThread) Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xOpenThread,lpData->xGetProcAddress);

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
	lpData->xSetThreadContext=(TSetThreadContext)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xSetThreadContext,lpData->xGetProcAddress);



	lpData->xThread32First=(TThread32First)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xThread32First,lpData->xGetProcAddress);
	lpData->xThread32Next=(TThread32Next)Hash_GetProcAddress(hModuleBase, (DWORD)lpData->xThread32Next,lpData->xGetProcAddress);


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

	lpData->xZwSuspendProcess=(TZwSuspendProcess)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xZwSuspendProcess,lpData->xGetProcAddress);
	lpData->xZwResumeProcess=(TZwResumeProcess)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xZwResumeProcess,lpData->xGetProcAddress);

	lpData->xZwQuerySystemInformation=(TZwQuerySystemInformation)Hash_GetProcAddress(hNtdllBase,(DWORD)lpData->xZwQuerySystemInformation,lpData->xGetProcAddress);
}
//------------------------------------------------
//|---shellcode---|---TShellData---|---dll文件---|
//------------------------------------------------

void InitApiHashToStruct()
{

	HANDLE hFile;
	DWORD dwBytes, dwSize,dwShellCodeSize,derror,dwOldProtect;
	PUCHAR lpBuffer;
	DWORD dw_error=0;
	BOOL   b1=0;

//	kd> ?? &ShellData

	PShellData lpShData=&ShellData;
	ZeroMemory(&ShellData,sizeof(TShellData));

	lpShData->xCreateFileA=(TCreateFileA)0x94e43293;//
	lpShData->xCreateFileW=(TCreateFileW)0x94e432a9;
	lpShData->xCreateFileMappingA=(TCreateFileMappingA)0x014b19c2;
	lpShData->xCloseHandle=(TCloseHandle)0xff0d6657;//
	lpShData->xCreateToolhelp32Snapshot=(TCreateToolhelp32Snapshot)0x3cc0153d;
	lpShData->xCheckRemoteDebuggerPresent=(TCheckRemoteDebuggerPresent)0x1a2789fe;
	lpShData->xCreateHardLinkA=(TCreateHardLinkA)0x77a742b;
	lpShData->xCreateHardLinkW=(TCreateHardLinkW)0x77a7441;
	lpShData->xCopyFileA=(TCopyFileA)0x7eb0fb1;
	lpShData->xCopyFileW=(TCopyFileW)0x7eb0fc7;
	lpShData->xCreateDirectoryA=(TCreateDirectoryA)0xa66b05d4;
	lpShData->xCreateDirectoryW=(TCreateDirectoryW)0xa66b05ea;
	lpShData->xCreateDesktopA=(TCreateDesktopA)0xe2513549;
	lpShData->xCreateDesktopW=(TCreateDesktopW)0xe251355f;
	lpShData->xCreateProcessA=(TCreateProcessA)0x6ba6bcc9;
	lpShData->xCreateProcessW=(TCreateProcessW)0x6ba6bcdf;

	lpShData->xDeleteFileA=(TDeleteFileA)0x98e63979;
	lpShData->xDeleteFileW=(TDeleteFileW)0x98e6398f;

	lpShData->xExitProcess=(TExitProcess)0x4fd18963;
	lpShData->xFindResourceA=(TFindResourceA)0x83ceca69;

	lpShData->xGlobalFree=(TGlobalFree)0x048223c0;
	lpShData->xGetProcAddress = (TGetProcAddress)0xbbafdf85;
	lpShData->xGetCurrentProcess=(TGetCurrentProcess)0x3a2fe6bb;
	lpShData->xGetFileSize=(TGetFileSize)0xac0a138e;
	lpShData->xGetProcessHeap=(TGetProcessHeap)0x80ae9074;
	lpShData->xGetSystemDirectoryA=(TGetSystemDirectoryA)0x8e6902b2;
	lpShData->xGetSystemDirectoryW=(TGetSystemDirectoryW)0x8e6902c8;
	lpShData->xGetModuleHandleA=(TGetModuleHandleA)0xf4e2f2b2;
	lpShData->xGetProcessImageFileNameA=(TGetProcessImageFileNameA)0x34ef0e5a;
	lpShData->xGetLastError=(TGetLastError)0x12f461bb;
	lpShData->xGetStartupInfoA=(TGetStartupInfoA)0x8fb53455;
	lpShData->xGetTickCount=(TGetTickCount)0xed04519b;
	lpShData->xGetCurrentProcessId=(TGetCurrentProcessId)0x2cece924;
	lpShData->xGetNativeSystemInfo=(TGetNativeSystemInfo)0x8a1fb2a8;
	lpShData->xGetModuleFileNameA=(TGetModuleFileNameA)0xb4ffafed;
	lpShData->xGetShortPathNameA=(TGetShortPathNameA)0xe72d6895;
	lpShData->xGetEnvironmentVariableA=(TGetEnvironmentVariableA)0xec496a9e;
	lpShData->xGetEnvironmentVariableW=(TGetEnvironmentVariableW)0xec496ab4;
	lpShData->xGetPrivateProfileStringA=(TGetPrivateProfileStringA)0x8f9ded68;
	lpShData->xGetPrivateProfileStringW=(TGetPrivateProfileStringW)0x8f9ded7e;
	lpShData->xGetThreadContext=(TGetThreadContext)0x114f57c8;
	lpShData->xSetThreadContext=(TSetThreadContext)0x174f57c8;

	lpShData->xHeapAlloc=(THeapAlloc)0xf8262c81;
	lpShData->xHeapFree=(THeapFree)0x052e3772;

	lpShData->xIsDebuggerPresent=(TIsDebuggerPresent)0xb483154;

	lpShData->xLoadResource=(TLoadResource)0xff951427;
	lpShData->xLockResource=(TLockResource)0xff951b2b;
	lpShData->xLoadLibraryA = (TLoadLibraryA)0x0c917432;

	lpShData->xMapViewOfFile=(TMapViewOfFile)0x9aa5f07d;
	lpShData->xMultiByteToWideChar=(TMultiByteToWideChar)0x70229207;
	lpShData->xMoveFileA=(TMoveFileA)0x896b19ae;
	lpShData->xMoveFileW=(TMoveFileW)0x896b19c4;
	lpShData->xMoveFileExA=(TMoveFileExA)0x56ca25ee;
	lpShData->xMoveFileExW=(TMoveFileExW)0x56ca2604;

	lpShData->xNtCreateFile=(TNtCreateFile)0x4489294c;

	lpShData->xOutputDebugStringA = (TOutputDebugStringA)0x354c31f2;
	lpShData->xOpenProcess=(TOpenProcess)0x77ce8553;
	lpShData->xOpenThread=(TOpenThread)0x5f4a878d;

	lpShData->xProcess32First=(TProcess32First)0xc4446aa6;
	lpShData->xProcess32Next=(TProcess32Next)0x2e255963;

	lpShData->xRtlGetVersion=(TRtlGetVersion)0x4907252b;
	lpShData->xRtlFreeUnicodeString=(TRtlFreeUnicodeString)0x07d63e06;
	lpShData->xRtlZeroMemory=(TRtlZeroMemory)0x555df489;
	lpShData->xRtlInitAnsiString=(TRtlInitAnsiString)0x65c26f71;
	lpShData->xRtlAnsiStringToUnicodeString=(TRtlAnsiStringToUnicodeString)0x199548c2;
	lpShData->xRtlAllocateHeap=(TRtlAllocateHeap)0x8e17053d;
	lpShData->xRtlFreeHeap=(TRtlFreeHeap)0xc839b3b6;
	lpShData->xRtlImageDirectoryEntryToData=(TRtlImageDirectoryEntryToData)0xc1eb7ae3;
	lpShData->xReadFile=(TReadFile)0x130f36b2;
	lpShData->xReadProcessMemory=(TReadProcessMemory)0xd5206133;


	lpShData->xRtlFormatCurrentUserKeyPath=(TRtlFormatCurrentUserKeyPath)0x29640660;
	lpShData->xRegCreateKeyExW=(TRegCreateKeyExW)0xb4b0ad31;
	lpShData->xRegSetValueExW=(TRegSetValueExW)0xd8c0fec0;
	lpShData->xRegCloseKey=(TRegCloseKey)0xe511783;
	lpShData->xRegOpenKeyA=(TRegOpenKeyA)0xf7be46f9;
	lpShData->xRegOpenKeyExA=(TRegOpenKeyExA)0xbf7df3b;
	lpShData->xRegSetValueExA=(TRegSetValueExA)0xd8c0feaa;
	lpShData->xRegQueryValueExA=(TRegQueryValueExA)0x8a2fc67e;
	lpShData->xRegQueryValueExW=(TRegQueryValueExW)0x8a2fc694;

	lpShData->xSizeofResource=(TSizeofResource)0xd90bb0a3;
	lpShData->xSleep=(TSleep)0xcb9765a0;
	lpShData->xSetFilePointer=(TSetFilePointer)0xdbacbe43;

	lpShData->xThread32First=(TThread32First)0x2eea7;
	lpShData->xThread32Next=(TThread32Next)0xd675981;

	lpShData->xUnmapViewOfFile=(TUnmapViewOfFile)0xdaa7fe52;

	lpShData->xVirtualAllocEx=(TVirtualAllocEx)0xef9c7bf1;
	lpShData->xVirtualFreeEx=(TVirtualFreeEx)0x3215858b;
	lpShData->xVirtualProtectEx=(TVirtualProtectEx)0x1a7bbe0b;
	lpShData->xVirtualAlloc=(TVirtualAlloc)0x1ede5967;
	lpShData->xVirtualFree=(TVirtualFree)0x6144aa05;//ef64a41e
	lpShData->xVirtualProtect=(TVirtualProtect)0xef64a41e;

	lpShData->xWideCharToMultiByte=(TWideCharToMultiByte)0xcb9bd550;
	lpShData->xWriteFile=(TWriteFile)0x741f8dc4;
	lpShData->xWinExec=(TWinExec)0x1a22f51;
	lpShData->xWriteProcessMemory=(TWriteProcessMemory)0x97410f58;

	lpShData->xZwQuerySystemInformation=(TZwQuerySystemInformation)0xeffc1cf8;
	lpShData->xZwSuspendProcess=(TZwSuspendProcess)0xec68e8bb;
	lpShData->xZwResumeProcess=(TZwResumeProcess)0x8af73c54;


#ifndef HHL_DEBUG


	b1=VirtualProtect(AsmShellData,sizeof(TShellData),PAGE_EXECUTE_READWRITE,&dwOldProtect);

	CopyMemory(AsmShellData,&ShellData,sizeof(TShellData));

	dwSize = (DWORD)shellcode_final_end - (DWORD)shellcode_final_start;

	lpBuffer = (PUCHAR)GlobalAlloc(GMEM_FIXED,dwSize);
	if(lpBuffer)
	{
		CopyMemory(lpBuffer,shellcode_final_start,dwSize);

		hFile = CreateFileA("hhlsh.bin", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

		if(hFile != INVALID_HANDLE_VALUE)
		{
			if(WriteFile(hFile,lpBuffer,dwSize,&dwBytes,NULL))
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
	GetRing3ApiAddr();
//	ShellCode_Start();
}
