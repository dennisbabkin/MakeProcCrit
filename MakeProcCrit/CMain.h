// This is a Proof-of-Concept (POC) project that demonstrates
// how to make any process into a "critical process" and to revert it back.
//
// Copyright (c) 2023, by dennisbabkin.com
//
//
// This project is used in the following blog post:
//
//  "Native Functions To The Rescue - Part 1"
//  "How to make a critical process that can crash Windows if it is closed."
//
//   https://dennisbabkin.com/blog/?i=AAA11F00
//

#pragma once

#include <iostream>

#include <Windows.h>
#include <winternl.h>
#include <strsafe.h>

#include <wininet.h>
#pragma comment(lib, "Wininet.lib")

#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


#include <assert.h>
#include <string>

#pragma comment(lib, "ntdll.lib")




#define APP_VERSION L"1.0.0"            //Main app version




extern "C" {

    NTSTATUS NTAPI
        NtSetInformationProcess(
            IN HANDLE ProcessHandle,
            IN PROCESSINFOCLASS ProcessInformationClass,
            IN PVOID ProcessInformation,
            IN ULONG ProcessInformationLength
        );

};


struct CMain
{
    static int processCmdLine(int argc, WCHAR *argv[]);

    static BOOL makeProcCriticalByPID(DWORD dwProcID, BOOL bCritical);
    static intptr_t makeProcsCriticalByName(LPCWSTR pProcName, BOOL bCritical);

    static BOOL makeThreadCriticalByThreadID(DWORD dwThreadID, BOOL bCritical);

    static std::wstring formatWin32ErrorCode(UINT nOSError);
    static BOOL adjustPrivilege(LPCTSTR pPrivilegeName, BOOL bEnable, HANDLE hProcess = NULL);

private:

    static BOOL _scanAs32bitDecimal(__in const WCHAR* pTxt, __in size_t szchLen, __out DWORD* pdwValue = NULL);
    static BOOL _scanAs32bitHex(__in const WCHAR* pTxt, __in size_t szchLen, __out DWORD* pdwValue = NULL);
    static void _showHelpInfo();


};

