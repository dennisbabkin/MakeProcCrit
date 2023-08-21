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

#include "CMain.h"




/// <summary>
/// Function that processes the command line from the user
/// </summary>
/// <param name="argc">Number of arguments</param>
/// <param name="argv">Array of pointers to the arguments</param>
/// <returns>Exit code to return from this app</returns>
int CMain::processCmdLine(int argc, WCHAR *argv[])
{
    int nExitCode = -1;

    int nErr;

    //We must have exactly 3 command line parameters
    //INFO: The first one is the path to our process.
    if(argc > 2)
    {
        const WCHAR* pArg;

        //Determine the on or off status
        int nOn = -1;
        pArg = argv[1];

        if(CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pArg, -1, L"on", -1) == CSTR_EQUAL ||
            CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pArg, -1, L"1", -1) == CSTR_EQUAL)
        {
            nOn = TRUE;
        }
        else if(CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pArg, -1, L"off", -1) == CSTR_EQUAL ||
            CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pArg, -1, L"0", -1) == CSTR_EQUAL)
        {
            nOn = FALSE;
        }


        if(nOn == TRUE ||
            nOn == FALSE)
        {
            //Second argument
            pArg = argv[2];
            size_t szcntArg = wcslen(pArg);

            if(szcntArg > 0)
            {
                //Get process ID
                DWORD dwPID;
                BOOL bGotPID = FALSE;

                WCHAR c = pArg[0];

                if(c == '0' && (pArg[1] == 'x' || pArg[1] == 'X'))
                {
                    //Try it as a hex number
                    if(_scanAs32bitHex(pArg + 2, szcntArg - 2, &dwPID))
                    {
                        //Got it
                        bGotPID = TRUE;
                    }
                    else
                    {
                        //Bad hex number
                        std::wcout << L"ERROR: Second parameter contains invalid hexadecimal number." << std::endl;
                    }
                }
                else if(c >= '0' && c <= '9')
                {
                    //Check for hex
                    c = pArg[szcntArg - 1];
                    if(c == 'h' ||
                        c == 'H')
                    {
                        //Scan as a hex number
                        if(_scanAs32bitHex(pArg, szcntArg - 1, &dwPID))
                        {
                            //Got it
                            bGotPID = TRUE;
                        }
                        else
                        {
                            //Bad hex number
                            std::wcout << L"ERROR: Second parameter contains invalid hexadecimal number." << std::endl;
                        }
                    }
                    else
                    {
                        //Scan as a decimal number
                        if(_scanAs32bitDecimal(pArg, szcntArg, &dwPID))
                        {
                            //Got it
                            bGotPID = TRUE;
                        }
                    }
                }


                //Set the debug privilege that we will need to change the "critical process" status
                if(adjustPrivilege(SE_DEBUG_NAME, TRUE))
                {
                    //Did we get a process ID?
                    if(bGotPID)
                    {
                        //Run it with the PID
                        if(makeProcCriticalByPID(dwPID, nOn))
                        {
                            //Success
                            nExitCode = 0;

                            if(nOn)
                            {
                                std::wcout << L"Success making the process with PID=" << dwPID << L" critical" << std::endl;
                            }
                            else
                            {
                                std::wcout << L"Success removing critical status from the process with PID=" << dwPID << std::endl;
                            }
                        }
                        else
                        {
                            //Failed
                            nErr = GetLastError();
                            std::wcout << L"ERROR: (" << nErr << L") Failed to " << 
                                (nOn ? L"make critical" : L"remove critical status from") <<
                                L" the process with PID=" << dwPID << std::endl;

                            //Give error description to the user
                            std::wcout << formatWin32ErrorCode(nErr) << std::endl;
                        }
                    }
                    else
                    {
                        //Try searching by process name
                        intptr_t nCntProcs = makeProcsCriticalByName(pArg, nOn);
                        if(nCntProcs > 0)
                        {
                            //Something was done
                            nExitCode = 0;
                        }
                        else if(nCntProcs == 0)
                        {
                            //Show a message that no processes was found
                            std::wcout << L"No running processes were found by the name: \"" << pArg << L"\"" << std::endl;

                            nExitCode = 1;
                        }
                    }
                }
                else
                {
                    //Error
                    nErr = GetLastError();
                    std::wcout << L"ERROR: (" << nErr << L") Failed to adjust privilege." << std::endl;

                    //Give error description to the user
                    std::wcout << formatWin32ErrorCode(nErr) << std::endl;

                    if(nErr == ERROR_NOT_ALL_ASSIGNED)
                    {
                        //Predict some obvious error and give user a better error message
                        std::wcout << L"Make sure to run this tool as administrator." << std::endl;
                    }
                }
            }
            else
            {
                //Error
                std::wcout << L"ERROR: Second parameter in required." << std::endl;
            }
        }
        else
        {
            //Bad arg
            std::wcout << L"ERROR: Bad first parameter." << std::endl;
        }
    }
    else
    {
        //Show help if nothing was provided, or if it's a wrong number of command line parameters
        _showHelpInfo();

        nExitCode = 1;
    }

    return nExitCode;
}





/// <summary>
/// Scan the text for a decimal number
/// </summary>
/// <param name="pTxt">Pointer to the text to scan from</param>
/// <param name="szchLen">Number of characters to scan</param>
/// <param name="pdwValue">If not 0, and success, will receive the number scanned</param>
/// <returns>TRUE if success</returns>
BOOL CMain::_scanAs32bitDecimal(__in const WCHAR* pTxt, __in size_t szchLen, __out DWORD* pdwValue)
{
    BOOL bRes = FALSE;
    DWORD dwVal = 0;

    if(szchLen > 0)
    {
        //Assume success
        bRes = TRUE;

        for(size_t i = 0; i < szchLen; i++)
        {
            WCHAR z = pTxt[i];

            if(z < '0' || z > '9')
            {
                //Bad char
                bRes = FALSE;
                break;
            }
        }

        if(bRes)
        {
            ULONGLONG v = _wtoi64(pTxt);
            if(v <= UINT_MAX)
            {
                dwVal = (DWORD)v;
            }
            else
            {
                //Overflowed
                bRes = FALSE;
            }
        }
    }

    if(pdwValue)
        *pdwValue = dwVal;

    return bRes;
}



/// <summary>
/// Scan the text for a hexadecimal number
/// </summary>
/// <param name="pTxt">Pointer to the text to scan from</param>
/// <param name="szchLen">Number of characters to scan</param>
/// <param name="pdwValue">If not 0, and success, will receive the number scanned</param>
/// <returns>TRUE if success</returns>
BOOL CMain::_scanAs32bitHex(__in const WCHAR* pTxt, __in size_t szchLen, __out DWORD* pdwValue)
{
    BOOL bRes = FALSE;
    DWORD dwVal = 0;

    if(szchLen > 0)
    {
        //Assume success
        bRes = TRUE;

        for(size_t i = 0; i < szchLen; i++)
        {
            if(i >= sizeof(dwVal) * 2)
            {
                //Overflowed
                bRes = FALSE;
                dwVal = 0;

                break;
            }

            dwVal = dwVal << 4;

            WCHAR z = pTxt[i];

            if(z >= '0' && z <= '9')
            {
                dwVal |= z - '0';
            }
            else if(z >= 'a' && z <= 'f')
            {
                dwVal |= z - 'a' + 10;
            }
            else if(z >= 'A' && z <= 'F')
            {
                dwVal |= z - 'A' + 10;
            }
            else
            {
                //Bad char
                bRes = FALSE;
                dwVal = 0;

                break;
            }
        }
    }

    if(pdwValue)
        *pdwValue = dwVal;

    return bRes;
}




/// <summary>
/// Format OS error code into a localized string with technical description
/// </summary>
/// <param name="nOSError">Win32 error code to format</param>
/// <returns>Resulting error string</returns>
std::wstring CMain::formatWin32ErrorCode(UINT nOSError)
{
    int n_old_err = GetLastError();
    std::wstring str_result;

    if (nOSError != NO_ERROR) 
    {

#ifndef INTERNET_ERROR_BASE
#define INTERNET_ERROR_BASE                     12000
#endif

#ifndef INTERNET_ERROR_LAST
#define INTERNET_ERROR_LAST                     (INTERNET_ERROR_BASE + 175)
#endif

        HMODULE hMod;

        if (nOSError >= INTERNET_ERROR_BASE && 
            nOSError <= INTERNET_ERROR_LAST) 
        {
            //Special module
            static HMODULE hModInet = NULL;
            if (!hModInet) 
            {
                hModInet = GetModuleHandle(L"WinINet.dll");

                if(!hModInet)
                {
                    //We need this block to ensure that WinINet.dll is linked statically to our module,
                    //so that GetModuleHandle call above can always get us its handle...
                    URL_COMPONENTSW uc = {};
                    InternetCrackUrlW(L"", 0,0x80000000 /*ICU_ESCAPE*/, &uc);

                    //We should never get here!
                    __debugbreak();
                }
            }

            hMod = hModInet;
        }
        else 
        {
            hMod = NULL;
        }

        static LPCTSTR pModsToTry[] = 
        {
            NULL,
            L"Kernel32.dll",
            L"ntdll.dll",
        };

        LPVOID lpMsgBuf = NULL;

        for (int m = 0; m < _countof(pModsToTry); m++) 
        {
            if (m > 0) 
            {
                hMod = GetModuleHandle(pModsToTry[m]);
            }

            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS |
                (hMod ? FORMAT_MESSAGE_FROM_HMODULE : FORMAT_MESSAGE_FROM_SYSTEM),
                hMod,
                nOSError,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&lpMsgBuf, 0, NULL))
            {
                break;
            }
        }

        if (lpMsgBuf)
        {
            //Replace all formatting in the string
            WCHAR* pE = (WCHAR*)lpMsgBuf;
            for (WCHAR* pS = pE;; pS++) 
            {
                WCHAR z = *pS;

                if (!z) 
                {
                    //Skip last spaces
                    for (pE = pS - 1; pE >= (WCHAR*)lpMsgBuf; pE--) 
                    {
                        if (*pE != L' ')
                            break;
                    }

                    pE++;

                    break;
                }
                else if (z == L'\r' || z == L'\n' || z == L'\t')
                    *pS = L' ';
                else if (z == L'%')
                    *pS = L'@';
            }

            str_result.assign((LPCTSTR)lpMsgBuf, pE - (WCHAR*)lpMsgBuf);

            LocalFree(lpMsgBuf);
            lpMsgBuf = NULL;
        }
        else 
        {
            //Didn't have this error code description - use just the number
            WCHAR buff[64];
            StringCchPrintf(buff, _countof(buff), 
                !(nOSError & 0xC0000000) || (int)nOSError > -1000 ? L"<%d>" : L"<0x%X>", nOSError);
            buff[_countof(buff) - 1] = 0;

            str_result = buff;
        }
    }

    SetLastError(n_old_err);
    return str_result;
}




/// <summary>
/// Tries to adjust the privileges for a process
/// </summary>
/// <param name="pPrivilegeName">Privilege name to adjust</param>
/// <param name="bEnable">TRUE to enable, FALSE to disable a privilege</param>
/// <param name="hProcess">Process to adjust the privilege for, or NULL for the current process</param>
/// <returns>TRUE if done; FALSE if privileges were not adjusted (check GetLastError() for info)</returns>
BOOL CMain::adjustPrivilege(LPCTSTR pPrivilegeName, BOOL bEnable, HANDLE hProcess)
{
    BOOL bRes = FALSE;
    int nOSError = NO_ERROR;

    HANDLE hToken = NULL; 
    TOKEN_PRIVILEGES tkp; 

    //Get a token for the process
    if(!OpenProcessToken(hProcess ? hProcess : GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE; 

    //Get the LUID for the privilege
    if(LookupPrivilegeValue(NULL, pPrivilegeName, &tkp.Privileges[0].Luid))
    {
        //One privilege only
        tkp.PrivilegeCount = 1;  
        tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0; 

        //Adjust it
        bRes = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        nOSError = GetLastError();
        if(bRes)
        {
            //See if no error
            if(nOSError != ERROR_SUCCESS)
            {
                //We did not adjust it
                bRes = FALSE;
            }
        }
    }
    else
    {
        //Failed
        nOSError = ::GetLastError();
    }

    //Close handle
    if(hToken)
    {
        CloseHandle(hToken);
    }

    ::SetLastError(nOSError);
    return bRes;
}





/// <summary>
/// Search for running processes by the process name and adjust their "critical process" status
/// </summary>
/// <param name="pProcName">Name of the process to search. It is case insensitive. If no extension is provided, the ".exe" is assumed.</param>
/// <param name="bCritical">TRUE to make matching processes as "critical", FALSE - to remove their "critical process" status</param>
/// <returns>[0-up) - number of processes that this function adjusted their "critical process" status, or -1 if didn't do anything due to an error</returns>
intptr_t CMain::makeProcsCriticalByName(LPCWSTR pProcName, BOOL bCritical)
{
    intptr_t nCntMatchedProcs = -1;
    int nErr = 0;

    //We must have a process name for the search
    if(pProcName &&
        pProcName[0])
    {
        WTS_PROCESS_INFO* pWPIs = NULL;
        DWORD dwCntWPIs = 0;

        //Enumerate all processes in this session
        if(WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pWPIs, &dwCntWPIs))
        {
            assert(pWPIs);

            //See if we have a full process name (including the extension)
            std::wstring strProcName = pProcName;
            if(*PathFindExtension(pProcName) == 0)
            {
                //Add .exe if not
                strProcName += L".exe";
            }


            //Start counting how many processes we succeed on
            nCntMatchedProcs = 0;

            BOOL bFailedAtLeastOnce = FALSE;

            LPCWSTR pSearchName = strProcName.c_str();
            int nchSearchLn = (int)strProcName.size();

            //Go through all processes found and try to match their names to ours
            for(DWORD p = 0; p < dwCntWPIs; p++)
            {
                //See if this proc matches our name
                if(CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pWPIs[p].pProcessName, -1, pSearchName, nchSearchLn) == CSTR_EQUAL)
                {
                    //This process matched
                    DWORD dwPID = pWPIs[p].ProcessId;

                    //Change its "critical" status
                    if(makeProcCriticalByPID(dwPID, bCritical))
                    {
                        //Succeeded
                        nCntMatchedProcs++;

                        if(bCritical)
                        {
                            std::wcout << L"Success making the process with PID=" << dwPID << L" critical" << std::endl;
                        }
                        else
                        {
                            std::wcout << L"Success removing critical status from the process with PID=" << dwPID << std::endl;
                        }
                    }
                    else
                    {
                        //Failed
                        nErr = GetLastError();
                        std::wcout << L"ERROR: (" << nErr << L") Failed to " << 
                            (bCritical ? L"make critical" : L"remove critical status from") <<
                            L" the process with PID=" << dwPID << std::endl;

                        std::wcout << formatWin32ErrorCode(nErr) << std::endl;

                        bFailedAtLeastOnce = TRUE;
                    }
                }
            }


            //Cover for the special case
            if(nCntMatchedProcs == 0 &&
                bFailedAtLeastOnce)
            {
                //Return this as an error
                nCntMatchedProcs = -1;
            }

            //Free memory
            WTSFreeMemory(pWPIs);
        }
        else
        {
            //Error
            nErr = GetLastError();
            std::wcout << L"ERROR: (" << nErr << L") Failed to enumerate processes" << std::endl;
            std::wcout << formatWin32ErrorCode(nErr) << std::endl;
        }
    }
    else
    {
        //No process name
        std::wcout << L"ERROR: We must have a process name to search" << std::endl;
    }

    return nCntMatchedProcs;
}





/// <summary>
/// Adjust the "critical process" status for a process by its process ID
/// </summary>
/// <param name="dwProcID">Process ID of a running process to adjust</param>
/// <param name="bCritical">TRUE to make a process "critical", FALSE - to remove its "critical process" status</param>
/// <returns>TRUE if success, FALSE if failed - check GetLastError() for detais.</returns>
BOOL CMain::makeProcCriticalByPID(DWORD dwProcID, BOOL bCritical)
{
    BOOL bRes = FALSE;
    int nOSError = 0;

    //Open our process
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, dwProcID);
    if(hProc)
    {
        ULONG bBreakOnTermination = !!bCritical;

#ifndef ProcessBreakOnTermination
#define ProcessBreakOnTermination (PROCESSINFOCLASS)29
#endif

        //IMPORTANT: Don't use SetProcessInformation() here!
        //
        NTSTATUS status = NtSetInformationProcess(hProc, 
            ProcessBreakOnTermination, 
            &bBreakOnTermination, 
            sizeof(bBreakOnTermination));

        if(NT_SUCCESS(status))
        {
            //Done
            bRes = TRUE;
        }
        else
        {
            //Error
            nOSError = RtlNtStatusToDosError(status);
        }

        //Close handle
        CloseHandle(hProc);
    }
    else
    {
        //Error
        nOSError = GetLastError();
    }

    SetLastError(nOSError);
    return bRes;
}





/// <summary>
/// Adjust the "critical thread" status for a thread by its ID
/// </summary>
/// <param name="dwThreadID">Thread ID of a running thread to adjust</param>
/// <param name="bCritical">TRUE to make a thread "critical", FALSE - to remove its "critical thread" status</param>
/// <returns>TRUE if success, FALSE if failed - check GetLastError() for detais.</returns>
BOOL CMain::makeThreadCriticalByThreadID(DWORD dwThreadID, BOOL bCritical)
{
    BOOL bRes = FALSE;
    int nOSError = 0;

    //Open the thread
    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, dwThreadID);
    if(hThread)
    {
        ULONG bBreakOnTermination = !!bCritical;

#ifndef ThreadBreakOnTermination
#define ThreadBreakOnTermination (THREADINFOCLASS)18
#endif

        NTSTATUS status = NtSetInformationThread(hThread, 
            ThreadBreakOnTermination,
            &bBreakOnTermination,
            sizeof(bBreakOnTermination));

        if(NT_SUCCESS(status))
        {
            //Done
            bRes = TRUE;
        }
        else
        {
            //Error
            nOSError = RtlNtStatusToDosError(status);
        }

        //Close it
        CloseHandle(hThread);
    }
    else
    {
        //Error
        nOSError = GetLastError();
    }

    SetLastError(nOSError);
    return bRes;
}






/// <summary>
/// Display help info to the user about how to call this app
/// </summary>
void CMain::_showHelpInfo()
{
    std::wcout << L"MakeProcCrit v." << APP_VERSION <<
        std::endl <<
        L"Copyright (c) by dennisbabkin.com" <<
        std::endl <<
        std::endl;

    std::wcout << L"Usage:" << std::endl;
    std::wcout << L"       MakeProcCrit [on|1|off|0] [pid|ProcName]" <<
        std::endl <<
        std::endl;

    std::wcout << L"where:" << 
        std::endl <<
        std::endl;

    std::wcout << L" on            Make process critical" << std::endl;
    std::wcout << L" 1             Same as on" << std::endl;
    std::wcout << L" off           Remove critical status of a process" << std::endl;
    std::wcout << L" 0             Same as off" << std::endl;
    std::wcout << L" pid           Process ID, eg: 1822, 0x71E or 71eh" << std::endl;
    std::wcout << L" ProcName      Process name, eg: \"notepad\", or \"explorer.exe\"" << std::endl;

    std::wcout << std::endl;
}


