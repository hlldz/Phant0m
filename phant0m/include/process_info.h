#pragma once

BOOL enoughIntegrityLevel() {

	BOOL checkResult = FALSE;

    HANDLE hToken, hProcess;

    DWORD dwLengthNeeded, dwIntegrityLevel;
    DWORD dwError = ERROR_SUCCESS;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;

    hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {

        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {

            dwError = GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER) {

                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
                if (pTIL != NULL) {

                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {

                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                            checkResult = TRUE;
                        }

                    }

                    LocalFree(pTIL);
                }

            }

        }

        CloseHandle(hToken);

    }

	return checkResult;

}

BOOL EnableDebugPrivilege() {

    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {

                return TRUE;

            }
        }
    }

    return FALSE;
}

BOOL isPrivilegeOK() {

    BOOL privilgeStatus = FALSE;

    LUID luid;
    PRIVILEGE_SET privs;
    HANDLE hProcess;
    HANDLE hToken;
    hProcess = GetCurrentProcess();

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

            privs.PrivilegeCount = 1;
            privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
            privs.Privilege[0].Luid = luid;
            privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

            BOOL privCheckResult;
            PrivilegeCheck(hToken, &privs, &privCheckResult);

            if (privCheckResult == TRUE) {

                printf("[+] SeDebugPrivilege is enable, continuing...\n\n");

                privilgeStatus = TRUE;
            }
            else {

                printf("[!] SeDebugPrivilege is not enabled, trying to enable...\n");
                
                if (EnableDebugPrivilege() == TRUE) {
                
                    printf("[+] SeDebugPrivilege is enabled, continuing...\n\n");

                    privilgeStatus = TRUE;
                
                }
                else {
                    
                    privilgeStatus = FALSE;
                
                }
            
            }
        
        }
    
    }

    return privilgeStatus;

}