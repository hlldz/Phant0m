#pragma once

DWORD GetPIDFromSCManager() {

	printf("[*] Attempting to detect PID from Service Manager...\n");

	SC_HANDLE schSCManager, schService;
	SERVICE_STATUS_PROCESS ssProcess = {};
	DWORD dwBytesNeeded = 0;

	schSCManager = OpenSCManagerA(NULL, NULL, SERVICE_QUERY_STATUS);

	if (NULL == schSCManager) {

		printf("[!] SCM: OpenSCManager failed (%d)\n", GetLastError());
		return 0;

	}

	schService = OpenServiceA(schSCManager, "EventLog", SERVICE_QUERY_STATUS);

	if (schService == NULL) {

		printf("[!] SCM: OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return 0;

	}

	if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssProcess), sizeof(ssProcess), &dwBytesNeeded)) {

		printf("[!] SCM: QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 0;

	}

	return ssProcess.dwProcessId;
}

