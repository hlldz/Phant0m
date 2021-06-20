#pragma once

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

DWORD GetPIDFromWMI() {

	printf("[*] Attempting to detect PID from WMI....\n");

	DWORD dwEventLogPID = 0;

	HRESULT hRes;

	hRes = CoInitializeEx(0, COINIT_MULTITHREADED);

	if (FAILED(hRes)) {

		printf("[!] WMI: Failed to initialize COM library.\n");
		return 0;

	}

	hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

	if (FAILED(hRes)) {

		printf("[!] WMI: Failed to initialize security.\n");
		CoUninitialize();
		return 0;

	}

	IWbemLocator* pLoc = NULL;

	hRes = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hRes)) {

		printf("[!] WMI: Failed to create IWbemLocator object.\n");
		CoUninitialize();
		return 0;

	}

	IWbemServices* pSvc = NULL;

	hRes = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hRes)) {

		printf("[!] WMI: Could not connect.");
		pLoc->Release();
		CoUninitialize();
		return 0;

	}

	hRes = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hRes)) {

		printf("[!] WMI: Could not set proxy blanket.\n");
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 0;

	}

	IEnumWbemClassObject* pEnumerator = NULL;

	hRes = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Service"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hRes)) {

		printf("[!] WMI: Query failed.\n");
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 0;

	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator) {

		HRESULT hR = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn) {

			break;

		}

		VARIANT vtProp;
		VariantInit(&vtProp);

		hR = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

		if (_wcsicmp(vtProp.bstrVal, L"eventlog") == 0) {

			hR = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
			dwEventLogPID = vtProp.intVal;
			break;

		}

		VariantClear(&vtProp);
		pclsObj->Release();

	}

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return dwEventLogPID;
}