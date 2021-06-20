<p align="center"><img src="https://raw.githubusercontent.com/hlldz/Phant0m/master/images/phant0m.png" alt="Phant0m" width="220"></p>

# Phant0m | Windows Event Log Killer

Svchost is essential in the implementation of so-called shared service processes, where a number of services can share a process in order to reduce resource consumption. Grouping multiple services into a single process conserves computing resources, and this consideration was of particular concern to NT designers because creating Windows processes takes more time and consumes more memory than in other operating systems, e.g. in the Unix family.<sup>[1](https://en.wikipedia.org/wiki/Svchost.exe)</sup>

This means briefly that; On Windows operating systems, svchost.exe manages the services and services are actually running under svchost.exe’s as threads. Phant0m targets the Event Log service and finding the process responsible for the Event Log service, it detects and kills the threads responsible for the Event Log service. Thus, while the Event Log service appears to be running in the system (because Phant0m didn't kill process), it does not actually run (because Phant0m killed threads) and the system does not collect logs.

# How It Works & How To Use

<p align="center"><img src="https://raw.githubusercontent.com/hlldz/Phant0m/master/images/execution-flow.png" alt="Phant0m - Execution Flow" width="800"></p>

## Detecting Event Log Service
Phant0m uses two different options to detect the Process ID of the Event Log service. The first is to detect via the SCM (Service Control Manager) and the second is to detect via WMI (Windows Management Instrumentation). With which method you want Phant0m to detect the Process ID of the Event Log service, change the following lines in the main.cpp file.

For example, if you want the Process ID to be detected via SCM, you should edit it as follows. (Do not set all values at the same time, set only the one technique you want.)
```cpp
// PID detection techniques configuration section.
#define PID_FROM_SCM 1 // If you set it to 1, the PID of the Event Log service is obtained from the Service Manager.
#define PID_FROM_WMI 0 // If you set it to 1, the PID of the Event Log service is obtained from the WMI.
```

For example, if you want threads to be killed using Technique-1, you should edit it as follows. (Do not set all values at the same time, set only the one technique you want.)
```cpp
// TID detection and kill techniques configuration section. 
#define KILL_WITH_T1 1 // If you set it to 1, Technique-1 will be use. For more information; https://github.com/hlldz/Phant0m
#define KILL_WITH_T2 0 // If you set it to 1, Technique-2 will be use. For more information; https://github.com/hlldz/Phant0m
```
## Detecting and Killing Threads
Phant0m uses two different options to detect and kill the threads of the Event Log service.

### Technique-1
When each service is registered on a machine running Windows Vista or later, the Service Control Manager (SCM) assigns a unique numeric tag to the service (in ascending order). Then, at service creation time, the tag is assigned to the TEB of the main service thread. This tag will then be propagated to every thread created by the main service thread. For example, if the Foo service thread creates an RPC worker thread (note: RPC worker threads don’t use the thread pool mechanism more on that later), that thread will have the Service Tag of the Foo service.<sup>[2](http://www.alex-ionescu.com/?p=52)</sup>

So, in this technique Phant0m will detect threads of Event Log service with NtQueryInformationThread API to get the thread’s TEB address and read the SubProcessTag from the TEB. Then it kills the threads related to the Event Log service. The codes for this technique are in `the technique_1.h` file.

### Technique-2
In this technique, Phant0m detects the names of DLLs associated with threads. Windows Event Log Service uses `wevtsvc.dll`. Full path is `%WinDir%\System32\wevtsvc.dll`. If the thread is using that DLL, it is the Windows Event Log Service’s thread and then Phant0m kills the thread. The codes for this technique are in `the technique_2.h` file.

## Usage
You can use Phant0m both as a standalone EXE and as a Reflective DLL. Open the project in Microsoft Visual Studio, make the settings (select the detection and kill techniques) and compile. You can also use the Reflective DLL version with Cobalt Strike, for this there is an Aggressor Script file (phant0m.cna) in the repository.

<p align="center"><img src="https://raw.githubusercontent.com/hlldz/Phant0m/master/images/cobaltstrike.png" alt="Phant0m - Cobalt Strike"></p>

Fork and inject method was used with `bdllspawn` in the execution type of Aggressor Script (phant0m.cna) for Cobalt Strike. If you want to inject Phant0m into your existing process and run it, you can review this project (https://github.com/rxwx/cs-rdll-ipc-example) and you can do it easily. You can also convert the code to DLL and then to Shellcode with [Donut](https://github.com/TheWover/donut).

---

### Special Thanks to Those Who Mentioned Phant0m
* Detecting in-memory attacks with Sysmon and Azure Security Center - https://azure.microsoft.com/tr-tr/blog/detecting-in-memory-attacks-with-sysmon-and-azure-security-center/
* Experiments with Invoke-Phant0m - http://www.insomniacsecurity.com/2017/08/27/phant0m.html
* Event Log Tampering Part 1: Disrupting the EventLog Service - https://medium.com/@7a616368/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c
* Flying under the radar - https://www.exploit-db.com/docs/english/45898-flying-under-the-radar.pdf?rss
* Denetim ve Log'lamanın Elli Tonu - https://gallery.technet.microsoft.com/Denetim-ve-Loglamann-Elli-cbed0000
* Disabling Windows Event Logs by Suspending EventLog Service Threads - https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
* Event Log Service – Between Offensive And Defensive - https://blog.cybercastle.io/event-log-service-between-offensive-and-defensive/
* Hunting Event Logging Coverup - https://malwarenailed.blogspot.com/2017/10/update-to-hunting-mimikatz-using-sysmon.html
* Defense Evasion: Windows Event Logging (T1562.002) - https://hacker.observer/defense-evasion-windows-event-logging-t1562-002/
* Pwning Windows Event Logging with YARA rules - https://labs.jumpsec.com/pwning-windows-event-logging-with-yara-rules/
* Various Notes - Incidence Response on Attacker Tricks for EventLog - https://hannahsuarez.github.io/2019/IncidentResponseNotes-Attackers-EventLog/
