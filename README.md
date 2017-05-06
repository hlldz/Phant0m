# Invoke-Phant0m
This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.

I have made this script for two reasons. First, This script will help to Red Teams and Penetration Testers. Second, I want to learn Powershell and Low-Level things on Powershell for cyber security field.

# Usage

```
PS C:\> Invoke-Phant0m
        _                 _    ___
  _ __ | |__   __ _ _ __ | |_ / _ \ _ __ ___
 | '_ \| '_ \ / _` | '_ \| __| | | | '_ ` _ \
 | |_) | | | | (_| | | | | |_| |_| | | | | | |
 | .__/|_| |_|\__,_|_| |_|\__|\___/|_| |_| |_|
 |_|


[!] I'm here to blur the line between life and death...

[*] Enumerating threads of PID: 1000...
[*] Parsing Event Log Service Threads...
[+] Thread 1001 Succesfully Killed!
[+] Thread 1002 Succesfully Killed!
[+] Thread 1003 Succesfully Killed!
[+] Thread 1004 Succesfully Killed!

[+] All done, you are ready to go!
```

# Video
[![PoC Video](https://i.ytimg.com/vi/PF0-tZWCmpc/maxresdefault.jpg)](https://www.youtube.com/watch?v=PF0-tZWCmpc)


