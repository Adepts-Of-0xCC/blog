---
title: "Adding a native sniffer to your implants: decomposing and recomposing PktMon"
date: 2021-07-09 00:00:00 +00:00
modified: 2021-07-09 00:00:00 +00:00
tags: [red team, research, X-C3LL]
description: Disecting PktMon.exe utility and building our own sniffer based on it
image: 
---

Dear Fell**owl**ship, today's homily is about how to add a sniffer to our implant. To accomplish this task we are going to dissect the native tool PktMon.exe, so we can learn about its internals in order to emulate its functionalities. Please, take a seat and listen to the story.

# Prayers at the foot of the Altar a.k.a. disclaimer
*In this article we are going to touch on some topics that we are not familiar with, so it is possible that we make some minor mistakes. If you find any, please do not hesitate to contact us so we can correct it.*

# Introduction
Some years ago we had to face a Red Team operation where at some point we discovered that a lot of machines were running a Backup service. This Backup service was old as hell and it was composed by a central node and agents installed in each machine that were enrolled in this "central server".

When a management task had to be executed (for example, to schedule a backup or to check agent stats) the central node sent the order to the target machine. To load those orders the central server had to authenticate against each agent and here comes the magic: the authentication was unencrypted and shared between machines. Getting those credentials meant RCE in all the machines that had the agent installed (to perform a backup task you could configure arbitrary pre/post system commands, so it was a insta-pwn). A lot of techniques can be used to intercept those credentials (injecting a hook, reversing the application in order to understand how the credentials are saved...), but undoubtedly the easiest and painless way is to use a sniffer. 

Today most of the communications between services are encrypted (SSL/TLS ftw!) and a sniffer inside a Red Team operation or a pentest is something that you are going to use only in a corner-case. But learning new things is always useful: you never know when this info can save your ass. So here we are! Let's build a shitty PoC able to sniff traffic!

In windows we have the utility [PktMon](https://docs.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax):

*Packet Monitor (Pktmon) is an in-box, cross-component network diagnostics tool for Windows. It can be used for packet capture, packet drop detection, packet filtering and counting. The tool is especially helpful in virtualization scenarios, like container networking and SDN, because it provides visibility within the networking stack. Packet Monitor is available in-box via pktmon.exe command on Windows 10 and Windows Server 2019 (Version 1809 and later).*


As the descriptions states, it is exactly the place where we should start to peek an eye.

# Phase I: decompose

Before feeding our disassembler with PktMon.exe we can extract some clues about what we should focus. First in the syntax page we have this text:

*Packet Monitor generates log files in ETL format. There are multiple ways to format the ETL file for analysis*

We can deduce that we are interested in code related with Event Trace Log files. Also the documentation for [`pktmon unload`](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-unload) states:

*Stop the PktMon driver service and unload PktMon.sys. Effectively equivalent to 'sc.exe stop PktMon'. Measurement (if active) will immediately stop, and any state will be deleted (counters, filters, etc.).*

If `sc` is related, it means that we are going to deal with services. So the first thing to look are functions related with "service". With the symbol search in Binary Ninja we can find that `OpenServiceW` is used with the parameter "PktMon", so it rings the bell.


<figure>
<img src="/PktMon-Dissection/OpenServiceW.png" alt="OpenServiceW">
<figcaption>
OpenServiceW with "PktMon" as parameter (function OpenService_PktMon was renamed by us).
</figcaption>
</figure>

Checking for cross-references leads us to this other function, where we can see clearly how it calls our renamed `OpenService_PktMon` (where the OpenServiceW was located) and if everything goes OK it opens the device "PktMonDev". 

<figure>
<img src="/PktMon-Dissection/Device.png" alt="Device">
<figcaption>
Opening the device "PktMonDev".
</figcaption>
</figure>

So far we know that our PktMon start a service called "PktMon" and it opens a handle to the device "PktMonDev". Playing with drivers means that we are going to deal with IOCTL codes. Indeed if we check again for cross-references we can see how the handle obtained before is used in a `DeviceIoControl` call:

<figure>
<img src="/PktMon-Dissection/DeviceIoControl.png" alt="DeviceIoControl">
<figcaption>
Calling DeviceIoControl() (yep, DeviceIoControl_Arbitrary -and also the args- was renamed by us).
</figcaption>
</figure>



At this point we can use a mix of static and dynamic analysis to check what IOCTLs are used and for what task. Just run `PktMon start -c --pkt-size 0` inside a debugger, put a breakpoint at `DeviceIoControl` and check where the IOCTL appears in the disassembly (the same approach can be done with Frida or any other tool that let you hook the function to check the parameters).

_**After one hour wasted reversing this (yeah, we are slow as hell because our skills doing RE are close to zero) we noticied that in System32 exists a DLL called `PktMonApi.dll`... and if you check the exports...**_
<figure>
<img src="/PktMon-Dissection/Stoopid.png" alt="DeviceIoControl">
<figcaption>
*Extreme Facepalm*. Each export is verbose enough to undertand exactly what does each IOCTL. 
</figcaption>
</figure>

_**So... yes, we could save a lot of time to understand what does each call to DeviceIoControl by just looking this DLL. Shame on us!**_


The IOCTL for the "start" parameter is **`0x220404`**. Let's check the registers when `DeviceIoControl` is called with this code:

```
RAX : 0000000000000000
RBX : 0000000000220404
RCX : 0000000000000188 <= Handle to \\.\PktMonDev    
RDX : 0000000000220404 <= IOCTL for "PktMonStart"
RBP : 0000000000000188     
RSP : 00000077D027FC28
RSI : 00000077D027FDB8
RDI : 0000000000000014
R8  : 00000077D027FDB8 <= Input buffer
R9  : 0000000000000014 <= Input size
R10 : 00000FFF26BD722B
R11 : 00000077D027FCC0
R12 : 0000000000000000
R13 : 00000192BDDE0570
R14 : 0000000000000001
R15 : 0000000000000000
RIP : 00007FF935E9AC00     <kernelbase.DeviceIoControl>
```

To get the input transmited to the driver we just have to read `R9` bytes at address contained in `R8`:

```
0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x01, 0x0, 0x00, 0x00 
```

This message tells the driver that should start capturing fully packets (by default the packets are truncated to 128 bytes, with `--pkt-size 0` we disable this limit).

If we want to add a filter (because we are only interested in a service that uses X port) we need to use the IOCTL **`0x220410`** which uses a bigger input (0xD8 bytes) with the next layout:

<figure>
<img src="/PktMon-Dissection/addfilterlayout.png" alt="Input buffer for PktMonAddFilter">
<figcaption>
Input buffer for PktMonAddFilter. 
</figcaption>
</figure>

As we can see the marked XX II bytes corresponds to the port. If we want to capture the traffic exchanged in port 14099, our input buffer will be:

```
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
(...)
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00,
(...)
```

So far at this point we know how to communicate with the driver in order to initate the capture of traffic and how to set capture filters based on ports. But... how are we going to collect and save the data? The MSDN page stated that packets are saved as ETL. Let's search for symbols related to [event logging](https://docs.microsoft.com/en-us/windows/win32/api/_etw/)!


<figure>
<img src="/PktMon-Dissection/StartTraceW.png" alt="StartTraceW">
<figcaption>
References to ETL related functions 
</figcaption>
</figure>

If we set a breakpoint on those functions and run PktMon.exe we are going to hit them. We are interested in [EnableTraceEx2](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2) because it receives as parameter the provider GUID which indicates the event trace provider we are going to enable.

```
RAX : 0000000000000012
RBX : 0000017419FE01B0
RCX : 000000000000001A
RDX : 0000017419FE01B0 
RBP : 0000003FB196F650
RSP : 0000003FB196F548
RSI : 0000017419FE01F0     
RDI : 0000000000000000
R8  : 0000000000000001
R9  : 0000000000000004
R10 : 0000017419FC0000
R11 : 0000003FB196F430
R12 : 0000000000000000
R13 : 0000017419FE01B0
R14 : 0000000000000000
R15 : 0000000000000001
RIP : 00007FF8F7389910     <sechost.EnableTraceEx2>
```

The [GUID is a 128-bit value](https://docs.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid). Let's retrieve it from `17419FE01B0`:

```
D9 80 4F 4D BD C8 73 4D BB 5B 19 C9 04 02 C5 AC
```

This translates to the GUID **`{4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC}`**. If we google this value we reach this [reference from Microsoft's repo](https://github.com/microsoft/NetMon_Parsers_for_PacketMon/blob/main/stub_etl_Microsoft-Windows-PktMon-Events.npl) that confirms the value:

```
(...)
[RegisterBefore(NetEvent.UserData, MicrosoftWindowsPktMon, "{4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac}")]
(...)
```


To recap:

- PktMon starts a service and communicate to the driver via `\\.\PktMonDev` device.
- Uses the IOCTL `0x220410` to set the filter and `0x220404` to start capturing traffic
- The packets are saved as events, so it creates a trace session to log the info in a .etl file (or info can be sent to the output in real-time).


Ooook. We have enough info to start to build our PoC

# Phase II: recompose

MSDN provides [an example](https://docs.microsoft.com/en-us/windows/win32/etw/example-that-creates-a-session-and-enables-a-manifest-based-provider) of how to start a trace session. We are going to use this example as base to enable the trace:

```c
//...
#define LOGFILE_PATH "C:\\Windows\\System32\\ShabbySniffer.etl"
#define LOGSESSION_NAME "My Shabby Sniffer doing things"
//...

DWORD initiateTrace(void) {
	static const GUID sessionGuid = { 0x6f0aaf43, 0xec9e, 0xa946, {0x9e, 0x7f, 0xf9, 0xf4, 0x13, 0x37, 0x13, 0x37 } };  
	static const GUID providerGuid = { 0x4d4f80d9, 0xc8bd, 0x4d73, {0xbb, 0x5b, 0x19, 0xc9, 0x04, 0x02, 0xc5, 0xac } }; // {4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC}

	// Taken from https://docs.microsoft.com/en-us/windows/win32/etw/example-that-creates-a-session-and-enables-a-manifest-based-provider
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE sessionHandle = 0;
	PEVENT_TRACE_PROPERTIES pSessionProperties = NULL;
	ULONG bufferSize = 0;
	BOOL TraceOn = TRUE;

	bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGFILE_PATH) + sizeof(LOGSESSION_NAME);
	pSessionProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);

	ZeroMemory(pSessionProperties, bufferSize);
	pSessionProperties->Wnode.BufferSize = bufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
	pSessionProperties->Wnode.Guid = sessionGuid;
	pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR;
	pSessionProperties->MaximumFileSize = 50;  // 50 MB
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGSESSION_NAME);
	StringCbCopyA(((LPSTR)pSessionProperties + pSessionProperties->LogFileNameOffset), sizeof(LOGFILE_PATH), LOGFILE_PATH);

	status = StartTraceA(&sessionHandle, LOGSESSION_NAME, pSessionProperties);
	if (status != ERROR_SUCCESS) {
		printf("[!] StartTraceA failed!\n");
		return -1;
	}
	status = EnableTraceEx2(sessionHandle, &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
	if (status != ERROR_SUCCESS) {
		printf("[!] EnableTraceEx2 failed!\n");
		return -1;
	}
	return 0;
}
//...
```

As this is just a PoC we are going to use `EVENT_TRACE_FILE_MODE_CIRCULAR` file mode. Exists different [logging modes](https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants) that can fit better for our purposes (for example generating a new file each time we reach the maximum size, so you can delete older files).

Implementing the driver communication is easy because the pseudocode obtained from Binary Ninja is pretty clear. First, let's start the service and open a handle to the device:

```c
//...
HANDLE PktMonServiceStart(void) {
	SC_HANDLE hManager;
	SC_HANDLE hService;
	HANDLE hDriver;
	BOOL status;

	hManager = OpenSCManagerA(NULL, "ServicesActive", SC_MANAGER_CONNECT); // SC_MANAGER_CONNECT == 0x01
	if (!hManager) {
		return NULL;
	}
	hService = OpenServiceA(hManager, "PktMon", SERVICE_START | SERVICE_STOP); // 0x10 | 0x20 == 0x30
	CloseServiceHandle(hManager);

	status = StartServiceA(hService, 0, NULL);
	CloseServiceHandle(hService);

	hDriver = CreateFileA("\\\\.\\PktMonDev", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // 0x80000000 | 0x40000000 == 0xC0000000; OPEN_EXISTING == 0x03; FILE_ATTRIBUTE_NORMAL == 0x80
	if (hDriver == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	return hDriver;
}
//...
```

In our PoC we are going to create a filter to intercept the traffic throught 14099 port (yeah we love **1337** jokes) and then start capturing the traffic:

```c
//...
DWORD initiateCapture(HANDLE hDriver) {
	BOOL status;
	DWORD IOCTL_start = 0x220404;
	DWORD IOCTL_filter = 0x220410;

	LPVOID IOCTL_start_InBuffer = NULL;
	DWORD IOCTL_start_bytesReturned = 0;
	char IOCTL_start_message[0x14] = { 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x01, 0x0, 0x00, 0x00 };

	LPVOID IOCTL_filter_InBuffer = NULL;
	DWORD IOCTL_filter_bytesReturned = 0;
	char IOCTL_filter_message[0xD8] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
					};


	IOCTL_filter_InBuffer = (LPVOID)malloc(0xD8);
	memcpy(IOCTL_filter_InBuffer, IOCTL_filter_message, 0xD8);
	status = DeviceIoControl(hDriver, IOCTL_filter, IOCTL_filter_InBuffer, 0xD8, NULL, 0, &IOCTL_filter_bytesReturned, NULL);
	if (!status) {
		printf("[!] Error! Filter creation failed!\n");
		return -1;
	}


	IOCTL_start_InBuffer = (LPVOID)malloc(0x14);
	memcpy(IOCTL_start_InBuffer, IOCTL_start_message, 0x14);
	status = DeviceIoControl(hDriver, IOCTL_start, IOCTL_start_InBuffer, 0x14, NULL, 0, &IOCTL_start_bytesReturned, NULL);
	if (status) {
		return 0;
	}
	return -1;
}
//...
```

# PoC || GTFO

All the parts are created, we only need to glue them together **:)**. 

<figure>
<img src="/PktMon-Dissection/PoC.png" alt="Working PoC">
<figcaption>
Working PoC. Communication sniffed succesfully!
</figcaption>
</figure>


**Keep in mind that in this PoC we did not clean up nothing!!**. For that you need to add code that:

- Kindly ask the driver to stop capturing and stop the service (check PktMonAPI.dll **;**))
- Disable the trace session (check `EVENT_CONTROL_CODE_DISABLE_PROVIDER` and `EVENT_TRACE_CONTROL_STOP`)

After this warning, here is the shitty PoC:

```c
/* Shabby PktMon (PoC) by Juan Manuel Fernandez (@TheXC3LL) */

#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <strsafe.h>

#define LOGFILE_PATH "C:\\Windows\\System32\\ShabbySniffer.etl"
#define LOGSESSION_NAME "My Shabby Sniffer doing things"

HANDLE PktMonServiceStart(void) {
	SC_HANDLE hManager;
	SC_HANDLE hService;
	HANDLE hDriver;
	BOOL status;

	hManager = OpenSCManagerA(NULL, "ServicesActive", SC_MANAGER_CONNECT); // SC_MANAGER_CONNECT == 0x01
	if (!hManager) {
		return NULL;
	}
	hService = OpenServiceA(hManager, "PktMon", SERVICE_START | SERVICE_STOP); // 0x10 | 0x20 == 0x30
	CloseServiceHandle(hManager);

	status = StartServiceA(hService, 0, NULL);
	CloseServiceHandle(hService);

	hDriver = CreateFileA("\\\\.\\PktMonDev", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // 0x80000000 | 0x40000000 == 0xC0000000; OPEN_EXISTING == 0x03; FILE_ATTRIBUTE_NORMAL == 0x80
	if (hDriver == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	return hDriver;
}

DWORD initiateCapture(HANDLE hDriver) {
	BOOL status;
	DWORD IOCTL_start = 0x220404;
	DWORD IOCTL_filter = 0x220410;

	LPVOID IOCTL_start_InBuffer = NULL;
	DWORD IOCTL_start_bytesReturned = 0;
	char IOCTL_start_message[0x14] = { 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x01, 0x0, 0x00, 0x00 };

	LPVOID IOCTL_filter_InBuffer = NULL;
	DWORD IOCTL_filter_bytesReturned = 0;
	char IOCTL_filter_message[0xD8] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
					};


	IOCTL_filter_InBuffer = (LPVOID)malloc(0xD8);
	memcpy(IOCTL_filter_InBuffer, IOCTL_filter_message, 0xD8);
	status = DeviceIoControl(hDriver, IOCTL_filter, IOCTL_filter_InBuffer, 0xD8, NULL, 0, &IOCTL_filter_bytesReturned, NULL);
	if (!status) {
		printf("[!] Error! Filter creation failed!\n");
		return -1;
	}


	IOCTL_start_InBuffer = (LPVOID)malloc(0x14);
	memcpy(IOCTL_start_InBuffer, IOCTL_start_message, 0x14);
	status = DeviceIoControl(hDriver, IOCTL_start, IOCTL_start_InBuffer, 0x14, NULL, 0, &IOCTL_start_bytesReturned, NULL);
	if (status) {
		return 0;
	}
	return -1;
}


DWORD initiateTrace(void) {
	static const GUID sessionGuid = { 0x6f0aaf43, 0xec9e, 0xa946, {0x9e, 0x7f, 0xf9, 0xf4, 0x13, 0x37, 0x13, 0x37 } };  
	static const GUID providerGuid = { 0x4d4f80d9, 0xc8bd, 0x4d73, {0xbb, 0x5b, 0x19, 0xc9, 0x04, 0x02, 0xc5, 0xac } }; // {4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC}

	// Taken from https://docs.microsoft.com/en-us/windows/win32/etw/example-that-creates-a-session-and-enables-a-manifest-based-provider
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE sessionHandle = 0;
	PEVENT_TRACE_PROPERTIES pSessionProperties = NULL;
	ULONG bufferSize = 0;
	BOOL TraceOn = TRUE;

	bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGFILE_PATH) + sizeof(LOGSESSION_NAME);
	pSessionProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);

	ZeroMemory(pSessionProperties, bufferSize);
	pSessionProperties->Wnode.BufferSize = bufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
	pSessionProperties->Wnode.Guid = sessionGuid;
	pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR;
	pSessionProperties->MaximumFileSize = 50;  // 50 MB
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGSESSION_NAME);
	StringCbCopyA(((LPSTR)pSessionProperties + pSessionProperties->LogFileNameOffset), sizeof(LOGFILE_PATH), LOGFILE_PATH);

	status = StartTraceA(&sessionHandle, LOGSESSION_NAME, pSessionProperties);
	if (status != ERROR_SUCCESS) {
		printf("[!] StartTraceA failed!\n");
		return -1;
	}
	status = EnableTraceEx2(sessionHandle, &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
	if (status != ERROR_SUCCESS) {
		printf("[!] EnableTraceEx2 failed!\n");
		return -1;
	}
	return 0;
}


int main(int argc, char** argv) {
	HANDLE hDriver;

	printf("\t\t-=[ Shabby PktMon by @TheXC3LL ]=-\n\n");

	printf("[*] Starting PktMon service...\n");
	hDriver = PktMonServiceStart();
	if (hDriver == NULL) {
		printf("\t[!] Error! Service PktMon could not be started!\n\n");
		return -1;
	}
	printf("\t[+] SERVICE STARTED SUCCESSFULLY! (Handle: %d)\n", hDriver);

	printf("[*] Initating Event Tracer...\n");
	if (initiateTrace() == -1) {
		printf("\t[!] Error! Could not start the event tracer!\n");
		return -1;
	}
	printf("\t[+] EVENT TRACER STARTED SUCCESSFULLY!\n");

	printf("[*] Adding a filter and initializing capture...\n");
	if (initiateCapture(hDriver) == -1) {
		printf("\t[!] Error! Could not start capturing!\n");
		return -1;
	}
	printf("\n[+] CAPTURE INITIATED SUCCESSFULLY!\n");
	return 0;
}
```


# EoF

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).



