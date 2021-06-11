---
title: "Don't use commands, use code: the tale of Netsh & PortProxy"
date: 2021-06-11 00:00:00 +00:00
modified: 2021-06-11 00:00:00 +00:00
tags: [red team, research, X-C3LL]
description: Understanding how netsh & portproxy works and how to implement it on our own code
image: 
---

Dear Fell**owl**ship, today's homily is a call to an (un)holy crusade: we have to banish the usage of commands in compromised machines and start to embrace coding. Please, take a seat and listen to the story of netsh and PortProxy.

# Prayers at the foot of the Altar a.k.a. disclaimer
*The intention of this short article is to encourage people to improve their tradecraft. We use netsh here as a mere example to transmit the core idea: we need to move from commands to tasks coded in our implants/tools.*

# Introduction
There are tons of ways to tunnel your traffic through a compromised machine. Probably the most common can be dropping an implant that implements a SOCKS4/5 proxy, so you can route your traffic through that computer and run your tools against other network segments previously inaccessible. But in some scenarios we can't just deploy our socks proxy listening to an arbitrary port and we need to rely on native tools, like the well-known **netsh**.

Forwarding traffic from one port to another machine is trivial with netsh. For example, if we want to connect to the RDP service exposed by a server (let's call it C) at 10.2.0.12 and we need to use B (10.1.0.233) as pivot, the command line would look like:

```
netsh interface portproxy add v4tov4 listenport=1337 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.2.0.12
```

Then we only need to use our favorite RDP client and point it to B (10.1.0.233) at port 1337. Easy peachy. 

But... how netsh works and **what is happening under the hood?** Can we implement this functionality by ourselves so we can avoid the use of the well-known netsh?

# Shedding light

The first thing to do (after googling) when we have to play with something in Windows is to take a look at ReactOS and Wine projects (usually both are a goldmine) but this time we were unlucky:

```c
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(netsh);

int __cdecl wmain(int argc, WCHAR *argv[])
{
    int i;

    WINE_FIXME("stub:");
    for (i = 0; i < argc; i++)
        WINE_FIXME(" %s", wine_dbgstr_w(argv[i]));
    WINE_FIXME("\n");

    return 0;
}
```

So let's try to execute netsh and take a look at it with Process Monitor:

<figure>
<img src="/Netsh-portproxy-code/procmon.png" alt="Netsh setting a registry value">
<figcaption>
Netsh setting a registry value.
</figcaption>
</figure>

In Process Monitor the only thing that is related to "PortProxy" is the creation of a value with the forwarding info (source an destination) inside the key **`HKLM\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp`**. If we google this key we can find a lot of articles talking about DFIR and how this key can be used to detect this particular TTP in forensic analysis (for example: [Port Proxy detection - How can we see port proxy configurations in DFIR?](http://www.dfirnotes.net/portproxy_detection/)). 

If we create manually this registry value nothing happens, so we need something more to trigger the proxy creation. What are we missing? Well, that question is easy to answer. Let's see what happened with our previous netsh execution with TCPView:

<figure>
<img src="/Netsh-portproxy-code/tcpview1.png" alt="svchost and iphlpsvc reference">
<figcaption>
Svchost and iphlpsvc reference.
</figcaption>
</figure>

As we can see iphlpsvc (IP Helper Service) is in charge to create the "portproxy". So netsh should "contact" this service in order to trigger the proxy creation, but how is this done? We should open iphlpsvc.dll inside Binary Ninja and look for references to "PortProxy". (Spoiler: it is using the **`paramchange`** control code, so we can trigger it with `sc` easily)

<figure>
<img src="/Netsh-portproxy-code/bninja1.png" alt="Reference to a registry key with 'PortProxy' word inside">
<figcaption>
Reference to a registry key with 'PortProxy' word inside
</figcaption>
</figure>

We have a hit with a registry key similar to the one that we were looking for...

<figure>
<img src="/Netsh-portproxy-code/bninja2.png" alt="Function chunk that references the registry key found">
<figcaption>
Function chunk that references the registry key found
</figcaption>
</figure>

...so we can start the old and dirty game of following the call cascade (cross-reference party!) until we reach something really interesting (Note: `OnConfigChange` is a function renamed by us):

<figure>
<img src="/Netsh-portproxy-code/bninja3.png" alt="String with the words ServiceHandler and SERVICE_CONTROL_PARAMCHANGE">
<figcaption>
String with the words ServiceHandler and SERVICE_CONTROL_PARAMCHANGE
</figcaption>
</figure>

We got it! If a `paramchange` control code arrives to the `iphlpsvc`, it is going to read again the PortProxy configuration from the registry and act according to the info retrieved. 

We can translate `netsh` PortProxy into the creation of a registry key and then sending a `paramchange` control code to the IP Helper service, or in other words we can execute these commands:

```
reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp /t REG_SZ /v 0.0.0.0/49777 /d 192.168.8.128/80
sc control iphlpsvc paramchange
reg delete HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PortProxy\v4tov4 /f 
```


# From stone to steel

It's time to translate our commands into a shitty PoC in C:
```c
// PortProxy PoC
// @TheXC3LL

#include <Windows.h>
#include <stdio.h>


DWORD iphlpsvcUpdate(void) {
	SC_HANDLE hManager;
	SC_HANDLE hService;
	SERVICE_STATUS serviceStatus;
	DWORD retStatus = 0;
	DWORD ret = -1;

	hManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
	if (hManager) {
		hService = OpenServiceA(hManager, "IpHlpSvc", SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS);
		if (hService) {
			printf("[*] Connected to IpHlpSvc\n");
			retStatus = ControlService(hService, SERVICE_CONTROL_PARAMCHANGE, &serviceStatus);
			if (retStatus) {
				printf("[*] Configuration update requested\n");
				ret = 0;
			}
			else {
				printf("[!] ControlService() failed!\n");
			}
			CloseServiceHandle(hService);
			CloseServiceHandle(hManager);
			return ret;
		}
		CloseServiceHandle(hManager);
		printf("[!] OpenServiceA() failed!\n");
		return ret;
	}
	printf("[!] OpenSCManager() failed!\n");
	return ret;
}

DWORD addEntry(LPSTR source, LPSTR destination) {
	LPCSTR v4tov4 = "SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp";
	HKEY hKey = NULL;
	LSTATUS retStatus = 0;
	DWORD ret = -1;
	
	retStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, v4tov4, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (retStatus == ERROR_SUCCESS) {
		retStatus = (RegSetValueExA(hKey, source, 0, REG_SZ, (LPBYTE)destination, strlen(destination) + 1));
		if (retStatus == ERROR_SUCCESS) {
			printf("[*] New entry added\n");
			ret = 0;
		}
		else {
			printf("[!] RegSetValueExA() failed!\n");
		}
		RegCloseKey(hKey);
		return ret;
	}
	printf("[!] RegCreateKeyExA() failed!\n");
	return ret;
}

DWORD deleteEntry(LPSTR source) {
	LPCSTR v4tov4 = "SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp";
	HKEY hKey = NULL;
	LSTATUS retStatus = 0;
	DWORD ret = -1;

	retStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, v4tov4, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (retStatus == ERROR_SUCCESS) {
		retStatus = RegDeleteKeyValueA(HKEY_LOCAL_MACHINE, v4tov4, source);
		if (retStatus == ERROR_SUCCESS) {
			printf("[*] New entry deleted\n");
			ret = 0;
		}
		else {
			printf("[!] RegDeleteKeyValueA() failed!\n");
		}
		RegCloseKey(hKey);
		return ret;
	}
	printf("[!] RegCreateKeyExA() failed!\n");
	return ret;
}

int main(int argc, char** argv) {
	printf("\t\t-=<[ PortProxy PoC by @TheXC3LL ]>=-\n\n");
	if (argc <= 2) {
		printf("[!] Invalid syntax! Usage: PortProxy.exe SOURCE_IP/PORT DESTINATION_IP/PORT (example: ./PortProxy.exe 0.0.0.0/1337 10.0.2.2/22\n");
	}
	if (addEntry(argv[1], argv[2]) != -1) {
		if (iphlpsvcUpdate() == -1) {
			printf("[!] Something went wrong :S\n");
		}
		if (deleteEntry(argv[1]) == -1) {
				printf("[!] Troubles deleting the entry, please try it manually!!\n");
		}
	}
	return 0;
}
```

Fire in the hole!

<figure>
<img src="/Netsh-portproxy-code/PoC.png" alt="Proof of Concept working like a charm">
<figcaption>
Proof of Concept working like a charm
</figcaption>
</figure>

# EoF
As we stated at the beginning this short article is not about "netsh" or the "PortProxy" functionality. We aim higher: we want to encourage you to stop using commands blindly and to start to dig inside what is doing your machine. Explore and learn the internals of everything you do on an red team operation or a pentest. 

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).
