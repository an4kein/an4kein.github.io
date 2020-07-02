---
title:     "Hack The Box - Bounty"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/1.jpg)

## Enumeration

### Nmap
Vamos comecar a enumeracao usando nosso nmap de sempre

```
root@kali:~/HTB-Windows/bounty# nmap -sV -sC -oA nmap/initial   10.10.10.93
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-26 17:59 EDT
Nmap scan report for 10.10.10.93
Host is up (0.36s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Se voce observou o nmap por padrao so faz o scan em 1000 portas **999 filtered ports**, quando queremos escanear as 65535 portas usamos as opcoes `-p-` ou `-p1-65353` ou voce pode usar tambem opcoes como `--top-ports <NUMERO DE PORTAS>` ou escolher individualmente as portas a serem escaneadas, usando a opcao `-p<SUA PORTA>` LEIA o manual do nmap para aprender mais 


Continuando, ate o momento encontramos apenas a porta 80 aberta e tambem foi feito o scan nas portas TCP dependendo do caso poderia ser necessario fazer scan  nas UDPs tambem.

Navegando ate a porta 80 encontro essa imagem 

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/2.jpg)


Tbm foi feito scan de ports UDP

```
root@kali:~/HTB-Windows/bounty# nmap -sU -sV -sC --top-ports 20 -oN nmap/toppotd_udp 10.10.10.93
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-01 10:05 EDT
Nmap scan report for 10.10.10.93
Host is up (0.18s latency).

PORT      STATE         SERVICE      VERSION
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
|_ike-version: ERROR: Script execution failed (use -d to debug)
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
```

Como temos no momentos a porta 80 para trabalhar, entao vamos brincar com ela

```
root@kali:~/HTB-Windows/bounty# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -x asp,aspx,bat,c,cfm,cgi,css,com,dll,exe,htm,html,inc,jhtml,js,jsa,jsp,l
og,mdb,nsf,pcap,php,php2,php3,php4,php5,php6,php7,phps,pht,phtml,pl,reg,sh,shtml,sql,swf,txt,xml -u http://bounty.htb/ 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bounty.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     jhtml,js,php2,php7,asp,dll,php5,aspx,com,pcap,pl,shtml,swf,cfm,cgi,phps,txt,inc,jsp,php4,pht,phtml,sql,jsa,mdb,nsf,php,php6,reg,bat,html,xml,c,sh,htm,l
og,php3,css,exe                           
[+] Timeout:        10s
===============================================================
2020/07/01 10:46:36 Starting gobuster
===============================================================
/aspnet_client (Status: 301)
```

Usando o vulnscan(https://github.com/scipag/vulscan), antes desse passo eu ja tinha rodado o `gobuster` mas nada muito util por enquanto

```
# Nmap 7.80 scan initiated Wed Jul  1 13:20:40 2020 as: nmap -p80 -sV --script=vulscan/vulscan.nse -oN nmap/vulnscan 10.10.10.93
Nmap scan report for bounty.htb (10.10.10.93)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| vulscan: VulDB - https://vuldb.com:
| [68404] Microsoft IIS 7.5 Error Message mypage cross site scripting
| [6924] Microsoft IIS 7.5 Log File Permission information disclosure
| [5623] Microsoft IIS up to 7.5 File Name Tilde privilege escalation
| [4234] Microsoft IIS 7.5 FTP Server Telnet IAC Character Heap-based denial of service
| [4179] Microsoft IIS 7.5 FastCGI Request Header memory corruption
| [98097] Microsoft IIS 7.0/7.5/8.0/8.5/10 /uncpath/ cross site scripting
| [6925] Microsoft IIS 7.0/7.5 FTP Command information disclosure
| [4484] Microsoft Windows Phone 7.5 SMS Service denial of service
| 
| MITRE CVE - https://cve.mitre.org:
| [CVE-2012-2532] Microsoft FTP Service 7.0 and 7.5 for Internet Information Services (IIS) processes unspecified commands before TLS is enabled for a session, which allows remote attackers to obtain sensitive information by reading the replies to these commands, aka "FTP Command Injection Vulnerability."
| [CVE-2012-2531] Microsoft Internet Information Services (IIS) 7.5 uses weak permissions for the Operational log, which allows local users to discover credentials by reading this file, aka "Password Disclosure Vulnerability."
| [CVE-2010-3972] Heap-based buffer overflow in the TELNET_STREAM_CONTEXT::OnSendData function in ftpsvc.dll in Microsoft FTP Service 7.0 and 7.5 for Internet Information Services (IIS) 7.0, and IIS 7.5, allows remote attackers to execute arbitrary code or cause a denial of service (daemon crash) via a crafted FTP command, aka "IIS FTP Service Heap Buffer Overrun Vulnerability." NOTE: some of these details are obtained from third party information.
| [CVE-2010-2730] Buffer overflow in Microsoft Internet Information Services (IIS) 7.5, when FastCGI is enabled, allows remote attackers to execute arbitrary code via crafted headers in a request, aka "Request Header Buffer Overflow Vulnerability."
| [CVE-2010-1899] Stack consumption vulnerability in the ASP implementation in Microsoft Internet Information Services (IIS) 5.1, 6.0, 7.0, and 7.5 allows remote attackers to cause a denial of service (daemon outage) via a crafted request, related to asp.dll, aka "IIS Repeated Parameter Request Denial of Service Vulnerability."
| [CVE-2010-1256] Unspecified vulnerability in Microsoft IIS 6.0, 7.0, and 7.5, when Extended Protection for Authentication is enabled, allows remote authenticated users to execute arbitrary code via unknown vectors related to "token checking" that trigger memory corruption, aka "IIS Authentication Memory Corruption Vulnerability."
| [CVE-2013-0941] EMC RSA Authentication API before 8.1 SP1, RSA Web Agent before 5.3.5 for Apache Web Server, RSA Web Agent before 5.3.5 for IIS, RSA PAM Agent before 7.0, and RSA Agent before 6.1.4 for Microsoft Windows use an improper encryption algorithm and a weak key for maintaining the stored data of the node secret for the SecurID Authentication API, which allows local users to obtain sensitive information via cryptographic attacks on this data.
| [CVE-2010-3229] The Secure Channel (aka SChannel) security package in Microsoft Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7, when IIS 7.x is used, does not properly process client certificates during SSL and TLS handshakes, which allows remote attackers to cause a denial of service (LSASS outage and reboot) via a crafted packet, aka "TLSv1 Denial of Service Vulnerability."
| [CVE-2010-1886] Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 SP2 and R2, and Windows 7 allow local users to gain privileges by leveraging access to a process with NetworkService credentials, as demonstrated by TAPI Server, SQL Server, and IIS processes, and related to the Windows Service Isolation feature.  NOTE: the vendor states that privilege escalation from NetworkService to LocalSystem does not cross a "security boundary."
| [CVE-2009-3555] The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Internet Information Services (IIS) 7.0, mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5 and earlier, Mozilla Network Security Services (NSS) 3.12.4 and earlier, multiple Cisco products, and other products, does not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context, related to a "plaintext injection" attack, aka the "Project Mogul" issue.
| [CVE-2009-2521] Stack consumption vulnerability in the FTP Service in Microsoft Internet Information Services (IIS) 5.0 through 7.0 allows remote authenticated users to cause a denial of service (daemon crash) via a list (ls) -R command containing a wildcard that references a subdirectory, followed by a .. (dot dot), aka "IIS FTP Service DoS Vulnerability."
| [CVE-2009-1536] ASP.NET in Microsoft .NET Framework 2.0 SP1 and SP2 and 3.5 Gold and SP1, when ASP 2.0 is used in integrated mode on IIS 7.0, does not properly manage request scheduling, which allows remote attackers to cause a denial of service (daemon outage) via a series of crafted HTTP requests, aka "Remote Unauthenticated Denial of Service in ASP.NET Vulnerability."
| [CVE-2008-1446] Integer overflow in the Internet Printing Protocol (IPP) ISAPI extension in Microsoft Internet Information Services (IIS) 5.0 through 7.0 on Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, and Server 2008 allows remote authenticated users to execute arbitrary code via an HTTP POST request that triggers an outbound IPP connection from a web server to a machine operated by the attacker, aka "Integer Overflow in IPP Service Vulnerability."
| [CVE-2008-0074] Unspecified vulnerability in Microsoft Internet Information Services (IIS) 5.0 through 7.0 allows local users to gain privileges via unknown vectors related to file change notifications in the TPRoot, NNTPFile\Root, or WWWRoot folders.
| [CVE-2007-2931] Heap-based buffer overflow in Microsoft MSN Messenger 6.2, 7.0, and 7.5, and Live Messenger 8.0 allows user-assisted remote attackers to execute arbitrary code via unspecified vectors involving video conversation handling in Web Cam and video chat sessions.
| [CVE-2007-1278] Unspecified vulnerability in the IIS connector in Adobe JRun 4.0 Updater 6, and ColdFusion MX 6.1 and 7.0 Enterprise, when using Microsoft IIS 6, allows remote attackers to cause a denial of service via unspecified vectors, involving the request of a file in the JRun web root.
| [CVE-2006-5858] Adobe ColdFusion MX 7 through 7.0.2, and JRun 4, when run on Microsoft IIS, allows remote attackers to read arbitrary files, list directories, or read source code via a double URL-encoded NULL byte in a ColdFusion filename, such as a CFM file.
| [CVE-2006-5028] Directory traversal vulnerability in filemanager/filemanager.php in SWsoft Plesk 7.5 Reload and Plesk 7.6 for Microsoft Windows allows remote attackers to list arbitrary directories via a ../ (dot dot slash) in the file parameter in a chdir action.
| [CVE-2006-0363] The "Remember my Password" feature in MSN Messenger 7.5 stores passwords in an encrypted format under the HKEY_CURRENT_USER\Software\Microsoft\IdentityCRL\Creds registry key, which might allow local users to obtain the original passwords via a program that calls CryptUnprotectData, as demonstrated by the "MSN Password Recovery.exe" program.  NOTE: it could be argued that local-only password recovery is inherently insecure because the decryption methods and keys must be stored somewhere on the local system, and are thus inherently accessible with varying degrees of effort.  Perhaps this issue should not be included in CVE.
| 
| SecurityFocus - https://www.securityfocus.com/bid/:
| [55569] Microsoft Windows Phone 7 SSL Certificate 'Common Name' Validation Security Bypass Vulnerability
| [28820] Microsoft Works 7 'WkImgSrv.dll' ActiveX Control Remote Code Execution Vulnerability
| [28498] Microsoft Internet Explorer 7 Popup Window Address Bar URI Spoofing Vulnerability
| [24483] Microsoft Internet Explorer 7 HTTP Authentication International Domain Name Spoofing Weakness
| [20728] Microsoft Internet Explorer 7 Popup Window Address Bar Spoofing Weakness
| [18736] Microsoft Internet Explorer 7 Denial of Service Vulnerability
| [5877] Microsoft SQL Server 7.0/2000 DBCC Buffer Overflow Vulnerability
| [4108] Microsoft Visual C++ 7/Visual C++.Net Buffer Overflow Protection Weakness
| [1714] Microsoft Windows Media Player 7 Embedded OCX Control Vulnerability
| [1444] Microsoft SQL Server 7.0 Stored Procedure Vulnerability
| [1281] Microsoft SQL Server 7.0 System Administrator Password Disclosure Vulnerability
| [817] Microsoft SQL Server 7.0 NULL Data DoS Vulnerability
| [90065] Microsoft Windows Kernel 'Win32k.sys' CVE-2016-0174 Local Privilege Escalation Vulnerability
| [86059] Microsoft IIS CVE-1999-0561 Remote Security Vulnerability
| [56440] Microsoft IIS FTP Service CVE-2012-2532 Remote Command Injection Vulnerability
| [56439] Microsoft IIS CVE-2012-2531 Password Information Disclosure Vulnerability
| [54276] Microsoft IIS Multiple FTP Command Request Denial of Service Vulnerability
| [54251] Microsoft IIS File Enumeration Weakness
| [53906] Microsoft IIS Authentication Bypass and Source Code Disclosure Vulnerabilities
| [45542] Microsoft IIS FTP Service Remote Buffer Overflow Vulnerability
| [43140] Microsoft IIS Repeated Parameter Request Denial of Service Vulnerability
| [43138] Microsoft IIS Request Header Buffer Overflow Vulnerability
| [41314] Microsoft IIS 5.1 Alternate Data Stream Authentication Bypass Vulnerability
| [40573] Microsoft IIS Authentication Remote Code Execution Vulnerability
| [37460] RETIRED: Microsoft IIS Malformed Local Filename Security Bypass Vulnerability
| [36276] RETIRED: Microsoft IIS FTPd Globbing Functionality Remote Denial of Service Vulnerability
| [36273] Microsoft IIS FTPd Globbing Functionality Remote Denial of Service Vulnerability
| [36189] Microsoft IIS FTPd NLST Remote Buffer Overflow Vulnerability
| [35232] Microsoft IIS 5.0 WebDAV Authentication Bypass Vulnerability
| [34993] Microsoft IIS Unicode Requests to WebDAV Multiple Authentication Bypass Vulnerabilities
| [33374] Microsoft IIS HTTP TRACK Method Information Disclosure Vulnerability
| [27101] Microsoft IIS File Change Notification Local Privilege Escalation Vulnerability
| [21865] Apache And Microsoft IIS Range Denial of Service Vulnerability
| [18858] Microsoft IIS ASP Remote Code Execution Vulnerability
| [14764] Microsoft IIS WebDAV HTTP Request Source Code Disclosure Vulnerability
| [10706] Microsoft IIS 4 Redirect Remote Buffer Overflow Vulnerability
| [9660] Microsoft IIS Unspecified Remote Denial Of Service Vulnerability
| [9313] Microsoft IIS Failure To Log Undocumented TRACK Requests Vulnerability
| [8244] Microsoft Multiple IIS 6.0 Web Admin Vulnerabilities
| [8092] Microsoft IIS _VTI_BOT Malicious WebBot Elevated Permissions Vulnerability
| [8035] Microsoft Windows Media Services NSIISlog.DLL Remote Buffer Overflow Vulnerability
| [7735] Microsoft IIS WebDAV PROPFIND and SEARCH Method Denial of Service Vulnerability
| [7734] Microsoft IIS SSINC.DLL Server Side Includes Buffer Overflow Vulnerability
| [7733] Microsoft IIS ASP Header Denial Of Service Vulnerability
| [7731] Microsoft IIS Redirection Error Page Cross-Site Scripting Vulnerability
| [7492] Microsoft IIS User Existence Disclosure Vulnerability
| [6795] Microsoft IIS False Logging Weakness
| [6789] Microsoft IIS Malformed HTTP Get Request Denial Of Service Vulnerability
| [6072] Microsoft IIS Administrative Pages Cross Site Scripting Vulnerabilities
| [6071] Microsoft IIS Script Source Access File Upload Vulnerability
| [6070] Microsoft IIS WebDAV Denial Of Service Vulnerability
| [6069] Microsoft IIS Out Of Process Privilege Escalation Vulnerability
| [6068] Multiple Microsoft IIS Vulnerabilities
| [5907] Microsoft IIS Malformed HTTP HOST Header Field Denial Of Service Vulnerability
| [5900] Microsoft IIS IDC Extension Cross Site Scripting Vulnerability
| [5213] Microsoft IIS SMTP Service Encapsulated SMTP Address Vulnerability
| [4855] Microsoft IIS HTR Chunked Encoding Transfer Heap Overflow Vulnerability
| [4846] Microsoft IIS 5.0 Denial Of Service Vulnerability
| [4543] Microsoft IIS CodeBrws.ASP File Extension Check Out By One Vulnerability
| [4525] Microsoft IIS CodeBrws.ASP Source Code Disclosure Vulnerability
| [4490] Microsoft IIS Chunked Encoding Heap Overflow Variant Vulnerability
| [4487] Microsoft IIS HTTP Redirect Cross Site Scripting Vulnerability
| [4486] Microsoft IIS HTTP Error Page Cross Site Scripting Vulnerability
| [4485] Microsoft IIS Chunked Encoding Transfer Heap Overflow Vulnerability
| [4483] Microsoft IIS Help File Search Cross Site Scripting Vulnerability
| [4482] Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability
| [4479] Microsoft IIS ISAPI Filter Access Violation Denial of Service Vulnerability
| [4478] Microsoft IIS ASP Server-Side Include Buffer Overflow Vulnerability
| [4476] Microsoft IIS HTTP Header Field Delimiter Buffer Overflow Vulnerability
| [4474] Microsoft IIS HTR ISAPI Extension Buffer Overflow Vulnerability
| [4235] Microsoft IIS Authentication Method Disclosure Vulnerability
| [4084] Microsoft IIS 5.1 Frontpage Server Extensions File Source Disclosure Vulnerability
| [4078] Microsoft IIS 5.1 Frontpage Extensions Path Disclosure Information Vulnerability
| [3667] Microsoft IIS False Content-Length Field DoS Vulnerability
| [3195] Microsoft IIS MIME Header Denial of Service Vulnerability
| [3194] Microsoft IIS WebDAV Invalid Request Denial of Service Vulnerability
| [3193] Microsoft IIS 5.0 In-Process Table Privelege Elevation Vulnerability
| [3191] Microsoft IIS 4.0 URL Redirection DoS Vulnerability
| [3190] Microsoft IIS SSI Buffer Overrun Privelege Elevation Vulnerability
| [2977] Microsoft IIS Device File Remote DoS Vulnerability
| [2973] Microsoft IIS Device File Local DoS Vulnerability
| [2909] Microsoft IIS Unicode .asp Source Code Disclosure Vulnerability
| [2719] Microsoft IIS Various Domain User Account Access Vulnerability
| [2717] Microsoft IIS FTP Denial of Service Vulnerability
| [2690] Microsoft IIS WebDAV 'Propfind' Server Restart Vulnerability
| [2674] Microsoft  IIS 5.0 .printer ISAPI Extension Buffer Overflow Vulnerability
| [2654] Microsoft IIS Long URL Denial of Service Vulnerability
| [2483] Microsoft IIS WebDAV 'Search' Denial of Service Vulnerability
| [2453] Microsoft IIS WebDAV Denial of Service Vulnerability
| [2441] Microsoft Exchange 2000 / IIS 5.0 Multiple Invalid URL Request DoS Vulnerability
| [2440] Microsoft IIS Multiple Invalid URL Request DoS Vulnerability
| [2313] Microsoft IIS File Fragment Disclosure Vulnerability
| [2280] Microsoft IIS 3.0/4.0 Upgrade BDIR.HTR Vulnerability
| [2218] Microsoft IIS '../..' Denial of Service Vulnerability
| [2144] Microsoft IIS Front Page Server Extension DoS Vulnerability
| [2110] Microsoft IIS 4.0 IISADMPWD Proxied Password Attack
| [2100] Microsoft IIS Far East Edition DBCS File Disclosure Vulnerability
| [2074] Microsoft IIS Appended Dot Script Source Disclosure Vulnerability
| [1912] Microsoft IIS Executable File Parsing Vulnerability
| [1911] Microsoft IIS 4.0 ISAPI Buffer Overflow Vulnerability
| [1832] Microsoft IIS 4.0/5.0 Session ID Cookie Disclosure Vulnerability
| [1819] Microsoft IIS 4.0 Pickup Directory DoS Vulnerability
| [1818] Microsoft IIS 3.0 newdsn.exe File Creation Vulnerability
| [1814] Microsoft IIS 3.0 %2e ASP Source Disclosure Vulnerability
| [1811] Microsoft Site Server 2.0 with IIS 4.0 Malicious File Upload Vulnerability
| [1806] Microsoft IIS and PWS Extended Unicode Directory Traversal Vulnerability
| [1756] Microsoft IIS 5.0 Indexed Directory Disclosure Vulnerability
| [1642] Microsoft NT 4.0 and IIS 4.0 Invalid URL Request DoS Vulnerability
| [1595] Microsoft IIS Cross Site Scripting .shtml Vulnerability
| [1594] Microsoft FrontPage/IIS Cross Site Scripting shtml.dll Vulnerability
| [1578] Microsoft IIS 5.0 Translate: f Source Disclosure Vulnerability
| [1565] Microsoft IIS 4.0/5.0 File Permission Canonicalization Vulnerability
| [1499] Microsoft IIS Internal IP Address Disclosure Vulnerability
| [1488] Microsoft IIS 4.0/5.0 Source Fragment Disclosure Vulnerability
| [1476] Microsoft IIS 3.0 .htr Missing Variable Denial of Service Vulnerability
| [1193] Microsoft IIS 4.0/5.0 Malformed Filename Request Vulnerability
| [1191] Microsoft IIS 4.0/5.0 Malformed .htr Request Vulnerability
| [1190] Microsoft IIS 4.0/5.0 Malformed File Extension DoS Vulnerability
| [1101] Microsoft IIS 4.0/5.0 Escaped Characters Vulnerability
| [1081] Microsoft IIS UNC Mapped Virtual Host Vulnerability
| [1066] Microsoft IIS 4.0 Chunked Transfer Encoding Buffer Overflow Vulnerability
| [1065] Microsoft IIS UNC Path Disclosure Vulnerability
| [886] Microsoft IIS Escape Character Parsing Vulnerability
| [882] Microsoft IIS Virtual Directory Naming Vulnerability
| [658] Microsoft IIS FTP NO ACCESS Read/Delete File Vulnerability
| [657] Microsoft IIS 4.0 Domain Resolution Vulnerability
| [582] Microsoft IIS And PWS 8.3 Directory Name Vulnerability
| [190] Microsoft VisualInterDev 6.0 - IIS4- Management With No Authentication Vulnerability
| 
| IBM X-Force - https://exchange.xforce.ibmcloud.com:
| [78620] Microsoft Windows Phone 7 domain name spoofing
| [66401] Microsoft Windows kernel-mode driver (win32k.sys) variant 7 privilege escalation
| [29670] Microsoft Internet Explorer 7 is installed
| [76716] Microsoft IIS FTP denial of service
| [76664] Microsoft IIS tilde information disclosure
| [61513] Microsoft Internet Information Services (IIS) URL authentication bypass
| [58864] Microsoft Internet Information Services (IIS) authentication code execution
| [55031] Microsoft Internet Information Services (IIS) filenames security bypass
| [53034] Microsoft Internet Information Services (IIS) directory listings denial of service
| [52915] Microsoft Internet Information Services (IIS) FTP buffer overflow
| [52243] Microsoft IIS With .NET Path Disclosure
| [52241] Microsoft IIS servervariables_vbscript.asp Information Disclosure
| [52240] Microsoft IIS Sample Application Physical Path Disclosure
| [52233] Microsoft IIS With .NET Path Disclosure
| [50573] Microsoft Internet Information Services (IIS) WebDAV security bypass
| [45584] Microsoft IIS adsiis.dll ActiveX control denial of service
| [42899] Microsoft IIS HTTP request smuggling
| [39235] Microsoft IIS root folders file change notification privilege escalation
| [39230] Microsoft IIS HTML encoded ASP code execution
| [34434] Microsoft IIS Hit-highlighting security bypass
| [34418] Microsoft Internet Information Server (IIS) AUX/.aspx denial of service
| [32074] Microsoft IIS iissamples directory present
| [31644] Microsoft IIS Web server access.cnf file detected
| [31642] Microsoft IIS Web server service.cnf file detected
| [31638] Microsoft IIS Web server svcacl.cnf file detected
| [31630] Microsoft Internet Information Services IISAdmin directory detected
| [27854] Microsoft IIS ASP cache virtual server information disclosure
| [26796] Microsoft Internet Information Services (IIS) ASP buffer overflow
| [16872] Microsoft Internet Information Server (IIS) ActivePerl command execution
| [16656] Microsoft Internet Information Server (IIS) MS04-021 patch is not installed
| [16578] Microsoft Internet Information Server (IIS) redirect buffer overflow
| [14077] Microsoft Internet Information Server (IIS) fails to properly log HTTP TRACK requests
| [13116] Microsoft IIS MS03-018 patch is not installed on the system
| [13088] Microsoft IIS running RealSecure Server Sensor ISAPI plug-in denial of service
| [12687] Microsoft IIS Remote Administration Tool allows attacker to reset administrative password
| [12686] Microsoft IIS Remote Administration Tool could allow an attacker to obtain valid session IDs
| [12652] Microsoft Windows 2000 and NT 4.0 Server IIS ISAPI nsiislog.dll extension POST request buffer overflow
| [12100] Microsoft IIS long WebDAV requests containing XML denial of service
| [12099] Microsoft IIS Response.AddHeader denial of service
| [12098] Microsoft IIS Server-Side Include (SSI) long file name buffer overflow
| [12097] Microsoft IIS redirect error cross-site scripting
| [12092] Microsoft Windows 2000 and NT 4.0 Server IIS ISAPI nsiislog.dll extension buffer overflow
| [11918] Microsoft IIS authentication mechanism could allow an attacker to determine valid user account names
| [11537] Microsoft IIS WebDAV service is running on the system
| [11533] Microsoft IIS WebDAV long request buffer overflow
| [10590] Microsoft Internet Information Server (IIS) MS02-062 patch
| [10504] Microsoft IIS script source access could be bypassed to upload .COM files
| [10503] Microsoft IIS WebDAV memory allocation denial of service
| [10502] Microsoft IIS out-of-process applications could be used to gain elevated privileges
| [10501] Microsoft IIS administrative Web pages cross-site scripting
| [10370] Microsoft IIS HTTP HOST header denial of service
| [10294] Microsoft IIS .idc extension error message cross-site scripting
| [10184] Microsoft IIS 5.0 resource utilization denial of service
| [9791] Microsoft Exchange IIS license exhaustion denial of service
| [9580] Microsoft IIS SMTP service encapsulated addresses could allow mail relaying
| [9327] Microsoft IIS ISAPI HTR chunked encoding heap buffer overflow
| [9123] Microsoft IIS 5.0 Log Files Directory Permission Exposure
| [8853] Microsoft IIS CodeBrws.asp sample script can be used to view arbitrary file source code
| [8811] Microsoft IIS MS02-018 patch is not installed on the system
| [8804] Microsoft IIS redirected URL error cross-site scripting
| [8803] Microsoft IIS HTTP error page cross-site scripting
| [8802] Microsoft IIS Help File search cross-site scripting
| [8801] Microsoft IIS FTP session status request denial of service
| [8800] Microsoft IIS FrontPage Server Extensions and ASP.NET ISAPI filter error handling denial of service
| [8799] Microsoft IIS HTR ISAPI ISM.DLL extension buffer overflow
| [8798] Microsoft IIS SSI safety check buffer overflow
| [8797] Microsoft IIS ASP HTTP header parsing buffer overflow
| [8796] Microsoft IIS ASP data transfer heap buffer overflow
| [8795] Microsoft IIS ASP chunked encoding heap buffer overflow
| [8388] Microsoft Windows NT Server with IIS 4.0 could allow users to bypass &quot
| [8385] Microsoft IIS specially-crafted request reveals IP address
| [8382] Microsoft IIS authentication error messages reveal configuration information
| [8191] Microsoft IIS 5.1 specially-crafted .cnf file request could reveal file contents
| [8174] Microsoft IIS 5.1 .cnf file request could reveal sensitive information
| [8056] Microsoft IIS is running on the system
| [7919] Microsoft IIS 4.0 and Norton Internet Security 2001 default permissions could allow an attacker to modify log files
| [7691] Microsoft IIS HTTP GET request with false &quot
| [7640] Microsoft IIS is present on the system
| [7613] Microsoft IIS allows attackers to create fake log entries
| [7566] Microsoft IIS 2.0 and 3.0 upgraded to Microsoft IIS 4.0 fails to remove the ism.dll file
| [7559] Microsoft Index Server installed with IIS 4.0 could allow a local attacker to obtain physical path information
| [7558] Microsoft IIS FileSystemObject in showfile.asp could allow remote attackers to read arbitrary files
| [7202] Microsoft IIS 4.0/5.0 escaped percent found
| [7201] Microsoft IIS 4.0/5.0 malformed double percent sequence
| [7199] Microsoft IIS 4.0/5.0 malformed hex sequence
| [6995] Microsoft IIS %u Unicode wide character encoding detected
| [6994] Microsoft IIS %u Unicode encoding detected
| [6985] Microsoft IIS relative path usage in system file process table could allow elevated privileges
| [6984] Microsoft IIS specially-crafted SSI directives buffer overflow
| [6983] Microsoft IIS invalid MIME header denial of service
| [6982] Microsoft IIS WebDAV long invalid request denial of service
| [6981] Microsoft IIS URL redirection denial of service
| [6963] Microsoft IIS HTTPS connection could reveal internal IP address
| [6858] Microsoft IIS cross-site scripting patch denial of service
| [6800] Microsoft IIS device file request can crash the ASP processor
| [6742] Microsoft IIS reveals .asp source code with Unicode extensions
| [6705] Microsoft IIS idq.dll ISAPI extension buffer overflow
| [6549] Microsoft IIS WebDAV lock method memory leak can cause a denial of service
| [6545] Microsoft IIS FTP weak domain authentication
| [6535] Microsoft IIS FTP wildcard processing function denial of service
| [6534] Microsoft IIS URL decoding error could allow remote code execution
| [6485] Microsoft IIS 5.0 ISAPI Internet Printing Protocol extension buffer overflow
| [6205] Microsoft IIS WebDAV denial of service
| [6171] Microsoft IIS and Exchange malformed URL request denial of service
| [6029] Microsoft IIS CmdAsp could allow remote attackers to gain privileges
| [5903] Microsoft IIS 5.0 allows the viewing of files through malformed URL
| [5823] Microsoft IIS Web form submission denial of service
| [5729] Microsoft IIS Far East editions file disclosure
| [5510] Microsoft Internet Information Service (IIS) ISAPI buffer overflow
| [5470] Microsoft Internet Information Service (IIS) invalid executable filename passing
| [5441] Microsoft IIS .htw cross-site scripting
| [5377] Microsoft IIS Unicode translation error allows remote command execution
| [5335] Microsoft IIS Index Server directory traversal
| [5202] Microsoft IIS invalid URL allows attackers to crash service
| [5156] Microsoft IIS Cross-Site Scripting
| [5106] Microsoft IIS 4.0 discloses internal IP addresses
| [5104] Microsoft IIS allows remote attackers to obtain source code fragments using +.htr
| [5071] Microsoft IIS canonicalization error applies incorrect permissions to certain types of files
| [4960] Microsoft IIS on Win2kPro security button restriction
| [4951] Microsoft IIS absent directory browser argument
| [4790] Microsoft IIS \mailroot\pickup directory denial of service
| [4757] Microsoft IIS server-side includes (SSI) #exec directive
| [4558] Microsoft IIS is installed on a domain controller
| [4448] Microsoft IIS ISM.DLL could allow users to read file contents
| [4430] Microsoft IIS malformed URL extension data denial of service
| [4392] Microsoft IIS could reveal source code of ASP files in some virtual directories
| [4302] Microsoft IIS malformed AuthChangUrl request can cause the server to stop servicing requests
| [4279] Microsoft IIS escape characters denial of service
| [4204] Microsoft IIS virtual UNC share source read
| [4183] Microsoft IIS could disclose path of network shares
| [4117] Microsoft IIS chunked encoding post or put denial of service
| [3986] Microsoft IIS ASP could be used to gain sensitive information
| [3892] Microsoft IIS Long URL with excessive forward slashes passed to ASP causes an access violation
| [3306] Microsoft IIS could allow remote access to servers marked as Restrict Access
| [3115] Microsoft IIS and SiteServer denial of service caused by malformed HTTP requests
| [2675] Microsoft IIS 4.0 samples installation on Web server
| [2673] Microsoft IIS samples installation on Web server
| [2671] Microsoft IIS Passive FTP patch not applied (asp.dll out of date)
| [2670] Microsoft IIS Passive FTP patch not applied (wam.dll out of date)
| [2669] Microsoft IIS Passive FTP patch not applied (w3svc.dll out of date)
| [2668] Microsoft IIS Passive FTP patch not applied (infocomm.dll out of date)
| [2662] Microsoft IIS CGI overflow
| [2412] Microsoft IIS account is member of Domain Users
| [2381] Microsoft IIS and SiteServer Showcode.asp sample file allows remote file viewing
| [2302] Microsoft IIS using double-byte code pages could allow remote attackers to retrieve source code
| [2282] Microsoft IIS bdir.htr allows remote traversal of directory structure
| [2281] Microsoft IIS buffer overflow in HTR requests can allow remote code execution
| [2229] Microsoft IIS ExAir sample site denial of service
| [2185] Microsoft IIS and Site Server sample programs can be used to remotely view files
| [1823] Microsoft IIS long GET request denial of service
| [1735] Microsoft IIS with Visual InterDev no authentication
| [1656] Microsoft IIS 4.0 allows user to avoid HTTP request logging
| [1654] Microsoft IIS remote FTP buffer overflow
| [1638] Microsoft IIS crashes processing some GET commands
| [1530] Microsoft IIS 3.0 newdsn.exe sample application allows remote creation of arbitrary files
| [1368] Microsoft IIS 4.0 allows file execution in the Web site directory
| [1273] Microsoft IIS special characters allowed in shell
| [1272] Microsoft IIS CGI scripts run as system
| [1271] Microsoft IIS version 2 installed
| [1270] Microsoft IIS incorrect permissions on restricted item
| [1269] Microsoft IIS incorrect Web permissions
| [1268] Microsoft IIS SSI #exec enabled
| [1216] Microsoft IIS SSL patch not applied
| [1215] Microsoft IIS Passive FTP patch not applied
| [1212] Microsoft IIS unauthorized ODBC data access with RDS
| [1125] Microsoft IIS ASP DATA issue could reveal source code
| [949] Microsoft IIS server script debugging enabled
| [948] Microsoft IIS samples installed on Web server
| [936] Microsoft IIS NTFS insecure permissions
| [935] Microsoft IIS executable paths
| [621] Microsoft IIS 3.0 script source revealed by appending 2E to requests
| [336] Microsoft IIS ASP dot bug
| [256] Microsoft IIS can be remotely crashed by excessively long client requests
| [7] Microsoft IIS ASP source visible
| 
| Exploit-DB - https://www.exploit-db.com:
| [19033] microsoft iis 6.0 and 7.5 - Multiple Vulnerabilities
| [17476] Microsoft IIS FTP Server <= 7.0 Stack Exhaustion DoS [MS09-053]
| 
| OpenVAS (Nessus) - http://www.openvas.org:
| [902914] Microsoft IIS GET Request Denial of Service Vulnerability
| [902796] Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability
| [902694] Microsoft Windows IIS FTP Service Information Disclosure Vulnerability (2761226)
| [901120] Microsoft IIS Authentication Remote Code Execution Vulnerability (982666)
| [900944] Microsoft IIS FTP Server 'ls' Command DOS Vulnerability
| [900874] Microsoft IIS FTP Service Remote Code Execution Vulnerabilities (975254)
| [900711] Microsoft IIS WebDAV Remote Authentication Bypass Vulnerability
| [900567] Microsoft IIS Security Bypass Vulnerability (970483)
| [802806] Microsoft IIS Default Welcome Page Information Disclosure Vulnerability
| [801669] Microsoft Windows IIS FTP Server DOS Vulnerability
| [801520] Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability
| [100952] Microsoft IIS FTPd NLST stack overflow
| [11443] Microsoft IIS UNC Mapped Virtual Host Vulnerability
| [10680] Test Microsoft IIS Source Fragment Disclosure
| [903041] Microsoft Windows Kernel Privilege Elevation Vulnerability (2724197)
| [903037] Microsoft JScript and VBScript Engines Remote Code Execution Vulnerability (2706045)
| [903036] Microsoft Windows Networking Components Remote Code Execution Vulnerabilities (2733594)
| [903035] Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerability (2731847)
| [903033] Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2718523)
| [903026] Microsoft Office Remote Code Execution Vulnerabilities (2663830)
| [903017] Microsoft Office Remote Code Execution Vulnerability (2639185)
| [903000] Microsoft Expression Design Remote Code Execution Vulnerability (2651018)
| [902936] Microsoft Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2783534)
| [902934] Microsoft .NET Framework Remote Code Execution Vulnerability (2745030)
| [902933] Microsoft Windows Shell Remote Code Execution Vulnerabilities (2727528)
| [902932] Microsoft Internet Explorer Multiple Use-After-Free Vulnerabilities (2761451)
| [902931] Microsoft Office Remote Code Execution Vulnerabilities - 2720184 (Mac OS X)
| [902930] Microsoft Office Remote Code Execution Vulnerabilities (2720184)
| [902923] Microsoft Internet Explorer Multiple Vulnerabilities (2722913)
| [902922] Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2723135)
| [902921] Microsoft Office Visio/Viewer Remote Code Execution Vulnerability (2733918)
| [902920] Microsoft Office Remote Code Execution Vulnerability (2731879)
| [902919] Microsoft SharePoint Privilege Elevation Vulnerabilities (2663841)
| [902916] Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2711167)
| [902913] Microsoft Office Remote Code Execution Vulnerabilities-2663830 (Mac OS X)
| [902912] Microsoft Office Word Remote Code Execution Vulnerability-2680352 (Mac OS X)
| [902911] Microsoft Office Word Remote Code Execution Vulnerability (2680352)
| [902910] Microsoft Office Visio Viewer Remote Code Execution Vulnerability (2597981)
| [902909] Microsoft Windows Service Pack Missing Multiple Vulnerabilities
| [902908] Microsoft Windows DirectWrite Denial of Service Vulnerability (2665364)
| [902906] Microsoft Windows DNS Server Denial of Service Vulnerability (2647170)
| [902900] Microsoft Windows SSL/TLS Information Disclosure Vulnerability (2643584)
| [902846] Microsoft Windows TLS Protocol Information Disclosure Vulnerability (2655992)
| [902845] Microsoft Windows Shell Remote Code Execution Vulnerability (2691442)
| [902842] Microsoft Lync Remote Code Execution Vulnerabilities (2707956)
| [902841] Microsoft .NET Framework Remote Code Execution Vulnerability (2706726)
| [902839] Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability
| [902833] Microsoft .NET Framework Remote Code Execution Vulnerability (2693777)
| [902832] MS Security Update For Microsoft Office, .NET Framework, and Silverlight (2681578)
| [902829] Microsoft Windows Common Controls Remote Code Execution Vulnerability (2664258)
| [902828] Microsoft .NET Framework Remote Code Execution Vulnerability (2671605)
| [902818] Microsoft Remote Desktop Protocol Remote Code Execution Vulnerabilities (2671387)
| [902817] Microsoft Visual Studio Privilege Elevation Vulnerability (2651019)
| [902811] Microsoft .NET Framework and Microsoft Silverlight Remote Code Execution Vulnerabilities (2651026)
| [902807] Microsoft Windows Media Could Allow Remote Code Execution Vulnerabilities (2636391)
| [902798] Microsoft SMB Signing Enabled and Not Required At Server
| [902797] Microsoft SMB Signing Information Disclosure Vulnerability
| [902785] Microsoft AntiXSS Library Information Disclosure Vulnerability (2607664)
| [902784] Microsoft Windows Object Packager Remote Code Execution Vulnerability (2603381)
| [902783] Microsoft Windows Kernel Security Feature Bypass Vulnerability (2644615)
| [902782] MicroSoft Windows Server Service Remote Code Execution Vulnerability (921883)
| [902766] Microsoft Windows Kernel Privilege Elevation Vulnerability (2633171)
| [902746] Microsoft Active Accessibility Remote Code Execution Vulnerability (2623699)
| [902727] Microsoft Office Excel Remote Code Execution Vulnerabilities (2587505)
| [902708] Microsoft Remote Desktop Protocol Denial of Service Vulnerability (2570222)
| [902696] Microsoft Internet Explorer Multiple Vulnerabilities (2761465)
| [902693] Microsoft Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2761226)
| [902692] Microsoft Office Excel ReadAV Arbitrary Code Execution Vulnerability
| [902689] Microsoft SQL Server Report Manager Cross Site Scripting Vulnerability (2754849)
| [902688] Microsoft System Center Configuration Manager XSS Vulnerability (2741528)
| [902687]  Microsoft Windows Data Access Components Remote Code Execution Vulnerability (2698365)
| [902686] Microsoft Internet Explorer Multiple Vulnerabilities (2719177)
| [902683] Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2685939)
| [902682] Microsoft Internet Explorer Multiple Vulnerabilities (2699988)
| [902678] Microsoft Silverlight Code Execution Vulnerabilities - 2681578 (Mac OS X)
| [902677] Microsoft Windows Prtition Manager Privilege Elevation Vulnerability (2690533)
| [902676] Microsoft Windows TCP/IP Privilege Elevation Vulnerabilities (2688338)
| [902670] Microsoft Internet Explorer Multiple Vulnerabilities (2675157)
| [902663] Microsoft Remote Desktop Protocol Remote Code Execution Vulnerabilities (2671387)
| [902662] MicroSoft SMB Server Trans2 Request Remote Code Execution Vulnerability
| [902660] Microsoft SMB Transaction Parsing Remote Code Execution Vulnerability
| [902658] Microsoft RDP Server Private Key Information Disclosure Vulnerability
| [902649] Microsoft Internet Explorer Multiple Vulnerabilities (2647516)
| [902642] Microsoft Internet Explorer Multiple Vulnerabilities (2618444)
| [902626] Microsoft SharePoint SafeHTML Information Disclosure Vulnerabilities (2412048)
| [902625] Microsoft SharePoint Multiple Privilege Escalation Vulnerabilities (2451858)
| [902613] Microsoft Internet Explorer Multiple Vulnerabilities (2559049)
| [902609] Microsoft Windows CSRSS Privilege Escalation Vulnerabilities (2507938)
| [902598] Microsoft Windows Time Component Remote Code Execution Vulnerability (2618451)
| [902597] Microsoft Windows Media Remote Code Execution Vulnerability (2648048)
| [902596] Microsoft Windows OLE Remote Code Execution Vulnerability (2624667)
| [902588] Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability
| [902581] Microsoft .NET Framework and Silverlight Remote Code Execution Vulnerability (2604930)
| [902580] Microsoft Host Integration Server Denial of Service Vulnerabilities (2607670)
| [902567] Microsoft Office Remote Code Execution Vulnerabilites (2587634)
| [902566] Microsoft Windows WINS Local Privilege Escalation Vulnerability (2571621)
| [902552] Microsoft .NET Framework Chart Control Information Disclosure Vulnerability (2567943)
| [902551] Microsoft .NET Framework Information Disclosure Vulnerability (2567951)
| [902523] Microsoft .NET Framework and Silverlight Remote Code Execution Vulnerability (2514842)
| [902522] Microsoft .NET Framework Remote Code Execution Vulnerability (2538814)
| [902518] Microsoft .NET Framework Security Bypass Vulnerability
| [902516] Microsoft Windows WINS Remote Code Execution Vulnerability (2524426)
| [902502] Microsoft .NET Framework Remote Code Execution Vulnerability (2484015)
| [902501] Microsoft JScript and VBScript Scripting Engines Remote Code Execution Vulnerability (2514666)
| [902496] Microsoft Office IME (Chinese) Privilege Elevation Vulnerability (2652016)
| [902495] Microsoft Office Remote Code Execution Vulnerability (2590602)
| [902494] Microsoft Office Excel Remote Code Execution Vulnerability (2640241)
| [902493] Microsoft Publisher Remote Code Execution Vulnerabilities (2607702)
| [902492] Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2639142)
| [902487] Microsoft Windows Active Directory LDAPS Authentication Bypass Vulnerability (2630837)
| [902484] Microsoft Windows TCP/IP Remote Code Execution Vulnerability (2588516)
| [902464] Microsoft Visio Remote Code Execution Vulnerabilities (2560978)
| [902463] Microsoft Windows Client/Server Run-time Subsystem Privilege Escalation Vulnerability (2567680)
| [902455] Microsoft Visio Remote Code Execution Vulnerability (2560847)
| [902445] Microsoft XML Editor Information Disclosure Vulnerability (2543893)
| [902443] Microsoft Internet Explorer Multiple Vulnerabilities (2530548)
| [902440] Microsoft Windows SMB Server Remote Code Execution Vulnerability (2536275)
| [902430] Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2545814)
| [902425] Microsoft Windows SMB Accessible Shares
| [902423] Microsoft Office Visio Viewer Remote Code Execution Vulnerabilities (2663510)
| [902411] Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2489283)
| [902410] Microsoft Office Excel Remote Code Execution Vulnerabilities (2489279)
| [902403] Microsoft Windows Fraudulent Digital Certificates Spoofing Vulnerability
| [902395] Microsoft Bluetooth Stack Remote Code Execution Vulnerability (2566220)
| [902378] Microsoft Office Excel Remote Code Execution Vulnerabilities (2537146)
| [902377] Microsoft Windows OLE Automation Remote Code Execution Vulnerability (2476490)
| [902365] Microsoft GDI+ Remote Code Execution Vulnerability (2489979)
| [902364] Microsoft Office Remote Code Execution Vulnerabilites (2489293)
| [902351] Microsoft Groove Remote Code Execution Vulnerability (2494047)
| [902337] Microsoft Windows Kernel Elevation of Privilege Vulnerability (2393802)
| [902336] Microsoft JScript and VBScript Scripting Engines Information Disclosure Vulnerability (2475792)
| [902325] Microsoft Internet Explorer 'CSS Import Rule' Use-after-free Vulnerability
| [902324] Microsoft SharePoint Could Allow Remote Code Execution Vulnerability (2455005)
| [902319] Microsoft Foundation Classes Could Allow Remote Code Execution Vulnerability (2387149)
| [902290] Microsoft Windows Active Directory SPN Denial of Service (2478953)
| [902289] Microsoft Windows LSASS Privilege Escalation Vulnerability (2478960)
| [902288] Microsoft Kerberos Privilege Escalation Vulnerabilities (2496930)
| [902287] Microsoft Visio Remote Code Execution Vulnerabilities (2451879)
| [902285] Microsoft Internet Explorer Information Disclosure Vulnerability (2501696)
| [902281] Microsoft Windows Data Access Components Remote Code Execution Vulnerabilities (2451910)
| [902280] Microsoft Windows BranchCache Remote Code Execution Vulnerability (2385678)
| [902277] Microsoft Windows Netlogon Service Denial of Service Vulnerability (2207559)
| [902276] Microsoft Windows Task Scheduler Elevation of Privilege Vulnerability (2305420)
| [902274] Microsoft Publisher Remote Code Execution Vulnerability (2292970)
| [902269] Microsoft Windows SMB Server NTLM Multiple Vulnerabilities (971468)
| [902265] Microsoft Office Word Remote Code Execution Vulnerabilities (2293194)
| [902264] Microsoft Office Excel Remote Code Execution Vulnerabilities (2293211)
| [902263] Microsoft Windows Media Player Network Sharing Remote Code Execution Vulnerability (2281679)
| [902262] Microsoft Windows Shell and WordPad COM Validation Vulnerability (2405882)
| [902256] Microsoft Windows win32k.sys Driver 'CreateDIBPalette()' BOF Vulnerability
| [902255] Microsoft Visual Studio Insecure Library Loading Vulnerability
| [902254] Microsoft Office Products Insecure Library Loading Vulnerability
| [902250] Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability
| [902246] Microsoft Internet Explorer 'toStaticHTML()' Cross Site Scripting Vulnerability
| [902243] Microsoft Outlook TNEF Remote Code Execution Vulnerability (2315011)
| [902232] Microsoft Windows  TCP/IP Privilege Elevation Vulnerabilities (978886)
| [902231] Microsoft Windows Tracing Feature Privilege Elevation Vulnerabilities (982799)
| [902230] Microsoft .NET Common Language Runtime Remote Code Execution Vulnerability (2265906)
| [902229] Microsoft Window MPEG Layer-3 Remote Code Execution Vulnerability (2115168)
| [902228] Microsoft Office Word Remote Code Execution Vulnerabilities (2269638)
| [902227] Microsoft Windows LSASS Denial of Service Vulnerability (975467)
| [902226] Microsoft Windows Shell Remote Code Execution Vulnerability (2286198)
| [902217] Microsoft Outlook SMB Attachment Remote Code Execution Vulnerability (978212)
| [902210] Microsoft IE cross-domain IFRAME gadgets keystrokes steal Vulnerability
| [902193] Microsoft .NET Framework XML HMAC Truncation Vulnerability (981343)
| [902192] Microsoft Office COM Validation Remote Code Execution Vulnerability (983235)
| [902191] Microsoft Internet Explorer Multiple Vulnerabilities (982381)
| [902183] Microsoft Internet Explorer 'IFRAME' Denial Of Service Vulnerability
| [902178] Microsoft Visual Basic Remote Code Execution Vulnerability (978213)
| [902176] Microsoft SharePoint '_layouts/help.aspx' Cross Site Scripting Vulnerability
| [902166] Microsoft Internet Explorer 'neutering' Mechanism XSS Vulnerability
| [902159] Microsoft VBScript Scripting Engine Remote Code Execution Vulnerability (980232)
| [902158] Microsoft Office Publisher Remote Code Execution Vulnerability (981160)
| [902157] Microsoft 'ISATAP' Component Spoofing Vulnerability (978338)
| [902156] Microsoft SMB Client Remote Code Execution Vulnerabilities (980232)
| [902155] Microsoft Internet Explorer Multiple Vulnerabilities (980182)
| [902151] Microsoft Internet Explorer Denial of Service Vulnerability - Mar10
| [902133] Microsoft Office Excel Multiple Vulnerabilities (980150)
| [902117] Microsoft DirectShow Remote Code Execution Vulnerability (977935)
| [902116]  Microsoft Client/Server Run-time Subsystem Privilege Elevation Vulnerability (978037)
| [902115] Microsoft Kerberos Denial of Service Vulnerability (977290)
| [902114] Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (975416)
| [902112] Microsoft SMB Client Remote Code Execution Vulnerabilities (978251)
| [902095] Microsoft Office Excel Remote Code Execution Vulnerability (2269707)
| [902094] Microsoft Windows Kernel Mode Drivers Privilege Elevation Vulnerabilities (2160329)
| [902093] Microsoft Windows Kernel Privilege Elevation Vulnerabilities (981852)
| [902080] Microsoft Help and Support Center Remote Code Execution Vulnerability (2229593)
| [902069] Microsoft SharePoint Privilege Elevation Vulnerabilities (2028554)
| [902068] Microsoft Office Excel Remote Code Execution Vulnerabilities (2027452)
| [902067] Microsoft Windows Kernel Mode Drivers Privilege Escalation Vulnerabilities (979559)
| [902039] Microsoft Visio Remote Code Execution Vulnerabilities (980094)
| [902038] Microsoft MPEG Layer-3 Codecs Remote Code Execution Vulnerability (977816)
| [902033] Microsoft Windows '.ani' file Denial of Service vulnerability
| [902015] Microsoft Paint Remote Code Execution Vulnerability (978706)
| [901305] Microsoft Windows IP-HTTPS Component Security Feature Bypass Vulnerability (2765809)
| [901304] Microsoft Windows File Handling Component Remote Code Execution Vulnerability (2758857)
| [901301] Microsoft Windows Kerberos Denial of Service Vulnerability (2743555)
| [901212] Microsoft Windows DirectPlay Remote Code Execution Vulnerability (2770660)
| [901211] Microsoft Windows Common Controls Remote Code Execution Vulnerability (2720573)
| [901210] Microsoft Office Privilege Elevation Vulnerability - 2721015 (Mac OS X)
| [901209] Microsoft Windows Media Center Remote Code Execution Vulnerabilities (2604926)
| [901208] Microsoft Internet Explorer Multiple Vulnerabilities (2586448)
| [901205] Microsoft Windows Components Remote Code Execution Vulnerabilities (2570947)
| [901193] Microsoft Windows Media Remote Code Execution Vulnerabilities (2510030)
| [901183] Internet Information Services (IIS) FTP Service Remote Code Execution Vulnerability (2489256)
| [901180] Microsoft Internet Explorer Multiple Vulnerabilities (2482017)
| [901169] Microsoft Windows Address Book Remote Code Execution Vulnerability (2423089)
| [901166] Microsoft Office Remote Code Execution Vulnerabilites (2423930)
| [901164] Microsoft Windows SChannel Denial of Service Vulnerability (2207566)
| [901163] Microsoft Windows Media Player Remote Code Execution Vulnerability (2378111))
| [901162] Microsoft Internet Explorer Multiple Vulnerabilities (2360131)
| [901161] Microsoft ASP.NET Information Disclosure Vulnerability (2418042)
| [901151] Microsoft Internet Information Services Remote Code Execution Vulnerabilities (2267960)
| [901150] Microsoft Windows Print Spooler Service Remote Code Execution Vulnerability(2347290)
| [901140] Microsoft Windows SMB Code Execution and DoS Vulnerabilities (982214)
| [901139] Microsoft Internet Explorer Multiple Vulnerabilities (2183461)
| [901119] Microsoft Windows OpenType Compact Font Format Driver Privilege Escalation Vulnerability (980218)
| [901102] Microsoft Windows Media Services Remote Code Execution Vulnerability (980858)
| [901097] Microsoft Internet Explorer Multiple Vulnerabilities (978207)
| [901095] Microsoft Embedded OpenType Font Engine Remote Code Execution Vulnerabilities (972270)
| [901069] Microsoft Office Project Remote Code Execution Vulnerability (967183)
| [901065] Microsoft Windows IAS Remote Code Execution Vulnerability (974318)
| [901064] Microsoft Windows ADFS Remote Code Execution Vulnerability (971726)
| [901063] Microsoft Windows LSASS Denial of Service Vulnerability (975467)
| [901048] Microsoft Windows Active Directory Denial of Service Vulnerability (973309)
| [901041] Microsoft Internet Explorer Multiple Code Execution Vulnerabilities (974455)
| [901012]  Microsoft Windows Media Format Remote Code Execution Vulnerability (973812)
| [900973] Microsoft Office Word Remote Code Execution Vulnerability (976307)
| [900965] Microsoft Windows SMB2 Negotiation Protocol Remote Code Execution Vulnerability
| [900964] Microsoft .NET Common Language Runtime Code Execution Vulnerability (974378)
| [900963] Microsoft Windows Kernel Privilege Escalation Vulnerability (971486)
| [900957] Microsoft Windows Patterns & Practices EntLib DOS Vulnerability
| [900956] Microsoft Windows Patterns & Practices EntLib Version Detection
| [900929] Microsoft JScript Scripting Engine Remote Code Execution Vulnerability (971961)
| [900908] Microsoft Windows Message Queuing Privilege Escalation Vulnerability (971032)
| [900907] Microsoft Windows AVI Media File Parsing Vulnerabilities (971557)
| [900898] Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities - Nov09
| [900897] Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09
| [900891] Microsoft Internet Denial Of Service Vulnerability - Nov09
| [900887] Microsoft Office Excel Multiple Vulnerabilities (972652)
| [900886] Microsoft Windows Kernel-Mode Drivers Multiple Vulnerabilities (969947)
| [900881] Microsoft Windows Indexing Service ActiveX Vulnerability (969059)
| [900880] Microsoft Windows ATL COM Initialization Code Execution Vulnerability (973525)
| [900879] Microsoft Windows Media Player ASF Heap Overflow Vulnerability (974112)
| [900878] Microsoft Products GDI Plus Code Execution Vulnerabilities (957488)
| [900877] Microsoft Windows LSASS Denial of Service Vulnerability (975467)
| [900876] Microsoft Windows CryptoAPI X.509 Spoofing Vulnerabilities (974571)
| [900873] Microsoft Windows DNS Devolution Third-Level Domain Name Resolving Weakness (971888)
| [900863] Microsoft Internet Explorer 'window.print()' DOS Vulnerability
| [900838] Microsoft Windows TCP/IP Remote Code Execution Vulnerability (967723)
| [900837] Microsoft DHTML Editing Component ActiveX Remote Code Execution Vulnerability (956844)
| [900836] Microsoft Internet Explorer Address Bar Spoofing Vulnerability
| [900826] Microsoft Internet Explorer 'location.hash' DOS Vulnerability
| [900814] Microsoft Windows WINS Remote Code Execution Vulnerability (969883)
| [900813] Microsoft Remote Desktop Connection Remote Code Execution Vulnerability (969706)
| [900809] Microsoft Visual Studio ATL Remote Code Execution Vulnerability (969706)
| [900808] Microsoft Visual Products Version Detection
| [900757] Microsoft Windows Media Player '.AVI' File DOS Vulnerability
| [900741] Microsoft Internet Explorer Information Disclosure Vulnerability Feb10
| [900740] Microsoft Windows Kernel Could Allow Elevation of Privilege (977165)
| [900690] Microsoft Virtual PC/Server Privilege Escalation Vulnerability (969856)
| [900689] Microsoft Embedded OpenType Font Engine Remote Code Execution Vulnerabilities (961371))
| [900670] Microsoft Office Excel Remote Code Execution Vulnerabilities (969462)
| [900589] Microsoft ISA Server Privilege Escalation Vulnerability (970953)
| [900588] Microsoft DirectShow Remote Code Execution Vulnerability (961373)
| [900568] Microsoft Windows Search Script Execution Vulnerability (963093)
| [900566] Microsoft Active Directory LDAP Remote Code Execution Vulnerability (969805)
| [900476] Microsoft Excel Remote Code Execution Vulnerabilities (968557)
| [900465] Microsoft Windows DNS Memory Corruption Vulnerability - Mar09
| [900461] Microsoft MSN Live Messneger Denial of Service Vulnerability
| [900445] Microsoft Autorun Arbitrary Code Execution Vulnerability (08-038)
| [900404] Microsoft Windows RTCP Unspecified Remote DoS Vulnerability
| [900400] Microsoft Internet Explorer Unicode String DoS Vulnerability
| [900391] Microsoft Office Publisher Remote Code Execution Vulnerability (969516)
| [900366] Microsoft Internet Explorer Web Script Execution Vulnerabilites
| [900365] Microsoft Office Word Remote Code Execution Vulnerabilities (969514)
| [900337] Microsoft Internet Explorer Denial of Service Vulnerability - Apr09
| [900336] Microsoft Windows Media Player MID File Integer Overflow Vulnerability
| [900328] Microsoft Internet Explorer Remote Code Execution Vulnerability (963027)
| [900314] Microsoft XML Core Service Information Disclosure Vulnerability
| [900303] Microsoft Internet Explorer HTML Form Value DoS Vulnerability
| [900299] Microsoft Report Viewer Information Disclosure Vulnerability (2578230)
| [900297] Microsoft Windows Kernel Denial of Service Vulnerability (2556532)
| [900296] Microsoft Windows TCP/IP Stack Denial of Service Vulnerability (2563894)
| [900295] Microsoft Windows DNS Server Remote Code Execution Vulnerability (2562485)
| [900294] Microsoft Data Access Components Remote Code Execution Vulnerabilities (2560656)
| [900288] Microsoft Distributed File System Remote Code Execution Vulnerabilities (2535512)
| [900287] Microsoft SMB Client Remote Code Execution Vulnerabilities (2536276)
| [900285] Microsoft Foundation Class (MFC) Library Remote Code Execution Vulnerability (2500212)
| [900282] Microsoft DNS Resolution Remote Code Execution Vulnerability (2509553)
| [900281] Microsoft IE Developer Tools WMITools and Windows Messenger ActiveX Control Vulnerability (2508272)
| [900280] Microsoft Windows SMB Server Remote Code Execution Vulnerability (2508429)
| [900279] Microsoft SMB Client Remote Code Execution Vulnerabilities (2511455)
| [900278] Microsoft Internet Explorer Multiple Vulnerabilities (2497640)
| [900273] Microsoft Remote Desktop Client Remote Code Execution Vulnerability (2508062)
| [900267] Microsoft Media Decompression Remote Code Execution Vulnerability (2447961)
| [900266] Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (2424434)
| [900263] Microsoft Windows OpenType Compact Font Format Driver Privilege Escalation Vulnerability (2296199)
| [900262] Microsoft Internet Explorer Multiple Vulnerabilities (2416400)
| [900261] Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2293386)
| [900248] Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (981997)
| [900246] Microsoft Media Decompression Remote Code Execution Vulnerability (979902)
| [900245] Microsoft Data Analyzer and IE Developer Tools ActiveX Control Vulnerability (980195)
| [900241] Microsoft Outlook Express and Windows Mail Remote Code Execution Vulnerability (978542)
| [900240] Microsoft Exchange and Windows SMTP Service Denial of Service Vulnerability (981832)
| [900237] Microsoft Windows Authentication Verification Remote Code Execution Vulnerability (981210)
| [900236] Microsoft Windows Kernel Could Allow Elevation of Privilege (979683)
| [900235] Microsoft Windows Media Player Could Allow Remote Code Execution (979402)
| [900232] Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (975561)
| [900230] Microsoft Windows SMB Server Multiple Vulnerabilities (971468)
| [900229] Microsoft Data Analyzer ActiveX Control Vulnerability (978262)
| [900228] Microsoft Office (MSO) Remote Code Execution Vulnerability (978214)
| [900227] Microsoft Windows Shell Handler Could Allow Remote Code Execution Vulnerability (975713)
| [900223] Microsoft Ancillary Function Driver Elevation of Privilege Vulnerability (956803)
| [900192] Microsoft Internet Explorer Information Disclosure Vulnerability
| [900187] Microsoft Internet Explorer Argument Injection Vulnerability
| [900178] Microsoft Windows 'UnhookWindowsHookEx' Local DoS Vulnerability
| [900173] Microsoft Windows Media Player Version Detection
| [900172] Microsoft Windows Media Player 'MIDI' or 'DAT' File DoS Vulnerability
| [900170] Microsoft iExplorer '&NBSP
| [900131] Microsoft Internet Explorer Denial of Service Vulnerability
| [900125] Microsoft SQL Server 2000 sqlvdir.dll ActiveX Buffer Overflow Vulnerability
| [900120] Microsoft Organization Chart Remote Code Execution Vulnerability
| [900108] Microsoft Windows NSlookup.exe Remote Code Execution Vulnerability
| [900097] Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution
| [900095] Microsoft ISA Server and Forefront Threat Management Gateway DoS Vulnerability (961759)
| [900093] Microsoft DirectShow Remote Code Execution Vulnerability (961373)
| [900080] Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)
| [900079] Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)
| [900064] Vulnerability in Microsoft Office SharePoint Server Could Cause Elevation of Privilege (957175)
| [900063] Vulnerabilities in Microsoft Office Word Could Allow Remote Code Execution (957173)
| [900061] Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (959070)
| [900058] Microsoft XML Core Services Remote Code Execution Vulnerability (955218)
| [900048] Microsoft Excel Remote Code Execution Vulnerability (956416)
| [900047] Microsoft Office nformation Disclosure Vulnerability (957699)
| [900046] Microsoft Office Remote Code Execution Vulnerabilities (955047)
| [900033] Microsoft PowerPoint Could Allow Remote Code Execution Vulnerabilities (949785)
| [900029] Microsoft Office Filters Could Allow Remote Code Execution Vulnerabilities (924090)
| [900028] Microsoft Excel Could Allow Remote Code Execution Vulnerabilities (954066)
| [900025] Microsoft Office Version Detection
| [900006] Microsoft Word Could Allow Remote Code Execution Vulnerability
| [900004] Microsoft Access Snapshot Viewer ActiveX Control Vulnerability
| [855384] Solaris Update for snmp/mibiisa 108870-36
| [855273] Solaris Update for snmp/mibiisa 108869-36
| [803028] Microsoft Internet Explorer Remote Code Execution Vulnerability (2757760)
| [803007] Microsoft Windows Minimum Certificate Key Length Spoofing Vulnerability (2661254)
| [802912] Microsoft Unauthorized Digital Certificates Spoofing Vulnerability (2728973)
| [802888] Microsoft Windows Media Service Handshake Sequence DoS Vulnerability
| [802886] Microsoft Sidebar and Gadgets Remote Code Execution Vulnerability (2719662)
| [802864] Microsoft XML Core Services Remote Code Execution Vulnerability (2719615)
| [802774] Microsoft VPN ActiveX Control Remote Code Execution Vulnerability (2695962)
| [802726] Microsoft SMB Signing Disabled
| [802708] Microsoft Internet Explorer Code Execution and DoS Vulnerabilities
| [802634] Microsoft Windows Unauthorized Digital Certificates Spoofing Vulnerability (2718704)
| [802500] Microsoft Windows TrueType Font Parsing Privilege Elevation Vulnerability
| [802468] Compatibility Issues Affecting Signed Microsoft Binaries (2749655)
| [802462] Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability
| [802426] Microsoft Windows ActiveX Control Multiple Vulnerabilities (2647518)
| [802383] Microsoft Windows Color Control Panel Privilege Escalation Vulnerability
| [802379] Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability
| [802287] Microsoft Internet Explorer Cache Objects History Information Disclosure Vulnerability
| [802286] Microsoft Internet Explorer Multiple Information Disclosure Vulnerabilities
| [802260] Microsoft Windows WINS Remote Code Execution Vulnerability (2524426)
| [802203] Microsoft Internet Explorer Cookie Hijacking Vulnerability
| [802202] Microsoft Internet Explorer Cookie Hijacking Vulnerability
| [802140] Microsoft Explorer HTTPS Sessions Multiple Vulnerabilities (Windows)
| [802136] Microsoft Windows Insecure Library Loading Vulnerability (2269637)
| [801991] Microsoft Windows SMB/NETBIOS NULL Session Authentication Bypass Vulnerability
| [801966] Microsoft Windows ActiveX Control Multiple Vulnerabilities (2562937)
| [801935] Microsoft Silverlight Multiple Memory Leak Vulnerabilities
| [801934] Microsoft Silverlight Version Detection
| [801914] Microsoft Windows IPv4 Default Configuration Security Bypass Vulnerability
| [801876] Microsoft Internet Explorer 'msxml.dll' Information Disclosure Vulnerability
| [801831] Microsoft Internet Explorer Incorrect GUI Display Vulnerability
| [801830] Microsoft Internet Explorer 'ReleaseInterface()' Remote Code Execution Vulnerability
| [801725] Microsoft Products GDI Plus Remote Code Execution Vulnerabilities (954593)
| [801721] Microsoft Active Directory Denial of Service Vulnerability (953235)
| [801719] Microsoft Windows CSRSS CSRFinalizeContext Local Privilege Escalation Vulnerability (930178)
| [801718] Microsoft Windows Vista Information Disclosure Vulnerability (931213)
| [801717] Microsoft Windows Vista Teredo Interface Firewall Bypass Vulnerability
| [801716] Microsoft Outlook Express/Windows Mail MHTML URI Handler Information Disclosure Vulnerability (929123)
| [801715] Microsoft XML Core Services Remote Code Execution Vulnerability (936227)
| [801713] Microsoft Outlook Express And Windows Mail NNTP Protocol Heap Buffer Overflow Vulnerability (941202)
| [801707] Microsoft Internet Explorer mshtml.dll Remote Memory Corruption Vulnerability (942615)
| [801706] Microsoft Windows TCP/IP Remote Code Execution Vulnerabilities (941644)
| [801705] Microsoft Windows TCP/IP Denial of Service Vulnerability (946456)
| [801704] Microsoft Internet Information Services Privilege Elevation Vulnerability (942831)
| [801702] Microsoft Internet Explorer HTML Rendering Remote Memory Corruption Vulnerability (944533)
| [801701] Microsoft Windows DNS Client Service Response Spoofing Vulnerability (945553)
| [801677] Microsoft WMI Administrative Tools ActiveX Control Remote Code Execution Vulnerabilities
| [801606] Microsoft Internet Explorer 'mshtml.dll' Information Disclosure Vulnerability
| [801598] Microsoft Windows2k3 Active Directory 'BROWSER ELECTION' Buffer Overflow Vulnerability
| [801597] Microsoft Office Excel 2003 Invalid Object Type Remote Code Execution Vulnerability
| [801596] Microsoft Excel 2007 Office Drawing Layer Remote Code Execution Vulnerability
| [801595] Microsoft Office Excel Axis and Art Object Parsing Remote Code Execution Vulnerabilities
| [801594] Microsoft PowerPoint 2007 OfficeArt Atom Remote Code Execution Vulnerability
| [801580] Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities
| [801527] Microsoft Windows 32-bit Platforms Unspecified vulnerabilities
| [801491] Microsoft 'hxvz.dll' ActiveX Control Memory Corruption Vulnerability (948881)
| [801489] Microsoft Office Graphics Filters Remote Code Execution Vulnerabilities (968095)
| [801488] Microsoft Internet Explorer Data Stream Handling Remote Code Execution Vulnerability (947864)
| [801487] Microsoft Windows Kernel Usermode Callback Local Privilege Elevation Vulnerability (941693)
| [801486] Microsoft Windows Speech Components Voice Recognition Command Execution Vulnerability (950760)
| [801485] Microsoft Pragmatic General Multicast (PGM)  Denial of Service Vulnerability (950762)
| [801484] Microsoft Windows IPsec Policy Processing Information Disclosure Vulnerability (953733)
| [801483] Microsoft Windows Search Remote Code Execution Vulnerability (959349)
| [801482] Microsoft Windows ASP.NET Denial of Service Vulnerability(970957)
| [801481] Microsoft  Wireless LAN AutoConfig Service Remote Code Execution Vulnerability (970710)
| [801480] Microsoft Web Services on Devices API Remote Code Execution Vulnerability (973565)
| [801479] Microsoft Windows TCP/IP Could Allow Remote Code Execution (974145)
| [801457] Microsoft Windows Address Book Insecure Library Loading Vulnerability
| [801456] Microsoft Windows Progman Group Converter Insecure Library Loading Vulnerability
| [801349] Microsoft Internet Explorer 'IFRAME' Denial Of Service Vulnerability (June-10)
| [801348] Microsoft Internet Explorer 'IFRAME' Denial Of Service Vulnerability -june 10
| [801345] Microsoft .NET 'ASP.NET' Cross-Site Scripting vulnerability
| [801344] Microsoft .NET '__VIEWSTATE'  Cross-Site Scripting vulnerability
| [801342] Microsoft ASP.NET Cross-Site Scripting vulnerability
| [801333] Microsoft Windows Kernel 'win32k.sys' Multiple DOS Vulnerabilities
| [801330] Microsoft Internet Explorer Cross Site Data Leakage Vulnerability
| [801109] Microsoft IE CA SSL Certificate Security Bypass Vulnerability - Oct09
| [801090] Microsoft Windows Indeo Codec Multiple Vulnerabilities
| [800968] Microsoft SharePoint Team Services Information Disclosure Vulnerability
| [800910] Microsoft Internet Explorer Buffer Overflow  Vulnerability - Jul09
| [800902] Microsoft Internet Explorer XSS Vulnerability - July09
| [800872] Microsoft Internet Explorer 'li' Element DoS Vulnerability - Sep09
| [800863] Microsoft Internet Explorer XML Document DoS Vulnerability - Aug09
| [800862] Microsoft Windows Kernel win32k.sys Privilege Escalation Vulnerability
| [800861] Microsoft Internet Explorer 'findText()' Unicode Parsing DoS Vulnerability
| [800845] Microsoft Office Web Components ActiveX Control Code Execution Vulnerability
| [800829] Microsoft Video ActiveX Control 'msvidctl.dll' BOF Vulnerability
| [800742] Microsoft Internet Explorer Unspecified vulnerability
| [800700] Microsoft GDIPlus PNG Infinite Loop Vulnerability
| [800687] Microsoft Windows Server 2003 OpenType Font Engine DoS Vulnerability
| [800669] Microsoft Internet Explorer Denial Of Service Vulnerability - July09
| [800577] Microsoft Windows Server 2003 win32k.sys DoS Vulnerability
| [800505] Microsoft HTML Help Workshop buffer overflow vulnerability
| [800504] Microsoft Windows XP SP3 denial of service vulnerability
| [800481] Microsoft SharePoint Cross Site Scripting Vulnerability
| [800480] Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability
| [800466] Microsoft Windows TLS/SSL Spoofing Vulnerability (977377)
| [800461] Microsoft Internet Explorer Information Disclosure Vulnerability (980088)
| [800442] Microsoft Windows GP Trap Handler Privilege Escalation Vulnerability
| [800429] Microsoft Internet Explorer Remote Code Execution Vulnerability (979352)
| [800382] Microsoft PowerPoint File Parsing Remote Code Execution Vulnerability (967340)
| [800347] Microsoft Internet Explorer Clickjacking Vulnerability
| [800343] Microsoft Word 2007 Sensitive Information Disclosure Vulnerability
| [800337] Microsoft Internet Explorer NULL Pointer DoS Vulnerability
| [800332] Microsoft Windows Live Messenger Information Disclosure Vulnerability
| [800331] Microsoft Windows Live Messenger Client Version Detection
| [800328] Integer Overflow vulnerability in Microsoft Windows Media Player
| [800310] Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability
| [800267] Microsoft GDIPlus Library File Integer Overflow Vulnerability
| [800218] Microsoft Money 'prtstb06.dll' Denial of Service vulnerability
| [800217] Microsoft Money Version Detection
| [800209] Microsoft Internet Explorer Version Detection (Win)
| [800208] Microsoft Internet Explorer Anti-XSS Filter Vulnerabilities
| [800083] Microsoft Outlook Express Malformed MIME Message DoS Vulnerability
| [800082] Microsoft SQL Server sp_replwritetovarbin() BOF Vulnerability
| [800023] Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)
| [103254] Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability
| [102059] Microsoft Windows Vector Markup Language Buffer Overflow (938127)
| [102055] Microsoft Windows GDI Multiple Vulnerabilities (925902)
| [102053] Microsoft Windows Vector Markup Language Vulnerabilities (929969)
| [102015] Microsoft RPC Interface Buffer Overrun (KB824146)
| [101100] Vulnerabilities in Microsoft ATL Could Allow Remote Code Execution (973908)
| [101017] Microsoft MS03-018 security check
| [101016] Microsoft MS03-022 security check
| [101015] Microsoft MS03-034 security check
| [101014] Microsoft MS00-078 security check
| [101012] Microsoft MS03-051 security check
| [101010] Microsoft Security Bulletin MS05-004
| [101009] Microsoft Security Bulletin MS06-033
| [101007] Microsoft dotNET version grabber
| [101006] Microsoft Security Bulletin MS06-056
| [101005] Microsoft Security Bulletin MS07-040
| [101004] Microsoft MS04-017 security check
| [101003] Microsoft MS00-058 security check
| [101000] Microsoft MS00-060 security check
| [100950] Microsoft DNS server internal hostname disclosure detection
| [100624] Microsoft Windows SMTP Server DNS spoofing vulnerability
| [100607] Microsoft SMTP Service and Exchange Routing Engine Buffer Overflow Vulnerability
| [100596] Microsoft Windows SMTP Server MX Record Denial of Service Vulnerability
| [100283] Microsoft Windows SMB2 '_Smb2ValidateProviderCallback()' Remote Code Execution Vulnerability
| [100062] Microsoft Remote Desktop Protocol Detection
| [90024] Windows Vulnerability in Microsoft Jet Database Engine
| [80007] Microsoft MS00-06 security check 
| [13752] Denial of Service (DoS) in Microsoft SMS Client
| [11992] Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)
| [11874] IIS Service Pack - 404
| [11808] Microsoft RPC Interface Buffer Overrun (823980)
| [11433] Microsoft ISA Server DNS - Denial Of Service (MS03-009)
| [11217] Microsoft's SQL Version Query
| [11177] Flaw in Microsoft VM Could Allow Code Execution (810030)
| [11146] Microsoft RDP flaws could allow sniffing and DOS(Q324380)
| [11142] IIS XSS via IDC error
| [11067] Microsoft's SQL Hello Overflow
| [11003] IIS Possible Compromise
| [10993] IIS ASP.NET Application Trace Enabled
| [10991] IIS Global.asa Retrieval
| [10936] IIS XSS via 404 error
| [10862] Microsoft's SQL Server Brute Force
| [10755] Microsoft Exchange Public Folders Information Leak
| [10732] IIS 5.0 WebDav Memory Leakage
| [10699] IIS FrontPage DoS II
| [10695] IIS .IDA ISAPI filter applied
| [10674] Microsoft's SQL UDP Info Query
| [10673] Microsoft's SQL Blank Password
| [10671] IIS Remote Command Execution
| [10667] IIS 5.0 PROPFIND Vulnerability
| [10661] IIS 5 .printer ISAPI filter applied
| [10657] NT IIS 5.0 Malformed HTTP Printer Request Header Buffer Overflow Vulnerability
| [10585] IIS FrontPage DoS
| [10576] Check for dangerous IIS default files
| [10575] Check for IIS .cnf file leakage
| [10573] IIS 5.0 Sample App reveals physical path of web root
| [10572] IIS 5.0 Sample App vulnerable to cross-site scripting attack
| [10537] IIS directory traversal
| [10492] IIS IDA/IDQ Path Disclosure
| [10491] ASP/ASA source using Microsoft Translate f: bug
| [10144] Microsoft SQL TCP/IP listener is running
| 
| SecurityTracker - https://www.securitytracker.com:
| [1027751] Microsoft Internet Information Server (IIS) FTP Server Lets Remote Users Obtain Files and Local Users Obtain Passwords
| [1027223] Microsoft IIS Web Server Discloses Potentially Sensitive Information to Remote Users
| [1024921] Microsoft IIS FTP Server Lets Remote Users Deny Service
| [1024496] Microsoft Internet Information Server (IIS) Web Server Stack Overflow in Reading POST Data Lets Remote Users Deny Service
| [1023387] Microsoft Internet Information Services (IIS) Filename Extension Parsing Configuration Error May Let Users Bypass Security Controls
| [1022792] Microsoft Internet Information Server (IIS) FTP Server Buffer Overflows Let Remote Authenticated Users Execute Arbitrary Code and Deny Service
| [1016466] Microsoft Internet Information Server (IIS) Buffer Overflow in Processing ASP Pages Lets Remote Authenticated Users Execute Arbitrary Code
| [1015376] Microsoft IIS Lets Remote Users Deny Service or Execute Arbitrary Code With Malformed HTTP GET Requests
| [1015049] Microsoft Internet Explorer Drag-and-Drop Timing May Let Remote Users Install Arbitrary Files
| [1014777] Microsoft IIS ASP Error Page May Disclose System Information in Certain Cases
| [1011633] Microsoft IIS WebDAV XML Message Handler Error Lets Remote Users Deny Service
| [1010692] Microsoft IIS 4.0 Buffer Overflow in Redirect Function Lets Remote Users Execute Arbitrary Code
| [1010610] Microsoft IIS Web Server May Disclose Private IP Addresses in Certain Cases
| [1010079] Microsoft IIS ASP Script Cookie Processing Flaw May Disclose Application Information to Remote Users
| [1008563] Microsoft IIS Fails to Log HTTP TRACK Requests
| [1007262] Microsoft IIS 6.0 Vulnerabilities Permit Cross-Site Scripting and Password Changing Attacks Against Administrators
| [1007059] Microsoft Windows Media Services (nsiislog.dll) Extension to Internet Information Server (IIS) Has Another Buffer Overflow That Lets Remote Execute Arbitrary Code
| [1006867] Microsoft IIS Buffer Overflow Lets Remote Users With Upload Privileges Execute Code - Remote Users Can Also Crash the Service
| [1006866] Microsoft Windows Media Services (nsiislog.dll) Extension to Internet Information Server (IIS) Lets Remote Execute Arbitrary Code
| [1006704] Microsoft IIS Authentication Manager Discloses Validity of User Names to Remote Users
| [1006305] Microsoft IIS Web Server WebDAV Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1005505] Microsoft Internet Information Server (IIS) Script Access Control Bug May Let Remote Authenticated Users Upload Unauthorized Executable Files
| [1005504] Microsoft Internet Information Server (IIS) WebDAV Memory Allocation Flaw Lets Remote Users Crash the Server
| [1005503] Microsoft Internet Information Server (IIS) Administrative Pages Allow Cross-Site Scripting Attacks
| [1005502] Microsoft Internet Information Server (IIS) Out-of-Process Access Control Bug Lets Certain Authenticated Users Gain Full Control of the Server
| [1005083] Microsoft Internet Information Server (IIS) Web Server Fails to Properly Validate Client-side Certificates, Allowing Remote Users to Impersonate Other Users or Certificate Issuers
| [1004757] Microsoft IIS SMTP Service Encapsulation Bug Lets Remote Users Relay Mail and Send SPAM Via the Service
| [1004646] ColdFusion MX Buffer Overflow When Used With Microsoft Internet Information Server (IIS) Lets Remote Users Crash the IIS Web Server or Execute Arbitrary Code
| [1004526] Microsoft Internet Information Server (IIS) Heap Overflow in HTR ISAPI Extension While Processing Chunked Encoded Data Lets Remote Users Execute Arbitrary Code
| [1004044] Cisco CallManager Affected by Microsoft Internet Information Server (IIS) Bugs
| [1004032] Microsoft Internet Information Server (IIS) FTP STAT Command Bug Lets Remote Users Crash Both the FTP and the Web Services
| [1004031] Microsoft Internet Information Server (IIS) URL Length Bug Lets Remote Users Crash the Web Service
| [1004011] Microsoft Internet Information Server (IIS) Buffer Overflow in ASP Server-Side Include Function May Let Remote Users Execute Arbitrary Code on the Web Server
| [1004006] Microsoft Internet Information Server (IIS) Off-By-One Heap Overflow in .HTR Processing May Let Remote Users Execute Arbitrary Code on the Server
| [1003224] Microsoft Internet Information Server (IIS) Version 4 Lets Local Users Modify the Log File Undetected
| [1002778] Microsoft Internet Information Server (IIS) Lets Remote Users Create Bogus Web Log Entries
| [1002733] Microsoft IIS 4.0 Configuration Error May Allow Remote Users to Obtain Physical Directory Path Information
| [1002651] Microsoft Internet Information Server (IIS) May Disclose PHP Scripting Source Code
| [1002212] Microsoft IIS Web Server Contains Multiple Vulnerabilities That Allow Local Users to Gain System Privileges and Allow Remote Users to Cause the Web Server to Crash
| [1002161] Microsoft Internet Information Server (IIS) Web Server Discloses Internal IP Addresses or NetBIOS Host Names to Remote Users
| [1001818] Microsoft Internet Information Server (IIS) Web Server Discloses ASP Source Code When Installed on FAT-based Filesystem
| [1001576] eEye Digital Security's SecureIIS Application Firewall for Microsoft Web Servers Fails to Filter Certain Web URL Characters, Allowing Remote Users to Bypass the SecureIIS Firewall
| [1001565] Microsoft IIS Web Server on Windows 2000 Allows Remote Users to Cause the Server to Consume All Available Memory Due to Memory Leak in WebDAV Lock Method
| [1001530] Microsoft IIS Web Server Allows Remote Users to Execute Commands on the Server Due to CGI Decoding Error
| [1001483] Microsoft IIS Web Server Lets Remote Users Restart the Web Server with Another Specially Crafted PROPFIND XML Command
| [1001464] Microsoft Internet Information Server IIS 5.0 for Windows 2000 Lets Remote Users Execute Arbitrary Code on the Server and Gain Control of the Server
| [1001402] Microsoft IIS Web Server Can Be Effectively Shutdown By Certain Internal-Network Attacks When The Underlying OS Supports User Account Lockouts
| [1001116] Microsoft Personal Web Server Contains An Old Internet Information Server (IIS) Vulnerability Allowing Unauthorized Directory Listings and Possible Code Execution For Remote Users
| [1001050] Microsoft IIS 5.0 Web Server Can Be Restarted Remotely By Any User
| [1028908] Microsoft Active Directory Federation Services Discloses Account Information to Remote Users
| [1028905] (Microsoft Issues Fix for Exchange Server) Oracle Fusion Middleware Bugs Let Remote Users Deny Service and Access and Modify Data
| [1028904] (Microsoft Issues Fix for Exchange Server) Oracle PeopleSoft Products Bugs Let Remote Users Partially Access and Modify Data and Partially Deny Service
| [1028903] Microsoft Windows Unicode Scripts Processor Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1028902] Microsoft Internet Explorer Multiple Bugs Let Remote Users Execute Arbitrary Code and Conduct Cross-Site Scripting Attacks
| [1028759] (Microsoft Issues Fix for Internet Explorer) Adobe Flash Player Buffer Overflows Let Remote Users Execute Arbitrary Code
| [1028756] Microsoft .NET Bug Lets Remote Users Execute Arbitrary Code and Bypass Security Restrictions
| [1028755] Microsoft Silverlight Null Pointer Dereference Lets Remote Users Execute Arbitrary Code
| [1028754] Microsoft Windows Defender Pathname Bug Lets Local Users Gain Elevated Privileges
| [1028752] Microsoft DirectShow GIF Image Processing Flaw Lets Remote Users Execute Arbitrary Code
| [1028751] Microsoft Office TrueType Font Parsing Flaw Lets Remote Users Execute Arbitrary Code
| [1028750] Microsoft Visual Studio .NET TrueType Font Parsing Flaw Lets Remote Users Execute Arbitrary Code
| [1028749] Microsoft Lync TrueType Font Parsing Flaw Lets Remote Users Execute Arbitrary Code
| [1028748] Microsoft Windows GDI+ TrueType Font Parsing Flaw Lets Remote Users Execute Arbitrary Code
| [1028745] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Conduct Cross-Site Scripting Attacks
| [1028651] Microsoft Internet Explorer Multiple Memory Corruption Bugs Let Remote Users Execute Arbitrary Code
| [1028650] Microsoft Office Buffer Overflow in PNG Image Processing Lets Remote Users Execute Arbitrary Code
| [1028560] Microsoft Visio Discloses Information to Remote Users
| [1028558] Microsoft .NET Flaws Let Remote Users Bypass Authentication and Bypass XML File Signature Verification
| [1028557] Microsoft Malware Protection Engine Flaw Lets Remote Users Execute Arbitrary Code
| [1028553] Microsoft Word RTF Shape Data Parsing Error Lets Remote Users Execute Arbitrary Code
| [1028552] Microsoft Publisher Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1028551] Microsoft Lync Object Access Flaw Lets Remote Users Execute Arbitrary Code
| [1028550] Microsoft Office Communicator Object Access Flaw Lets Remote Users Execute Arbitrary Code
| [1028545] Microsoft Internet Explorer Multiple Use-After-Free Bugs Let Remote Users Execute Arbitrary Code
| [1028514] Microsoft Internet Explorer Object Access Bug Lets Remote Users Execute Arbitrary Code
| [1028412] Microsoft SharePoint Server Discloses Files to Remote Authenticated Users
| [1028411] Microsoft Office Web Apps Input Validation Flaw in Sanitization Component Permits Cross-Site Scripting Attacks
| [1028410] Microsoft InfoPath Input Validation Flaw in Sanitization Component Permits Cross-Site Scripting Attacks
| [1028409] Microsoft Groove Server Input Validation Flaw in Sanitization Component Permits Cross-Site Scripting Attacks
| [1028408] Microsoft SharePoint Input Validation Flaw in HTML Sanitization Component Permits Cross-Site Scripting Attacks
| [1028405] Microsoft Active Directory LDAP Processing Flaw Lets Remote Users Deny Service
| [1028404] Microsoft Antimalware Client Path Name Flaw Lets Local Users Gain Elevated Privileges
| [1028398] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1028281] Microsoft Office for Mac HTML Loading Bug Lets Remote Users Obtain Potentially Sensitive Information
| [1028279] Microsoft OneNote Buffer Validation Flaw Lets Remote Users Obtain Potentially Sensitive Information
| [1028278] Microsoft SharePoint Input Validation Flaws Permit Cross-Site Scripting and Denial of Service Attacks
| [1028276] Microsoft Visio Viewer Tree Object Type Confusion Error Lets Remote Users Execute Arbitrary Code
| [1028275] Microsoft Internet Explorer Use-After-Free Bugs Let Remote Users Execute Arbitrary Code
| [1028273] Microsoft Silverlight Memory Pointer Dereference Lets Remote Users Execute Arbitrary Code
| [1028123] Microsoft .NET Bug Lets Remote Users Execute Arbitrary Code and Bypass Security Restrictions
| [1028119] Microsoft DirectShow Media Decompression Flaw Lets Remote Users Execute Arbitrary Code
| [1028117] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Access Information Across Domains
| [1028116] Microsoft Internet Explorer Vector Markup Language Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1027949] Microsoft .NET Open Data (OData) Protocol Bug Lets Remote Users Deny Service
| [1027948] Microsoft System Center Configuration Manager Input Validation Flaws Permit Cross-Site Scripting Attacks
| [1027945] Microsoft .NET Flaws Let Remote Users Execute Arbitrary Code, Obtain Potentially Sensitive Information, and Bypass Security Restrictions
| [1027943] Microsoft XML Core Services (MSXML) XML Parsing Flaws Let Remote Users Execute Arbitrary Code
| [1027934] Microsoft Windows Includes Some Invalid TURKTRUST Certificates
| [1027930] Microsoft Internet Explorer CDwnBindInfo Object Reuse Flaw Lets Remote Users Execute Arbitrary Code
| [1027870] Microsoft Internet Explorer Discloses Mouse Location to Remote Users
| [1027859] Microsoft DirectPlay Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1027857] Microsoft Exchange Server RSS Feed Bug Lets Remote Users Deny Service
| [1027852] Microsoft Word RTF Parsing Error Lets Remote Users Execute Arbitrary Code
| [1027851] Microsoft Internet Explorer Multiple Use-After-Free Bugs Let Remote Users Execute Arbitrary Code
| [1027753] Microsoft .NET Flaws Let Remote Users Execute Arbitrary Code, Obtain Potentially Sensitive Information, and Bypass Security Restrictions
| [1027752] Microsoft Excel Buffer Overflow, Memory Corruption, and Use-After-Free Errors Let Remote Users Execute Arbitrary Code
| [1027749] Microsoft Internet Explorer Multiple Use-After-Free Bugs Let Remote Users Execute Arbitrary Code
| [1027647] EMC NetWorker Module for Microsoft Applications Lets Remote Users Execute Arbitrary Code and Local Users Obtain Passwords
| [1027629] Microsoft Office InfoPath HTML Sanitizer Flaw Permits Cross-Site Scripting Attacks
| [1027628] Microsoft Office Communicator HTML Sanitizer Flaw Permits Cross-Site Scripting Attacks
| [1027627] Microsoft Lync HTML Sanitizer Flaw Permits Cross-Site Scripting Attacks
| [1027626] Microsoft SharePoint HTML Sanitizer Flaw Permits Cross-Site Scripting Attacks
| [1027625] Microsoft Groove Server HTML Sanitizer Flaw Permits Cross-Site Scripting Attacks
| [1027623] Microsoft SQL Server Input Validation Flaw in Reporting Services Permits Cross-Site Scripting Attacks
| [1027621] Microsoft Works Heap Corruption Flaw Lets Remote Users Execute Arbitrary Code
| [1027620] Microsoft Kerberos Null Pointer Dereference Lets Remote Users Deny Service
| [1027618] Microsoft Word Memory Errors Let Remote Users Execute Arbitrary Code
| [1027555] Microsoft Internet Explorer Multiple Use-After-Free Bugs Let Remote Users Execute Arbitrary Code
| [1027538] Microsoft Internet Explorer execCommand Flaw Lets Remote Users Execute Arbitrary Code
| [1027512] Microsoft System Center Configuration Manager Input Validation Flaw Permits Cross-Site Scripting Attacks
| [1027511] Microsoft Visual Studio Team Foundation Server Input Validation Flaw Permits Cross-Site Scripting Attacks
| [1027394] Microsoft Visio Buffer Overflow in Processing DXF Format Files Lets Remote Users Execute Arbitrary Code
| [1027393] Microsoft Office CGM Graphics File Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1027392] Microsoft JScript and VBScript Engine Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1027390] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1027389] Microsoft Visual Basic Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027385] Microsoft Visual FoxPro Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027384] Microsoft Host Integration Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027383] Microsoft Commerce Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027381] Microsoft SQL Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027380] Microsoft Office Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1027295] Microsoft SharePoint Server Bugs in Oracle Outside In Libraries Let Remote Users Execute Arbitrary Code
| [1027294] Microsoft Exchange Server Bugs in Oracle Outside In Libraries Let Remote Users Execute Arbitrary Code
| [1027234] Microsoft Office for Mac Folder Permission Flaw Lets Local Users Gain Elevated Privileges
| [1027232] Microsoft SharePoint Input Validation Flaws Permit Cross-Site Scripting, Information Disclosure, and URL Redirection Attacks
| [1027229] Microsoft Office DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1027228] Microsoft Visual Basic for Applications DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1027227] Microsoft Data Access Components (MDAC) ADO Cachesize Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1027226] Microsoft Internet Explorer Deleted Object Access Bugs Let Remote Users Execute Arbitrary Code
| [1027157] Microsoft XML Core Services (MSXML) Object Access Error Lets Remote Users Execute Arbitrary Code
| [1027151] Microsoft Dynamics AX Input Validation Flaw Permits Cross-Site Scripting Attacks
| [1027150] Microsoft Lync DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1027149] Microsoft .NET Memory Access Bug Lets Remote Users Execute Arbitrary Code
| [1027147] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code, Conduct Cross-Site Scripting Attacks, and Obtain Potentially Sensitive Information
| [1027114] Microsoft Windows Includes Some Invalid Certificates
| [1027048] Microsoft .NET Bugs Let Remote Users Execute Arbitrary Code and Deny Service
| [1027043] Microsoft Windows Partition Manager Memory Allocation Error Lets Local Users Gain Elevated Privileges
| [1027042] Microsoft Visio Viewer Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1027041] Microsoft Office Excel File Memory Corruption Errors and Heap Overflows Let Remote Users Execute Arbitrary Code
| [1027040] Microsoft Silverlight Double Free Memory Error Lets Remote Users Execute Arbitrary Code
| [1027038] Microsoft GDI+ Bugs Let Remote Users Execute Arbitrary Code
| [1027036] Microsoft .NET Framework Serialization Bugs Let Remote Users Execute Arbitrary Code
| [1027035] Microsoft Word RTF Processing Flaw Lets Remote Users Execute Arbitrary Code
| [1026911] Microsoft Office WPS File Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1026910] Microsoft Works WPS File Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1026909] Microsoft Forefront Unified Access Gateway Bugs Let Remote Users Obtain Potentially Sensitive Information and Conduct Browser Redirection Attacks
| [1026907] Microsoft .NET Parameter Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1026905] Microsoft BizTalk Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026904] Microsoft Visual Basic Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026903] Microsoft Visual FoxPro Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026902] Microsoft Commerce Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026901] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1026900] Microsoft Office Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026899] Microsoft SQL Server Windows Common Controls (MSCOMCTL.OCX) Bug Lets Remote Users Execute Arbitrary Code
| [1026794] Microsoft DirectWrite Unicode Character Processing Flaw Lets Remote Users Deny Service
| [1026792] Microsoft Visual Studio Lets Local Users Gain Elevated Privileges
| [1026791] Microsoft Expression Design DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1026789] Microsoft DNS Server Lets Remote Users Deny Service
| [1026686] Microsoft SharePoint Input Validation Flaws Permit Cross-Site Scripting Attacks
| [1026685] Microsoft Windows Ancillary Function Driver Lets Local Users Gain Elevated Privileges
| [1026684] Microsoft Visio Viewer Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1026681] Microsoft Silverlight Bugs Let Remote Users Execute Arbitrary Code
| [1026680] Microsoft .NET Bugs Let Remote Users Execute Arbitrary Code
| [1026677] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Obtain Potentially Sensitive Information
| [1026499] Microsoft Anti-Cross Site Scripting Library Flaw May Permit Cross-Site Scripting Attacks
| [1026497] Microsoft Windows ClickOnce Feature Lets Remote Users Execute Arbitrary Code
| [1026479] Microsoft .NET Bugs Let Remote Users Execute Arbitrary Commands, Access User Accounts, and Redirect Users
| [1026469] Microsoft ASP.NET Hash Table Collision Bug Lets Remote Users Deny Service
| [1026416] Microsoft Office IME (Chinese) Lets Local Users Gain Elevated Privileges
| [1026414] Microsoft Publisher Multiple Errors Let Remote Users Execute Arbitrary Code
| [1026413] Microsoft Internet Explorer DLL Loading Error Lets Remote Users Execute Arbitrary Code and HTML Processing Bugs Let Remote Users Obtain Information
| [1026412] Microsoft Active Directory Memory Access Error Lets Remote Authenticated Users Execute Arbitrary Code
| [1026411] Microsoft PowerPoint DLL Loading and OfficeArt Object Processing Flaws Let Remote Users Execute Arbitrary Code
| [1026410] Microsoft Office Excel File Memory Error Lets Remote Users Execute Arbitrary Code
| [1026409] Microsoft Office Use-After-Free Bug Lets Remote Users Execute Arbitrary Code
| [1026408] Microsoft Internet Explorer Error in Microsoft Time Component Lets Remote Users Execute Arbitrary Code
| [1026294] Microsoft Active Directory CRL Validation Flaw Lets Remote Users Bypass Authentication
| [1026271] Microsoft Windows TrueType Font Parsing Flaw Lets Remote Users Execute Arbitrary Code
| [1026220] Microsoft Publisher 'Pubconv.dll' Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1026169] Microsoft Forefront Unified Access Gateway Input Validation Flaws Permits Cross-Site Scripting, HTTP Response Splitting, and Denial of Service Attacks
| [1026168] Microsoft Host Integration Server Bugs Let Remote Users Deny Service
| [1026167] Microsoft Windows Ancillary Function Driver Lets Local Users Gain Elevated Privileges
| [1026164] Microsoft Active Accessibility Component DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1026162] Microsoft .NET Inheritance Restriction Error Lets Remote Users Execute Arbitrary Code
| [1026161] Microsoft Silverlight Inheritance Restriction Error Lets Remote Users Execute Arbitrary Code
| [1026160] Microsoft Internet Explorer Multiple Flaws Let Remote Users Execute Arbitrary Code
| [1026103] Microsoft Windows SSL/TLS Protocol Flaw Lets Remote Users Decryption Sessions
| [1026041] Microsoft Windows Components DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1026040] Microsoft SharePoint Multiple Flaws Permit Cross-Site Scripting and Information Disclosure Attacks
| [1026039] Microsoft Office DLL Loading Error and Unspecified Bug Lets Remote Users Execute Arbitrary Code
| [1026038] Microsoft Excel Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1026037] Microsoft Windows Internet Name Service (WINS) Input Validation Flaw in ECommEndDlg() Lets Local Users Gain Elevated Privileges
| [1025937] Microsoft Windows DHCPv6 Processing Flaw Lets Remote Denial of Service to RPC Services
| [1025905] Microsoft .NET Socket Trust Validation Error Lets Remote Users Obtain Information and Redirect Certain Network Traffic
| [1025903] Microsoft Visual Studio Input Validation Hole Permits Cross-Site Scripting Attacks
| [1025902] Microsoft ASP.NET Chart Control Remote File Disclosure
| [1025896] Microsoft Visio Memory Corruption Errors Let Remote Users Execute Arbitrary Code
| [1025895] Microsoft Data Access Components Insecure Library Loading Lets Remote Users Execute Arbitrary Code
| [1025894] Microsoft DNS Server Flaws Let Remote Users Execute Arbitrary Code and Deny Service
| [1025893] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Obtain Potentially Sensitive Information
| [1025847] Microsoft Internet Explorer Flaw in Processing EUC-JP Encoded Characters Lets Remote Users Conduct Cross-Site Scripting Attacks
| [1025763] Microsoft Visio May Load DLLs Unsafely and Remotely Execute Arbitrary Code
| [1025760] Microsoft Windows Bluetooth Stack Memory Access Error Lets Remote Users Execute Arbitrary Code
| [1025675] Microsoft Word Unspecified Flaw Lets Remote Users Execute Arbitrary Code
| [1025655] Microsoft MHTML Input Validation Hole Permits Cross-Site Scripting Attacks
| [1025654] Microsoft Internet Explorer Vector Markup Language (VML) Object Access Error Lets Remote Users Execute Arbitrary Code
| [1025653] Microsoft Active Directory Input Validation Flaw in Certificate Services Web Enrollment Permits Cross-Site Scripting Attacks
| [1025649] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Obtain Potentially Sensitive Information
| [1025648] Microsoft SQL Server XML Editor External Entity Resolution Flaw Lets Remote Users Obtain Potentially Sensitive Information
| [1025647] Microsoft Visual Studio XML Editor External Entity Resolution Flaw Lets Remote Users Obtain Potentially Sensitive Information
| [1025646] Microsoft Office InfoPath XML Editor External Entity Resolution Flaw Lets Remote Users Obtain Potentially Sensitive Information
| [1025644] Microsoft Hyper-V VMBus Packet Validation Flaw Lets Local Users Deny Service
| [1025643] Microsoft Windows Ancillary Function Driver Lets Local Users Gain Elevated Privileges
| [1025642] Microsoft Excel Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1025641] Microsoft .NET JIT Compiler Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1025639] Microsoft Distributed File System Bugs Let Remote Users Deny Service and Execute Arbitrary Code
| [1025637] Microsoft Forefront Threat Management Gateway Bounds Validation Flaw in Winsock Provider Lets Remote Users Execute Arbitrary Code
| [1025636] Microsoft .NET Array Offset Error Lets Remote Users Execute Code
| [1025635] Microsoft Silverlight Array Offset Error Lets Remote Users Execute Arbitrary Code
| [1025634] Microsoft Windows OLE Automation Underflow Lets Remote Users Execute Arbitrary Code
| [1025513] Microsoft PowerPoint Memory Corruption Errors Let Remote Users Execute Arbitrary Code
| [1025512] Microsoft Windows Internet Name Service Socket Send Exception Handling Bug Lets Remote Users Execute Arbitrary Code
| [1025360] Microsoft Reader Memory Corruption Errors Let Remote Users Execute Arbitrary Code
| [1025359] Microsoft MHTML Stack Overflow Lets Remote Users Execute Arbitrary Code
| [1025347] Microsoft Fax Cover Page Editor Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1025346] Microsoft Foundation Classes May Load DLLs Unsafely and Remotely Execute Arbitrary Code
| [1025344] Microsoft WordPad Parsing Error Lets Remote Users Execute Arbitrary Code
| [1025343] Microsoft Office DLL Loading and Graphic Object Processing Flaws Let Remote Users Execute Arbitrary Code
| [1025340] Microsoft PowerPoint Bugs Let Remote Users Execute Arbitrary Code
| [1025337] Microsoft Excel Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1025335] Microsoft GDI+ EMF Image Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1025334] Microsoft OpenType Compact Font Format (CFF) Driver Stack Overflow Lets Remote Users Execute Arbitrary Code
| [1025333] Microsoft JScript and VBScript Engine Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1025331] Microsoft .NET Stack Corruption Error in JIT Compiler Lets Remote Users Execute Arbitrary Code
| [1025330] Microsoft WMITools and Windows Messenger ActiveX Controls Let Remote Users Execute Arbitrary Code
| [1025327] Microsoft Internet Explorer Bugs Let Remote Users Obtain Potentially Sensitive Information, Execute Arbitrary Code, and Hijack User Clicks
| [1025312] Microsoft Windows Kernel Bug in AFD.sys Lets Local Users Deny Service
| [1025248] Microsoft Windows Includes Some Invalid Comodo Certificates
| [1025171] Microsoft Groove DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1025170] Microsoft DirectShow DLL Loading Error Lets Remote Users Execute Arbitrary Code
| [1025164] Microsoft Internet Explorer Lets Remote Users Spoof the Address Bar
| [1025117] Microsoft Malware Protection Engine Registry Processing Error Lets Local Users Gain Elevated Privileges
| [1025086] Microsoft Active Directory Heap Overflow in Processing BROWSER ELECTION Packets May Let Remote Users Execute Arbitrary Code
| [1025049] Microsoft Local Security Authority Subsystem Service (LSASS) Lets Local Users Gain Elevated Privileges
| [1025044] Microsoft JScript and VBScript Disclose Information to Remote Users
| [1025043] Microsoft Visio Memory Corruption Error in Processing Visio Files Lets Remote Users Execute Arbitrary Code
| [1025042] Microsoft Active Directory SPN Collosions May Let Remote Authenticated Users Deny Service
| [1025038] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1025003] Microsoft MHTML Input Validation Hole May Permit Cross-Site Scripting Attacks
| [1024947] Microsoft Data Access Components (MDAC) Memory Corruption Errors in Processing DSN Data and ADO Records Let Remote Users Execute Arbitrary Code
| [1024940] Microsoft Internet Explorer Use-After-Free in 'mshtml.dll' May Let Remote Users Execute Arbitrary Code
| [1024925] Microsoft Fax Cover Page Editor Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1024922] Microsoft Internet Explorer Recursive CSS Import Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1024888] Microsoft Exchange Server RPC Processing Flaw Lets Remote Authenticated Users Deny Service
| [1024887] Microsoft Office Graphics Filters Let Remote Users Execute Arbitrary Code
| [1024886] Microsoft SharePoint Input Validation Flaw in Processing SOAP Requests Let Remote Users Execute Arbitrary Code
| [1024885] Microsoft Publisher Bugs Let Remote Users Execute Arbitrary Code
| [1024884] Microsoft Hyper-V Input Validation Flaw Lets Local Guest Operating System Users Deny Service
| [1024879] Microsoft Windows Internet Connection Signup Wizard May Load DLLs Unsafely and Remotely Execute Arbitrary Code
| [1024877] Microsoft Windows May Load DLLs Unsafely and Remotely Execute Arbitrary Code
| [1024874] Microsoft Windows Task Scheduler Lets Local Users Gain Elevated Privileges
| [1024872] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Conduct Cross-Domain Attacks
| [1024790] Microsoft Outlook Attachment Processing Flaw Lets Remote Users Deny Service
| [1024707] Microsoft Forefront Unified Access Gateway Input Validation Flaws Permit Cross-Site Scripting and URL Redirection Attacks
| [1024706] Microsoft PowerPoint Bugs Let Remote Users Execute Arbitrary Code
| [1024705] Microsoft Office Flaws Let Remote Users Execute Arbitrary Code
| [1024676] Microsoft Internet Explorer Freed Object Invalid Flag Reference Access Lets Remote Users Execute Arbitrary Code
| [1024630] Microsoft Internet Explorer 'window.onerror' Callback Lets Remote Users Obtain Information From Other Domains
| [1024559] Microsoft SharePoint Input Validation Hole in SafeHTML Permits Cross-Site Scripting Attacks
| [1024558] Microsoft Cluster Service Disk Permission Flaw Lets Local Users Gain Elevated Privileges
| [1024557] Microsoft Foundation Classes Library Buffer Overflow in Window Title Lets Remote Users Execute Arbitrary Code
| [1024552] Microsoft Office Excel Has Multiple Flaws That Let Remote Users Execute Arbitrary Code
| [1024551] Microsoft Office Word Processing Flaws Let Remote Users Execute Arbitrary Code
| [1024546] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code, Obtain Information, and Conduct Cross-Site Scripting Attacks
| [1024543] Microsoft .NET Framework JIT Compiler Memory Access Error Lets Remote Users Execute Arbitrary Code
| [1024459] Microsoft ASP.NET Padding Oracle Attack Lets Remote Users Decrypt Data
| [1024445] Microsoft Outlook Web Access Authentication Flaw Lets Remote Users Hijack User Sessions
| [1024443] Microsoft Local Security Authority Subsystem Service (LSASS) Heap Overflow Lets Remote Authenticated Users Execute Arbitrary Code
| [1024442] Microsoft WordPad Parsing Error in Text Converters Lets Remote Users Execute Arbitrary Code
| [1024441] Microsoft Windows RPC Memory Allocation Error Lets Remote Users Execute Arbitrary Code
| [1024440] Microsoft Internet Information Services Bugs Let Remote Users Bypass Authentication, Deny Service, and Execute Arbitrary Code
| [1024439] Microsoft Outlook Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1024438] Microsoft Office Unicode Font Parsing in USP10.DLL Lets Remote Users Execute Arbitrary Code
| [1024312] Microsoft Windows Tracing Feature for Services Lets Local Users Gain Elevated Privileges
| [1024310] Microsoft Office Excel Flaw Lets Remote Users Execute Arbitrary Code
| [1024306] Microsoft Silverlight Memory Corruption Errors Let Remote Users Execute Arbitrary Code
| [1024305] Microsoft .NET Framework Virtual Method Delegate Processing Error Lets Remote Users Execute Arbitrary Code
| [1024304] Microsoft Cinepak Codec Memory Pointer Error Lets Remote Users Execute Arbitary Code
| [1024303] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Conduct Cross-Domain Attacks
| [1024302] Microsoft MPEG Layer-3 Codecs Stack Overflow Lets Remote Users Execute Arbitary Code
| [1024301] Microsoft XML Core Services (MSXML) HTTP Response Processing Flaw Lets Remote Users Execute Arbitrary Code
| [1024298] Microsoft Office Word RTF, Word, and HTML Processing Errors Let Remote Users Execute Arbitrary Code
| [1024216] Microsoft Windows Shell LNK Shortcut Processing Flaw Lets Users Execute Arbitrary Code
| [1024189] Microsoft Office Outlook Validation Error in Processing Attachments Lets Remote Users Execute Arbitrary Code
| [1024188] Microsoft Office Access ActiveX Controls Let Remote Users Execute Arbitrary Code
| [1024084] Microsoft Help and Support Center URL Escaping Flaw Lets Remote Users Execute Arbitrary Commands
| [1024080] Microsoft .NET XML Digital Signature Flaw May Let Remote Users Bypass Authentication
| [1024079] Microsoft Internet Information Services Memory Allocation Error Lets Remote Authenticated Users Execute Arbitrary Code
| [1024078] Microsoft SharePoint Input Validation Flaw in toStaticHTML API Permits Cross-Site Scripting Attacks
| [1024077] Microsoft SharePoint Help Page Processing Bug Lets Remote Users Deny Service
| [1024076] Microsoft Office Excel Has Multiple Flaws That Let Remote Users Execute Arbitrary Code
| [1024075] Microsoft Office Open XML File Format Converter for Mac Lets Local Users Gain Elevated Privileges
| [1024073] Microsoft Office COM Object Instantiation Error Lets Remote Users Execute Arbitrary Code
| [1024070] Microsoft Internet Explorer 8 Developer Tools ActiveX Control Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1024068] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Conduct Cross-Site Scripting Attacks
| [1023975] Microsoft Office Memory Corruption Error in VBE6.DLL Lets Remote Users Execute Arbitrary Code
| [1023974] Microsoft Visual Basic for Applications Memory Corruption Error in VBE6.DLL Lets Remote Users Execute Arbitrary Code
| [1023972] Microsoft Outlook Express Integer Overflow in Processing POP3/IMAP Responses Lets Remote Users Execute Arbitrary Code
| [1023938] Microsoft Office Visio Buffer Overflow in Processing DXF Files Lets Remote Users Execute Arbitrary Code
| [1023932] Microsoft Office SharePoint Input Validation Flaw in 'help.aspx' Permits Cross-Site Scripting Attacks
| [1023856] Microsoft Visio Index Calculation and Attribute Validation Flaws Let Remote Users Execute Code
| [1023855] Microsoft Exchange May Disclose Message Fragments to Remote Users
| [1023854] Microsoft Exchange Error in Parsing MX Records Lets Remote Users Deny Service
| [1023853] Microsoft Office Publisher TextBox Processing Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1023848] Microsoft MPEG Layer-3 Codecs Stack Overflow Lets Remote Users Execute Arbitary Code
| [1023773] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code and Obtain Potentially Sensitive Information
| [1023720] Microsoft Virtual PC/Server Lets Local Users Gain Elevated Privileges
| [1023699] Microsoft Internet Explorer Invalid Pointer Reference Lets Remote Users Execute Arbitrary Code
| [1023698] Microsoft Office Excel Bugs Let Remote Users Execute Arbitrary Code
| [1023571] Microsoft Windows Protocol Flaw in SSL Renegotiation Lets Remote Users Conduct Man-in-the-Middle Attacks
| [1023567] Microsoft Hyper-V Instruction Validation Bug Lets Local Users Deny Service
| [1023566] Microsoft Windows Kerberos Ticket-Granting-Ticket Processing Flaw Lets Remote Authenticated Users Deny Service
| [1023565] Microsoft Office Buffer Overflow in 'MSO.DLL' Lets Remote Users Execute Arbitrary Code
| [1023564] Microsoft Paint Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1023563] Microsoft PowerPoint Buffer Overflows and Memory Errors Let Remote Users Execute Arbitrary Code
| [1023562] Microsoft DirectShow Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1023560] Microsoft Internet Explorer Flaw in Microsoft Data Analyzer ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1023542] Microsoft Internet Explorer Discloses Known Files to Remote Users
| [1023495] Microsoft Internet Explorer and Windows OS Shell Handler URL Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1023494] Microsoft Internet Explorer Cross-Site Scripting Filter Can Be Bypassed
| [1023493] Microsoft Internet Explorer Multiple Memory Access Flaws Let Remote Users Execute Arbitrary Code
| [1023462] Microsoft Internet Explorer Invalid Pointer Reference Lets Remote Users Execute Arbitrary Code
| [1023432] Microsoft Embedded OpenType Font Engine Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1023301] Microsoft Internet Explorer Indeo Codec Bugs Let Remote Users Execute Arbitrary Code
| [1023297] Microsoft Local Security Authority Subsystem Service Validation Flaw Lets Remote Users Deny Service
| [1023296] Microsoft Active Directory Federation Services Lets Remote Authenticated Users Execute Arbitrary Code and Spoof Web Sites
| [1023294] Microsoft Office Word and WordPad Text Converter Memory Errors Let Remote Users Execute Arbitrary Code
| [1023293] Microsoft Internet Explorer Memory Access Flaws Let Remote Users Execute Arbitrary Code
| [1023292] Microsoft Office Publisher Memory Allocation Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1023291] Microsoft Internet Authentication Service Bugs Let Remote Authenticated Users Execute Arbitrary Code or Gain Privileges of the Target User
| [1023233] Microsoft Internet Explorer Discloses Local Path Names When Printing Local HTML Files to PDF Files
| [1023226] Microsoft Internet Explorer Invalid Pointer Reference in getElementsByTagName() Method Lets Remote Users Execute Arbitrary Code
| [1023158] Microsoft Word Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1023157] Microsoft Excel Bugs Let Remote Users Execute Arbitrary Code
| [1023156] Microsoft Active Directory Stack Memory Consumption Flaw Lets Remote Users Deny Service
| [1023154] Microsoft License Logging Service Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1023153] Microsoft Web Services on Devices API (WSDAPI) Validation Error Lets Remote Users Execute Arbitrary Code
| [1023013] Microsoft Crypto API NULL Character Flaw in Common Name Field and ASN.1 Integer Overflow Lets Remote Users Spoof Certficiates
| [1023011] Microsoft Indexing Service ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1023010] Microsoft Local Security Authority Subsystem Service (LSASS) Integer Underflow Lets Local Users Deny Service
| [1023009] Microsoft Silverlight Memory Modification Flaw Lets Remote Users Execute Arbitrary Code
| [1023008] Microsoft .NET Bugs Let Remote Users Execute Arbitrary Code
| [1023006] Microsoft GDI+ Overflows Let Remote Users Execute Arbitrary Code
| [1023002] Microsoft Internet Explorer Flaws Let Remote Users Execute Arbitrary Code
| [1022846] Microsoft Wireless LAN AutoConfig Service Heap Overflow Lets Remote Wireless Users Execute Arbitrary Code
| [1022843] Microsoft DHTML Editing Component ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1022842] Microsoft JScript Scripting Engine Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1022716] Microsoft Telnet NTLM Credential Reflection Flaw Lets Remote Users Gain Access
| [1022715] Microsoft ASP.NET Request Scheduling Flaw Lets Remote Users Deny Service
| [1022712] Microsoft Active Template Library (ATL) Bugs Let Remote Users Execute Arbitrary Code
| [1022710] Microsoft Windows Internet Name Service (WINS) Buffer Overflows Let Remote Users Execute Arbitrary Code
| [1022708] Microsoft Office Web Components Buffer Overflows in ActiveX Control Let Remote Users Execute Arbitrary Code
| [1022611] Microsoft Internet Explorer Memory Corruption Bugs Let Remote Users Execute Arbitrary Code
| [1022610] Microsoft Visual Studio Active Template Library Bugs Let Remote Users Execute Arbitrary Code
| [1022547] Microsoft Internet Security and Acceleration Server OTP Authentication Bug Lets Remote Users Access Resources
| [1022546] Microsoft Office Publisher Pointer Dereference Bug Lets Remote Users Execute Arbitrary Code
| [1022545] Microsoft DirectX DirectShow Validation Bugs Let Remote Users Execute Arbitrary Code
| [1022544] Microsoft Virtual PC/Server Lets Local Users Gain Elevated Privileges Within a Guest Operating System
| [1022535] Microsoft Office Web Components Bug in Spreadsheet ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1022514] Microsoft DirectShow Buffer Overflow in ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1022369] Microsoft PowerPoint Buffer Overflow in Freelance Translator Lets Remote Users Execute Arbitrary Code
| [1022358] Microsoft Internet Information Services WebDAV Bug Lets Remote Users Bypass Authentication
| [1022356] Microsoft Word Buffer Overflows Let Remote USers Execute Arbitrary Code
| [1022355] Microsoft Office Works Document Converter Bug Lets Remote Users Execute Arbitrary Code
| [1022354] Microsoft Works Document Converter Bug Lets Remote Users Execute Arbitrary Code
| [1022351] Microsoft Excel Bugs Let Remote Users Execute Arbitrary Code
| [1022350] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1022349] Microsoft Active Directory Bugs Let Remote Users Execute Arbitrary Code or Deny Service
| [1022330] Microsoft Windows Bug in SETDESKWALLPAPER and GETDESKWALLPAPER Calls Let Local Users Deny Service
| [1022299] Microsoft DirectX Bug in DirectShow QuickTime Parser Lets Remote Users Execute Arbitrary Code
| [1022240] Microsoft Internet Information Server WebDAV Input Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1022205] Microsoft PowerPoint Has Multiple Buffer Overflows and Memory Corruption Bugs That Let Remote Users Execute Arbitrary Code
| [1022047] Microsoft Windows SearchPath Function May Let Remote Users Execute Arbitrary Code
| [1022046] Microsoft ISA Server Input Validation Flaw in 'cookieauth.dll' Permits Cross-Site Scripting Attacks
| [1022045] Microsoft ISA Server TCP State Error Lets Remote Users Deny Service
| [1022044] Microsoft Windows Privilege Separation and Access Control Bugs Let Local Users Gain Elevated Privileges
| [1022043] Microsoft WordPad and Office Text Converter Bugs Let Remote Users Execute Arbitrary Code
| [1022042] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1022040] Microsoft DirectX Bug in Decompressing DirectShow MJPEG Content Lets Remote Users Execute Arbitrary Code
| [1022039] Microsoft Excel Malformed Object Memory Corruption Bug Lets Remote Users Execute Arbitrary Code
| [1021967] Microsoft Office PowerPoint Invalid Object Access Bug Lets Remote Users Execute Arbitrary Code
| [1021880] Microsoft Internet Explorer Unspecified Bug Lets Remote Users Execute Arbitrary Code
| [1021831] Microsoft DNS Server Bugs Let Remote Users Spoof the DNS Service
| [1021830] Microsoft DNS Server Registration Validation Flaw Lets Remote Users Conduct Spoofing Attacks
| [1021829] Microsoft WINS Server Registration Validation Flaw Lets Remote Users Conduct Spoofing Attacks
| [1021744] Microsoft Excel Invalid Object Access Flaw Lets Remote Users Execute Arbitrary Code
| [1021702] Microsoft Visio Bugs Let Remote Users Execute Arbitrary Code
| [1021701] Microsoft Exchange MAPI Command Literal Processing Bug Lets Remote Users Deny Service
| [1021700] Microsoft Exchange Memory Corruption Error in Decoding TNEF Data Lets Remote Users Execute Arbitrary Code
| [1021699] Microsoft Internet Explorer Bugs in Handling CSS Sheets and Deleted Objects Lets Remote Users Execute Arbitrary Code
| [1021629] Microsoft Windows Guidelines for Disabling AutoRun are Ineffective and May Permit Code Execution
| [1021490] Microsoft SQL Server Heap Overflow Lets Remote Authenticated Users Execute Arbitrary Code
| [1021381] Microsoft Internet Explorer DHTML Data Binding Invalid Pointer Reference Bug Lets Remote Users Execute Arbitrary Code
| [1021376] Microsoft WordPad Word 97 Text Converter Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1021371] Microsoft Internet Explorer HTML Processing Bugs Let Remote Users Execute Arbitrary Code
| [1021370] Microsoft Word Memory Corruption Errors Let Remote Users Execute Arbitrary Code
| [1021369] Microsoft Visual Basic DataGrid/FlexGrid/Heirarchival FlexGrid/Windows Common/Charts ActiveX Controls Let Remote Users Execute Arbitrary Code
| [1021368] Microsoft Excel Formula, Object, and Global Array Bugs Let Remote Users Execute Arbitrary Code
| [1021367] Microsoft Office SharePoint Server Access Control Flaw Lets Remote Users Gain Administrative Access
| [1021365] Microsoft GDI Buffer Overflows in Processing WMF Files Lets Remote Users Execute Arbitrary Code
| [1021363] Microsoft SQL Server Memory Overwrite Bug in sp_replwritetovarbin May Let Remote Users Execute Arbitrary Code
| [1021294] Microsoft Office Communicator VoIP Processing Bugs Let Remote Users Deny Service
| [1021164] Microsoft XML Core Services (MSXML) Bugs Let Remote Users Obtain Information and Execute Arbitrary Code
| [1021053] Microsoft Ancillary Function Driver 'afd.sys' Lets Local Users Gain Elevated Privileges
| [1021052] Microsoft Message Queuing (MSMQ) Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1021047] Microsoft Internet Explorer Flaws Permit Cross-Domain Scripting Attacks and Let Remote Users Execute Arbitrary Code
| [1021045] Microsoft Office CDO Protocol Bug Lets Remote Users Execute Arbitrary Scripting Code
| [1021044] Microsoft Excel Object, Calendar, and Formula Bugs Let Remote Users Execute Arbitrary Code
| [1021043] Microsoft Host Integration Server RPC Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1021042] Microsoft Active Directory LDAP Memory Allocation Error Lets Remote Users Execute Arbitrary Code
| [1021020] Cisco Unity Bug in Microsoft API Lets Remote Users Deny Service
| [1021018] Microsoft Digital Image 'PipPPush.DLL' ActiveX Control Lets Remote Users Access Files
| [1020838] Microsoft GDI+ Integer Overflow in Processing BMP Files Lets Remote Users Execute Arbitrary Code
| [1020837] Microsoft GDI+ Buffer Overflow in Processing WMF Files Lets Remote Users Execute Arbitrary Code
| [1020836] Microsoft GDI+ Bug in Processing GIF Image Files Lets Remote Users Execute Arbitrary Code
| [1020835] Microsoft GDI+ Memory Corruption Error in Processing EMF Image Files Lets Remote Users Execute Arbitrary Code
| [1020834] Microsoft GDI+ Heap Overflow in Processing Gradient Sizes Lets Remote Users Execute Arbitrary Code
| [1020833] Microsoft Office OneNote Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1020679] Microsoft Outlook Express MTHML Redirect Bug Lets Remote Users Obtain Information
| [1020678] Microsoft Windows IPSec Policy May Not Be Enforced in Certain Cases
| [1020677] Microsoft Windows Event System Bugs Let Remote Authenticated Users Execute Arbitrary Code
| [1020676] Microsoft PowerPoint Memory Errors Let Remote Users Execute Arbitrary Code
| [1020675] Microsoft Color Management Module Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1020674] Microsoft Internet Explorer Multiple Bugs Let Remote Users Execute Arbitrary Code
| [1020673] Microsoft Office Format Filter Bugs Let Remote Users Execute Arbitrary Code
| [1020672] Microsoft Excel Input Validation Bug in Parsing Records Lets Remote Users Execute Arbitrary Code
| [1020671] Microsoft Excel Input Validation Bug in Processing Array Index Values Lets Remote Users Execute Arbitrary Code
| [1020670] Microsoft Excel Input Validation Bug in Processing Index Values Lets Remote Users Execute Arbitrary Code
| [1020669] Microsoft Excel Credential Caching Bug Lets Local Users Gain Access to Remote Data Sources
| [1020607] Mac OS X Quick Look Buffer Overflow in Downloading Microsoft Office Files Lets Remote Users Execute Arbitrary Code
| [1020447] Microsoft Word Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1020446] Microsoft Windows AutoRun Bug May Let Users Execute Arbitrary Code
| [1020441] Microsoft SQL Server Bugs Let Remote Authenticated Users Obtain Information and Execute Arbitrary Code
| [1020439] Microsoft Outlook Web Access for Exchange Server Input Validation Bugs Permit Cross-Site Scripting Attacks
| [1020433] Microsoft Access Snapshot Viewer ActiveX Control Lets Remote Users Download Files to Arbitrary Locations
| [1020382] Microsoft Internet Explorer Lets Remote Users Conduct Cross-Domain Scripting Attacks
| [1020232] Microsoft Speech API Lets Remote Users Execute Arbitrary Commands
| [1020229] Microsoft Active Directory LDAP Validation Bug Lets Remote Users Deny Service
| [1020228] Microsoft WINS Data Structure Validation Bug Lets Local Users Gain Elevated Privileges
| [1020226] Microsoft Internet Explorer HTTP Request Header Bug May Let Remote Users Obtain Information in a Different Domain
| [1020225] Microsoft Internet Explorer Bug in Processing Method Calls Lets Remote Users Execute Arbitrary Code
| [1020223] Microsoft DirectX SAMI File Validation Bug Lets Remote Users Execute Arbitrary Code
| [1020222] Microsoft DirectX MJPEG Stream Error Handling Bug Lets Remote Users Execute Arbitrary Code
| [1020016] Microsoft Malware Protection Engine Lets Remote Users Deny Service
| [1020015] Microsoft Publisher Bug in Processing Object Header Data Lets Remote Users Execute Arbitrary Code
| [1020014] Microsoft Word Memory Error in Processing CSS Values Lets Remote Users Execute Arbitrary Code
| [1020013] Microsoft Word Memory Error in Processing RTF Files Lets Remote Users Execute Arbitrary Code
| [1020006] Microsoft Windows XP 'i2omgmt.sys' Input Validation Flaw Lets Local Users Gain Elevated Privileges
| [1019804] Microsoft Visio Lets Remote Users Execute Arbitrary Code
| [1019801] Microsoft Internet Explorer Data Stream Processing Bug Lets Remote Users Execute Arbitrary Code
| [1019800] Microsoft Internet Explorer 'hxvz.dll' ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1019798] Microsoft GDI Buffer Overflow in Processing EMF and WMF Files Lets Remote Users Execute Arbitrary Code
| [1019797] Microsoft Project Memory Error Lets Remote Users Execute Arbitrary Code
| [1019738] Microsoft Office S/MIME Processing Lets Remote Users Access Arbitrary URLs
| [1019736] Microsoft Outlook S/MIME Processing Lets Remote Users Access Arbitrary URLs
| [1019686] Microsoft Jet Database Buffer Overflow in 'msjet40.dll' Lets Remote Users Execute Arbitrary Code via Word Documents
| [1019587] Microsoft Excel Input Validation Bug in Processing Conditional Formatting Values Lets Remote Users Execute Arbitrary Code
| [1019586] Microsoft Excel Input Validation Bug in Processing Rich Text Data Lets Remote Users Execute Arbitrary Code
| [1019585] Microsoft Excel Formula Parsing Error Lets Remote Users Execute Arbitrary Code
| [1019584] Microsoft Excel Input Validation Bug in Processing Style Record Data Lets Remote Users Execute Arbitrary Code
| [1019583] Microsoft Excel Flaw in Importing '.slk' Files Lets Remote Users Execute Arbitrary Code
| [1019582] Microsoft Excel Input Validation Bug in Processing Data Validation Records Lets Remote Users Execute Arbitrary Code
| [1019581] Microsoft Office Web Components DataSource Bug Lets Remote Users Execute Arbitrary Code
| [1019580] Microsoft Office Web Components URL Parsing Bug Lets Remote Users Execute Arbitrary Code
| [1019579] Microsoft Outlook 'mailto:' URL Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1019578] Microsoft Office and Excel Memory Corruption Bugs Let Remote Users Execute Arbitrary Code
| [1019388] Microsoft Works/Microsoft Office Bug in Processing '.wps' Field Length Values Lets Remote Users Execute Arbitrary Code
| [1019387] Microsoft Works/Microsoft Office Bug in Processing '.wps' Header Index Table Lets Remote Users Execute Arbitrary Code
| [1019386] Microsoft Works/Microsoft Office Bug in Processing '.wps' File Section Length Headers Lets Remote Users Execute Arbitrary Code
| [1019385] Microsoft Internet Information Services Error in Processing ASP Page Input Lets Remote Users Execute Arbitrary Code
| [1019384] Microsoft Internet Information Services File Change Notification Bug Lets Local Users Gain Elevated Privileges
| [1019381] Microsoft Internet Explorer Argument Validation Flaw in 'dxtmsft.dll' Lets Remote Users Execute Arbitrary Code
| [1019380] Microsoft Internet Explorer Property Method Processing Bug Lets Remote Users Execute Arbitrary Code
| [1019379] Microsoft Internet Explorer HTML Layout Rendering Bug Lets Remote Users Execute Arbitrary Code
| [1019378] Microsoft Internet Explorer Buffer Overflow in Fox Pro ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1019377] Microsoft Office Publisher Memory Corruption Bug Lets Remote Users Execute Arbitrary Code
| [1019376] Microsoft Office Publisher Invalid Memory Reference Bug Lets Remote Users Execute Arbitrary Code
| [1019375] Microsoft Office Object Processing Flaw Lets Remote Users Execute Arbitrary Code
| [1019374] Microsoft Word Memory Error Lets Remote Users Execute Arbitrary Code
| [1019258] Microsoft Visual Basic '.dsr' File Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1019200] Microsoft Excel File Header Bug Lets Remote Users Execute Arbitrary Code
| [1019165] Microsoft Windows LSASS Lets Local Users Gain Elevated Privileges
| [1019078] Microsoft Internet Explorer Object Access Bugs Let Remote Users Execute Arbitrary Code
| [1019077] Microsoft Message Queuing (MSMQ) Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1019073] Microsoft DirectX Bugs in Parsing SAMI, WAV, and AVI Files Let Remote Users Execute Arbitrary Code
| [1019033] Microsoft Web Proxy Auto-Discovery Name Server Resolution Bug Lets Remote Users Conduct Man-in-the-Middle Attacks
| [1018976] Microsoft Jet Engine Stack Overflow May Let Remote Users Execute Arbitrary Code
| [1018942] Microsoft Windows DNS Service Insufficent Entropy Lets Remote Users Spoof the DNS Service
| [1018903] Microsoft DebugView 'Dbgv.sys' Module Lets Local Users Gain Kernel Level Privileges
| [1018831] Microsoft Windows ShellExecute() URI Handler Bug Lets Remote Users Execute Arbitrary Commands
| [1018790] Microsoft Word Bug in Processing Office Files Lets Remote Users Execute Arbitrary Code
| [1018789] Microsoft SharePoint Input Validation Hole Permits Cross-Site Scripting Attacks
| [1018788] Microsoft Internet Explorer Bugs Let Remote Users Spoof the Address Bar and Execute Arbitrary Code
| [1018786] Microsoft Outlook Express Bug in Processing NNTP Responses Lets Remote Users Execute Arbitrary Code
| [1018727] Microsoft Internet Security and Acceleration Server SOCKS4 Proxy Discloses IP Address Information to Remote Users
| [1018677] Microsoft Agent ActiveX Control Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1018676] Microsoft Visual Basic VBP File Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1018568] Microsoft Vector Markup Language Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1018567] Microsoft Virtual PC/Server Heap Overflow Lets Local Users Gain Elevated Privileges
| [1018563] Microsoft GDI Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1018562] Microsoft Internet Explorer CSS and ActiveX Control Bugs Let Remote Users Execute Arbitrary Code
| [1018561] Microsoft Excel Workspace Index Validation Bug Lets Remote Users Execute Arbitrary Code
| [1018560] Microsoft OLE Automation Memory Corruption Bug Lets Remote Users Execute Arbitrary Code
| [1018559] Microsoft Core XML Services Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1018551] Microsoft DirectX Buffer Overflow in FlashPix ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1018520] Microsoft Visual Database Tools Buffer Overflow in ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1018420] Microsoft DirectX Heap Overflow in Processing RLE-Compressed Targa Images Lets Remote Users Execute Arbitrary Code
| [1018353] Microsoft Office Publisher Lets Remote Users Execute Arbitrary Code
| [1018352] Microsoft Excel Caculation Error and Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1018351] Microsoft Internet Explorer Bug in Firefox URL Protocol Handler Lets Remote Users Execute Arbitrary Commands
| [1018321] Microsoft Excel Sheet Name Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1018251] Microsoft Office Buffer Overflow in MSODataSourceControl ActiveX Control May Let Remote Users Execute Arbitrary Code
| [1018235] Microsoft Internet Explorer Bugs Let Remote Users Execute Arbitrary Code
| [1018202] Microsoft GDI+ ICO File Divide By Zero Bug Lets Remote Users Deny Service
| [1018193] Microsoft Internet Explorer Lets Remote Users Spoof Certain Objects
| [1018192] Microsoft Internet Explorer Input Validation Hole Permits Cross-Site Scripting Attacks
| [1018107] Microsoft Office Buffer Overflow in OUACTRL.OCX ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1018019] Microsoft Internet Explorer Bugs Let Remote Users Modify Files or Execute Arbitrary Code
| [1018017] Microsoft CAPICOM 'CAPICOM.Certificates' ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1018016] Microsoft BizTalk Server 'CAPICOM.Certificates' ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1018015] Microsoft Exchange Base64, iCal, IMAP, and Attachment Processing Bugs Let Remote Users Deny Service or Execute Arbitrary Code
| [1018014] Microsoft Office Drawing Object Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1018013] Microsoft Word Array and RTF Processing Bugs Let Remote Users Execute Arbitrary Code
| [1018012] Microsoft Excel Specially Crafted BIFF Records, Set Font Values, and Filter Records Permit Remote Code Execution
| [1017969] Microsoft Internet Explorer Digest Authentication Bug Lets Remote Users Conduct HTTP Request Splitting Attacks
| [1017910] Microsoft Windows DNS Service RPC Stack Overflow Lets Remote Users Execute Arbitrary Code
| [1017902] Microsoft Word Lets Remote Users Cause Arbitrary Code to Be Executed
| [1017901] Microsoft Windows Help File Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1017896] Microsoft Agent URL Parsing Bug Lets Remote Users Execute Arbitrary Code
| [1017894] Microsoft Content Management Server Permits Cross-Site Scripting Attacks and Lets Remote Users Execute Arbitrary Code
| [1017827] Microsoft Windows Animated Cursor Bug Lets Remote Users Execute Arbitrary Code
| [1017752] Adobe JRun IIS Connector Bug Lets Remote Users Deny Service
| [1017736] Microsoft Windows Explorer OLE Parsing Bug Lets Users Deny Service
| [1017694] VeriSign Secure Messaging for Microsoft Exchange Stack Overflow in ConfigChk ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1017653] Microsoft Word Unspecified Vulnerability Lets Remote Users Execute Arbitrary Code
| [1017643] Microsoft Internet Explorer Multiple COM Objects Let Remote Users Execute Arbitrary Code
| [1017642] Microsoft Internet Explorer FTP Server Response Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017641] Microsoft Windows RichEdit OLE Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017640] Microsoft Office OLE Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017639] Microsoft Word Macro Security Warning Bug and Drawing Object Memory Corrupution Error Lets Remote Users Execute Arbitrary Code
| [1017638] Microsoft MFC Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017637] Microsoft OLE Dialog RTF File Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017636] Microsoft Windows Defender Integer Overflow in Parsing PDF Files Lets Remote Users Execute Arbitrary Code
| [1017635] Microsoft HTML Help ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1017632] Microsoft Step-by-Step Interactive Training Buffer Overflow in Processing Bookmark Links Lets Remote Users Execute Arbitrary Code
| [1017584] Microsoft Office Excel Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1017579] [Duplicate Entry] Microsoft Word Unspecified Vulnerability Lets Remote Users Execute Arbitrary Code
| [1017564] Microsoft Word Function Processing Bug Lets Remote Users Execute Arbitrary Code
| [1017530] Microsoft Help Workshop Buffer Overflow in Processing '.CNT' Files Lets Remote Users Execute Arbitrary Code
| [1017488] Microsoft Outlook '.iCal', '.oss', and SMTP Header Bugs Let Remote Users Execute Arbitrary Code or Deny Service
| [1017487] Microsoft Excel Buffer Overflows in Processing Various Records and Strings Lets Remote Users Execute Arbitrary Code
| [1017486] Microsoft Office Brazilian Portuguese Grammar Checker Lets Remote Users Execute Arbitrary Code
| [1017485] Microsoft Excel Memory Access Error Lets Remote Users Execute Arbitrary Code
| [1017441] Microsoft Windows Workstation Service Memory Allocation Error in NetrWkstaUserEnum() Lets Remote Users Deny Service
| [1017397] Microsoft Outlook Recipient ActiveX Control Lets Remote Users Deny Service
| [1017390] Microsoft Word Unchecked Count Vulnerability Lets Remote Users Execute Arbitrary Code
| [1017388] Microsoft Project Discloses Database Password to Remote Authenticated Users
| [1017374] Microsoft Internet Explorer May Disclose Contents of the Temporary Internet Files Folder to Remote Users
| [1017373] Microsoft Internet Explorer DHTML and Script Error Handling Bugs Let Remote Users Execute Arbitrary Code
| [1017369] Microsoft Outlook Express Buffer Overflow in Processing Windows Address Book Files Let Remote Users Execute Arbitrary Code
| [1017358] Microsoft Word Data Structure Processing Bug Lets Remote Users Cause Arbitrary Code to Be Executed
| [1017339] Microsoft Word String Processing Bug Lets Remote Users Execute Arbitrary Code
| [1017224] Microsoft Client Service for Netware Buffer Overflows Let Remote Users Execute Arbitrary Code and Crash the System
| [1017223] Microsoft Internet Explorer Bug in Rending HTML Layout Combinations May Let Remote Users Execute Arbitrary Code
| [1017222] Microsoft Agent '.ACF' File Memory Corruption Error Lets Remote Users Execute Arbitrary Code
| [1017168] Microsoft Windows Kernel GDI Data Structure Processing Bug Lets Local Users Gain Elevated Privileges
| [1017165] Microsoft Internet Explorer 'ieframe.dll' Lets Remote Users Spoof Invalid Certificates
| [1017157] Microsoft XML Core Services ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1017142] Microsoft Visual Studio WMI Object Broker ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1017133] Microsoft NAT Helper 'ipnathlp.dll' Lets Remote Users Deny Service
| [1017127] Microsoft Data Access Components 'ADODB.Connection' Execute Function Lets Remote Users Execute Arbitrary Code
| [1017122] Microsoft Internet Explorer Lets Remote Users Partially Spoof Address Bar URLs
| [1017059] Microsoft PowerPoint Bug Causes PowerPoint to Crash
| [1017034] Microsoft Office String, Chart Record, and SmartTag Validation Errors Let Remote Users Execute Arbitrary Code
| [1017033] Microsoft XML Core Services Lets Remote Users Execute Arbitrary Code or Obtain Information
| [1017032] Microsoft Word String and Mail Merge Record Validation Flaws Let Remote Users Execute Arbitrary Code
| [1017031] Microsoft Excel DATETIME/COLINFO Record Errors and Lotus 1-2-3 Errors Let Remote Users Execute Arbitrary Code
| [1017030] Microsoft PowerPoint Errors in Parsing Object Pointers and Data Records Lets Remote Users Execute Arbitrary Code
| [1016941] Microsoft Windows Shell Integer Overflow Lets Remote Users Execute Arbitrary Code
| [1016937] Microsoft PowerPoint Memory Corruption Bug Lets Remote Users Execute Arbitrary Code
| [1016886] [Duplicate] Microsoft PowerPoint Bug Lets Remote Users Execute Arbitrary Code
| [1016879] Microsoft Internet Explorer VML Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1016854] Microsoft Internet Explorer Buffer Overflow in 'daxctle.ocx' ActiveX in KeyFrame Method Control Lets Remote Users Execute Arbitrary Code
| [1016839] Microsoft Internet Explorer URLMON.DLL Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1016827] Microsoft PGM Implementation Buffer Overflow in MSMQ Service Lets Remote Users Execute Arbitrary Code
| [1016825] Microsoft Publisher Buffer Overflow in Parsing '.pub' Files Lets Remote Users Execute Arbitrary Code
| [1016787] Microsoft Word Record Validation Vulnerability Lets Remote Users Execute Arbitrary Code
| [1016764] Microsoft Internet Explorer (IE) Buffer Overflow in 'daxctle.ocx' ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1016731] Microsoft Internet Explorer URL Buffer Overflow in Processing HTTP 1.1 Protocol with Compression Lets Remote Users Execute Arbitrary Code
| [1016720] [Duplicate Entry] Microsoft PowerPoint Unknown Bug May Let Remote Users Execute Arbitrary Code
| [1016663] Microsoft Internet Explorer Bugs Let Remote Users Obtain Information or Execute Arbitrary Code
| [1016657] Microsoft Office Buffer Overflow in Processing PowerPoint Records Lets Remote Users Execute Arbitrary Code
| [1016656] Microsoft Visual Basic for Applications Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1016655] Microsoft Management Console Input Validation Hole Permits Remote Code Execution
| [1016654] Microsoft Outlook Express MHTML Parsing Error Lets Remote Users Execute Arbitrary Code
| [1016506] Microsoft Internet Security and Acceleration Server HTTP File Exentsion Filter Can Be Bypassed By Remote Users
| [1016504] Microsoft Works Buffer Overflow in Processing Spreadsheet Files May Let Remote Users Execute Arbitrary Code
| [1016496] Microsoft PowerPoint 'mso.dll' Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1016472] Microsoft Excel Errors in Processing Various Malformed Records Let Remote Users Execute Arbitrary Code
| [1016470] Microsoft Office PNG and GIF File Buffer Error Lets Remote Users Execute Arbitrary Code
| [1016469] Microsoft Office String Parsing and Property Bugs Let Remote Users Execute Arbitrary Code
| [1016468] Microsoft DHCP Client Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1016453] Microsoft Office LsCreateLine() Function May Let Remote Users Execute Arbitrary Code
| [1016434] Microsoft HTML Help Heap Overflow in HHCtrl ActiveX Control May Let Remote Users Execute Arbitrary Code
| [1016430] Microsoft Excel STYLE Record Bug May Let Remote Users Execute Arbitrary Code
| [1016388] Microsoft Windows Explorer Lets Remote Users Access Information in Other Domains and Execute HTA Applications
| [1016344] Microsoft Excel 'Shockwave Flash Object' Lets Remote Users Execute Code Automatically
| [1016339] Microsoft Windows 'hlink.dll' Buffer Overflow in Processing Hyperlinks Lets Remote Users Execute Arbitrary Code
| [1016316] Microsoft Excel Memory Validation Flaw May Let Remote Users Cause Arbitrary Code to Be Executed
| [1016292] Microsoft Windows Buffer Overflow in AOL ART Image Rendering Library Lets Remote Users Execute Arbitrary Code
| [1016291] Microsoft Internet Explorer Multiple Memory and Access Control Errors Let Remote Users Execute Arbitrary Code
| [1016290] Microsoft Windows Buffer Overflow in TCP/IP Stack Lets Remote Users Execute Arbitrary Code
| [1016289] Microsoft RPC Mutual Authentication Bug Lets Remote Users Spoof Other Systems
| [1016287] Microsoft PowerPoint Buffer Overflow in Processing Malformed Records Lets Remote Users Execute Arbitrary Code
| [1016286] Microsoft Windows 98 Graphics Rendering Engine Buffer Overflow in Processing WMF Images Lets Remote Users Execute Arbitrary Code
| [1016283] Microsoft JScript Memory Corruption Bug Lets Remote Users Execute Arbitrary Code
| [1016280] Microsoft Outlook Web Access Input Validation Hole Permits Cross-Site Scripting Attacks
| [1016196] F-Secure Anti-Virus for Microsoft Exchange Buffer Overflow in Web Console May Let Remote Users Execute Arbitrary Code
| [1016130] Microsoft Word Lets Remote Users Cause Arbitrary Code to Be Executed
| [1016048] Microsoft Exchange Error in Processing iCAL/vCAL Properties Lets Remote Users Execute Arbitrary Code
| [1016047] Microsoft Distributed Transaction Coordinator Bugs Let Remote Users Deny Service
| [1016005] Microsoft Outlook Express 'mhtml:' Redirect URL Processing Lets Remote Users Bypass Security Domains
| [1016001] Microsoft Internet Explorer Bug in Processing Nested OBJECT Tags Lets Remote Users Execute Arbitrary Code
| [1015900] Microsoft Internet Explorer  Parsing and State Errors Let Remote Users Execute Arbitrary Code
| [1015899] Microsoft Internet Explorer Lets Remote Users Spoof the Address Bar URL
| [1015898] Microsoft Outlook Express Buffer Overflow  in Processing Windows Address Books Lets Remote Users Execute Arbitrary Code
| [1015897] Microsoft Windows Explorer COM Object Bug Lets Remote Users Execute Arbitrary Code
| [1015896] Microsoft FrontPage Server Extensions Input Validation Holes Permit Cross-Site Scripting Attacks
| [1015895] Microsoft SharePoint Team Services Input Validation Holes Permit Cross-Site Scripting Attacks
| [1015894] Microsoft Data Access Components RDS.Dataspace Access Control Bug Lets Remote Users Execute Arbitrary Code
| [1015892] Microsoft Internet Explorer Popup Window Object Bugs Let Remote Users Execute Scripting Code in Arbitrary Domains
| [1015855] Microsoft Office Array Index Boundary Error Lets Remote Users Execute Arbitrary Code
| [1015825] Microsoft ASP.NET Incorrect COM Component Reference Lets Remote Users Deny Service
| [1015812] Microsoft Internet Explorer createTextRange() Memory Error Lets Remote Users Execute Arbitrary Code
| [1015800] (Vendor Issues Fix) Microsoft Internet Explorer (IE) Lets Remote Users Cause HTA Files to Be Executed
| [1015794] (Vendor Issues Fix) Microsoft Internet Explorer 'mshtml.dll' Bug in Processing Multiple Action Handlers Lets Remote Users Deny Service
| [1015766] Microsoft Office and Excel Buffer Overflows Let Remote Users Execute Arbitrary Code
| [1015765] Microsoft Windows Services Have Unsafe Default ACLs That Let Remote Authenticated Users Gain Elevated Privileges
| [1015720] Microsoft Internet Explorer Modal Security Dialog Race Condition May Let Remote Users Install Code or Obtain Information
| [1015632] Microsoft PowerPoint May Let Users Access Contents of the Temporary Internet Files Folder
| [1015631] Microsoft Office Korean Input Method Editor Lets Local Users Gain Elevated Privileges
| [1015630] Microsoft Windows Web Client Buffer Overflow Lets Remote Authenticated Users Execute Arbitrary Code
| [1015629] Microsoft Windows IGMP Processing Bug Lets Remote Users Deny Service
| [1015595] Microsoft Windows UPnP/NetBT/SCardSvr/SSDP Services May Be Incorrectly Configured By 3rd Party Applications, Allowing Local Users to Gain Elevated Privileges
| [1015585] Microsoft HTML Help Workshop Buffer Overflow in Processing .hhp Files Lets Remote User Execute Arbitrary Code
| [1015559] Microsoft Internet Explorer Shockwave Flash Scripting Bug Lets Remote Users Deny Service
| [1015489] Microsoft Wireless Network Connection Software May Broadcast Ad-Hoc SSID Information in Certain Cases
| [1015461] Microsoft Outlook Buffer Overflow in Processing TNEF Messages Lets Remote Users Execute Arbitrary Code
| [1015460] Microsoft Exchange Buffer Overflow in Processing TNEF Messages Lets Remote Users Execute Arbitrary Code
| [1015459] Microsoft Windows Embedded Web Fonts Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1015453] Microsoft Windows Graphics Rendering Engine WMF File Memory Access Error Lets Remote Users Execute Arbitrary Code
| [1015416] Microsoft Windows Unspecified WMF Rendering Bug Lets Remote Users Execute Arbitrary Code
| [1015350] Microsoft Internet Explorer Bug in Using HTTPS Proxies May Disclose Web URLs to Remote Users
| [1015349] Microsoft Windows Internet Explorer May Let Remote Users Obfuscate the Download Dialog Box
| [1015348] Microsoft Internet Explorer Bug in Instantiating COM Objects May Let Remote Users Execute Arbitrary Code
| [1015347] Microsoft Windows 2000 Kernel APC Queue Bug Lets Local Users Gain Elevated Privileges
| [1015333] Microsoft Excel Unspecified Stack Overflow May Let Remote Users Cause Arbitrary Code to Be Executed
| [1015251] Microsoft Internet Explorer Bug in Processing Mismatched Document Object Model Objects May Let Remote Users Execute Arbitrary Code
| [1015233] Microsoft Windows RPC Service May Let Remote Users Deny Service
| [1015226] Microsoft AntiSpyware Improper CreateProcess() Call Lets Local Users Execute Arbitrary Code
| [1015168] Microsoft Windows Buffer Overflows in Graphics Rendering Engine Lets Remote Users Execute Arbitrary Code
| [1015143] F-Secure Anti-Virus for Microsoft Exchange Web Console May Disclose Files to Remote Users
| [1015101] Microsoft Internet Explorer J2SE Runtime Environment Bug Lets Remote Users Crash the Target User's Browser
| [1015044] Microsoft Windows Multiple COM Objects Let Remote Users Execute Arbitrary Code
| [1015043] Microsoft Network Connection Manager Lets Remote Users Deny Service
| [1015042] Microsoft Windows Plug and Play Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1015041] Microsoft Client Service for NetWare Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1015040] Microsoft Windows Shell Bugs in Processing '.lnk' Files and in Web View Preview Mode Lets Remote Users Execute Arbitrary Code
| [1015039] Microsoft Windows Buffer Overflow in Collaboration Data Objects Lets Remote Users Execute Arbitrary Code
| [1015038] Microsoft Exchange Buffer Overflow in Collaboration Data Objects Lets Remote Users Execute Arbitrary Code
| [1015037] Microsoft Windows Buffer Overflows in MSDTC and COM+ Let Remote Users Execute Arbitrary Code and Local User Gain Elevated Privileges
| [1015036] Microsoft Windows FTP Client Input Validation Hole Lets Remote Servers Create/Overwrite Files on the Target User's System
| [1015034] Microsoft DirectX DirectShow Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1014829] Microsoft Windows Firewall User Interface May Not Properly Display Exception Rules
| [1014809] Microsoft Internet Explorer Unspecified Bug May Permit Remote Code Execution
| [1014727] Microsoft 'msdds.dll' COM Object Lets Remote Users Execute Arbitrary Code
| [1014643] Microsoft Internet Explorer COM Object Instantiation Bug May Let Remote Users Execute Arbitrary Code
| [1014642] Microsoft Windows Kerberos and PKINIT Vulnerabilities Allow Denial of Service, Information Disclosure, and Spoofing
| [1014641] Microsoft Internet Explorer Web Folder URL Validation Bug Lets Remote Users Execute Scripting Code in an Arbitrary Security Domain
| [1014640] Microsoft Windows Plug and Play Stack Overflow Lets Remote Users Execute Arbitrary Code
| [1014639] Microsoft Windows Telephony Service Remote Code Execution or Local Privilege Escalation
| [1014638] Microsoft Windows Print Spooler Service Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1014501] Hosting Controller 'IISActions.asp' Script Lets Remote Authenticated Users Add Domains/Subdomains
| [1014500] Microsoft Internet Explorer (IE) JPEG Rendering Bugs Let Remote Users Deny Service or Execute Arbitrary Code
| [1014498] Microsoft Windows Remote Desktop Protocol Bug Lets Remote Users Deny Service
| [1014458] Microsoft Office Buffer Overflow in Parsing Fonts Lets Remote Users Cause Arbitrary Code to Be Executed
| [1014457] Microsoft Microsoft Color Management Module Lets Remote Users Execute Arbitrary Code
| [1014417] Microsoft Windows Named Pipe NULL Session Bugs in svcctl and eventlog RPC Interfaces Disclose Information to Remote Users
| [1014364] Microsoft Internet Information Server May Allow Remote Users to Conduct HTTP Response Smuggling Attacks
| [1014356] Microsoft ISA Server May Accept HTTP Authentication Even When SSL Is Required
| [1014352] Microsoft Front Page May Crash When Editing a Specially Crafted Web Page
| [1014329] Microsoft Internet Explorer 'javaprxy.dll' COM Object Exception Handling Lets Remote Users Execute Arbitrary Code
| [1014261] Microsoft Internet Explorer Lets Remote Users Spoof Javascript Dialog Boxes
| [1014201] Microsoft Internet Explorer Buffer Overflow in Rendering PNG Images Lets Remote Users Execute Arbitrary Code
| [1014200] Microsoft Outlook Express Buffer Overflow in NNTP Response Parser Lets Remote Users Execute Arbitrary Code
| [1014199] Microsoft Outlook Web Access Input Validation Hole in IMG Tags Permits Cross-Site Scripting Attacks
| [1014198] Microsoft Windows Buffer Overflow in Processing Server Message Block Packets Lets Remote Users Execute Arbitrary Code
| [1014197] Microsoft Agent Lets Remote Users Spoof Security Dialog Box Contents
| [1014196] Microsoft Windows Buffer Overflow in Web Client Service Lets Remote Authenticated Users Execute Arbitrary Code
| [1014195] Microsoft HTML Help Input Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1014194] Microsoft Step-by-Step Interactive Training Bookmark Link File Validation Flaw Lets Remote Users Execute Arbitrary Code
| [1014193] Microsoft Internet Security and Acceleration Server Bugs Let Remote Users Poison the Cache and Establish NetBIOS Connections
| [1014174] Microsoft Internet Explorer Lets Remote Users Obfuscate Scripting Code
| [1014113] Microsoft ISA Server in SecureNAT Configuration Can Be Crashed By Remote Users
| [1014050] Computer Associates eTrust Antivirus Integer Overflow in Processing Microsoft OLE Data Lets Remote Users Execute Arbitrary Code
| [1013996] Microsoft ASP.NET May Disclose System Information to Remote Users in Certain Cases
| [1013761] Microsoft Windows Explorer 'webvw.dll' Input Validation Error Lets Remote Users Execute Arbitrary Scripting Code
| [1013724] RSA Authentication Agent for Web for IIS Input Validation Bug Lets Remote Users Conduct Cross-Site Scripting Attacks
| [1013692] Microsoft Internet Explorer Buffer Overflows in DHTML, URL Parsing, and Content Advisor Let Remote Users Execute Arbitrary Code
| [1013691] Microsoft Message Queuing Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1013689] Microsoft Windows Shell MSHTA Lets Remote Users Code Execute Arbitrary Scripting Code
| [1013688] Microsoft Windows Kernel and Font Buffer Overflows Let Local Users Deny Service or Obtain System Privileges
| [1013687] Microsoft Exchange Heap Overlow in Processing Extended SMTP Verb Lets Remote Users Execute Arbitrary Code
| [1013686] Microsoft Windows TCP, IP, and ICMP Processing Errors Let Remote Users Deny Service and Execute Arbitrary Code
| [1013684] Microsoft Word Unspecified Buffer Overflow in Processing Documents Lets Remote Users Execute Arbitrary Code
| [1013669] Microsoft Outlook Web Access 'From' Address Display Lets Remote Users Spoof Origination Addresses
| [1013668] Microsoft Outlook 'From' Address Display Lets Remote Users Spoof Origination Addresses
| [1013618] Microsoft Jet Database Buffer Overflow in 'msjet40.dll' Lets Remote Users Execute Arbitrary Code
| [1013583] Microsoft Outlook Connector for IBM Lotus Domino Lets Users Bypass Password Storage Policy
| [1013552] Microsoft Windows Remote Desktop 'TSShutdn.exe' Lets Remote Authenticated Users Shutdown the System
| [1013454] Microsoft Office InfoPath 2003 May Disclose System and Authentication Information to Remote Users
| [1013284] Microsoft Windows 2000 and XP Group Policy Can Be Bypassed By Microsoft Office Applications and By Flash Drives
| [1013205] Microsoft Internet Explorer Can Be Crashed With URL Containing Special URL Characters
| [1013126] Microsoft Internet Explorer CDF Scripting Error Lets Remote Users Execute Scripting Code in Arbitrary Domains
| [1013125] Microsoft Internet Explorer DHTML Method Heap Overflow Lets Remote Users Execute Arbitrary Code
| [1013124] Microsoft Internet Explorer URL Encoding Error Lets Remote Users Spoof Arbitrary URLs and Execute Scripting Code in Arbitrary Security Zone
| [1013120] Microsoft Windows OLE Buffer Overflow Lets Remote Users Execute Arbitrary Code and COM Access Flaw Lets Remote Authenticated Users Gain Elevated Privileges
| [1013119] Microsoft Windows Hyperlink Object Library Lets Remote Users Execute Arbitrary Code
| [1013117] Microsoft Windows License Logging Service Lets Remote Users Execute Arbitrary Code
| [1013115] Microsoft Windows Media Player Buffer Overflow in Processing PNG Files Lets Remote Users Execute Arbitrary Code
| [1013114] Microsoft Windows SMB Lets Remote Users Execute Arbitrary Code
| [1013112] Microsoft Windows XP Named Pipe Validation Error Lets Remote Users Obtain Information
| [1013111] Microsoft SharePoint Services Redirection Query Input Validation Hole Lets Remote Users Conduct Cross-Site Scripting Attacks
| [1013110] Microsoft Office XP Buffer Overflow in Processing URLs Lets Remote Users Execute Arbitrary Code
| [1013086] Microsoft Outlook Web Access 'owalogon.asp' Lets Remote Users Redirect Login Requests
| [1012891] Microsoft IE Windows XP SP2 File Download Security Can Be Bypassed With Dynamic IFRAME Tag
| [1012836] Microsoft HTML Help Active Control Cross-Domain Error Lets Remote Users Execute Arbitrary Commands
| [1012835] Microsoft Cursor and Icon Validation Error Lets Remote Users Execute Arbitrary Code
| [1012684] Microsoft Windows LoadImage API Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1012683] Microsoft Windows ANI File Parsing Errors Let Remote Users Deny Service
| [1012682] Microsoft Windows Help System Buffer Overflows in Processing Phrase Compressed Help Files Lets Remote Users Execute Arbitrary Code
| [1012626] Microsoft Windows Media Player setItemInfo Lets Remote Users Execute Arbitrary Code
| [1012584] Microsoft IE dhtmled.ocx Lets Remote Users Execute Cross-Domain Scripting Attacks
| [1012518] Microsoft HyperTerminal Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1012517] Microsoft WINS Buffer Overflow in Name Value Lets Remote Users Execute Arbitrary Code
| [1012515] Microsoft Windows NT 4.0 Buffer Overflows in the Logging and Processing of DHCP Packets May Let Remote Users Execute Arbitrary Code
| [1012514] Microsoft WordPad Error in Converting Tables/Fonts Lets Remote Users Execute Arbitrary Code
| [1012513] Microsoft Windows Kernel Buffer Overflow in Processing Local Procedure Call Messages Lets Local Users Gain System Privileges
| [1012512] Microsoft LSASS Bug in Validating Identity Tokens Lets Local Users Gain Elevated Privileges
| [1012458] Microsoft Internet Explorer Lets Remote Users Inject Content into Open Windows
| [1012444] Microsoft Internet Explorer Input Validation Error in Processing FTP URLs May Let Remote Users Inject Arbitrary FTP Commands
| [1012435] Microsoft Windows Resource Kit Buffer Overflow and Input Validation Holes in 'w3who.dll' May Permit Remote Code Execution and Cross-Site Scripting Attacks
| [1012341] Microsoft WINS Memory Overwrite Lets Remote Users Execute Arbitary Code
| [1012288] Microsoft IE Custom 404 Error Message and execCommand SaveAs Lets Remote Users Bypass XP SP2 Download Warning Mechanisms
| [1012234] Microsoft Internet Explorer on XP SP2 Has Unspecified Flaws That Let Remote Users Bypass File Download Restrictions
| [1012155] Microsoft Internet Security and Acceleration Server Reverse DNS Caching Bug Lets Remote Users Spoof Web Sites
| [1012154] Microsoft Proxy Server Reverse DNS Caching Bug Lets Remote Users Spoof Web Sites
| [1012138] Microsoft IE Discloses Whether Specified Files Exist to Remote Users
| [1012057] F-Secure Anti-Virus for Microsoft Exchange Lets Remote Users Bypass Anti-Virus Detection With a ZIP Archive
| [1012049] (Exploit Code Has Been Released) Microsoft Internet Explorer Buffer Overflow in IFRAME/EMBED Tag Processing Lets Remote Users Execute Arbitrary Code
| [1011987] Microsoft Internet Explorer Lets Remote Users Spoof the Status Bar Address with a Table Within a Link
| [1011940] Microsoft Remote Desktop on Windows XP Lets Remote Authenticated Users Restart the System
| [1011895] Microsoft IE for Mac Multi-Window Browsing Errors Let Remote Users Spoof Sites
| [1011890] Microsoft Outlook May Display Images in Plaintext Only Mode
| [1011880] Microsoft Windows XP Error in Explorer in Processing WAV Files Lets Remote Users Deny Service
| [1011859] Microsoft Internet Explorer on Windows XP Fails to Restrict Drag and Drop Operations When Configured to Disable These Operations
| [1011851] Microsoft IE AnchorClick Behavior and HTML Help Let Remote Users Execute Arbitrary Code
| [1011735] Microsoft Internet Explorer May Display the Incorrect URL When Loading a Javascript Homepage
| [1011706] Microsoft Operating System 'asycpict.dll' Lets Remote Users Crash the System
| [1011678] Microsoft IE MSN 'heartbeat.ocx' Component Has Unspecified Flaw
| [1011647] Microsoft Windows Shell Buffer Overflows Let Remote Users Execute Arbitrary Code
| [1011646] Microsoft Program Group Converter Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1011645] Microsoft Various Operating System Flaws Lets Remote Users Execute Code and Local Users Gain Elevated Privileges or Deny Service
| [1011644] Microsoft IE Plug-in Navigation Flaw Lets Remote Users Spoof URLs in the Addresses Bar
| [1011643] Microsoft IE Double Byte Parsing Flaw Lets Remote Users Spoof URLs in the Addresses Bar
| [1011642] Microsoft IE SSL Caching Flaw Lets Remote Users Run Scripting Code in the Context of Arbitrary Secure Sites
| [1011640] Microsoft IE Buffer Overflow in Install Engine Lets Remote Users Execute Arbitrary Code
| [1011639] Microsoft IE Buffer Overflow in Processing Cascading Style Sheets Lets Remote Users Execute Arbitrary Code
| [1011637] Microsoft Windows Buffer Overflow in Processing Compressed Folders Lets Remote Users Execute Arbitrary Code
| [1011636] Microsoft SMTP Service Buffer Overflow in Processing DNS Responses May Let Remote Users Execute Arbitrary Code
| [1011635] Microsoft Excel Unspecified Flaw Lets Remote Users Execute Arbitrary Code
| [1011634] Microsoft NetDDE Buffer Overflow Lets Remote Users Execute Arbitrary Code With System Privileges
| [1011632] Microsoft NT RPC Runtime Library Buffer Overflow Lets Remote Users Deny Service
| [1011631] Microsoft NNTP Buffer Overflow Lets Remote Users Execute Arbitrary Code With SYSTEM Privileges
| [1011626] Microsoft Cabarc Directory Traversal Flaw Lets Remote Users Create/Overwrite Files on the Target System
| [1011565] Microsoft Word Parsing Flaw May Let Remote Users Execute Arbitrary Code
| [1011563] Microsoft Internet Explorer Lets Remote Users Access XML Documents
| [1011559] Microsoft .NET Forms Authentication Can Be Bypassed By Remote Users
| [1011434] Microsoft SQL Server Can Be Crashed By Remote Users Sending a Specially Crafted Large Buffer
| [1011332] Microsoft Internet Explorer Bug in Setting Cookies in Certain Domains May Let Remote Users Conduct Session Fixation Attacks
| [1011253] Microsoft GDI+ Buffer Overflow in Processing JPEG Images Lets Remote Users Execute Arbitrary Code
| [1011252] Microsoft Works Suite Buffer Overflow in WordPerfect Converter Lets Remote Users Execute Arbitrary Code
| [1011251] Microsoft Publisher Buffer Overflow in WordPerfect Converter Lets Remote Users Execute Arbitrary Code
| [1011250] Microsoft FrontPage Buffer Overflow in WordPerfect Converter Lets Remote Users Execute Arbitrary Code
| [1011249] Microsoft Office Buffer Overflow in WordPerfect Converter Lets Remote Users Execute Arbitrary Code
| [1011200] F-Secure Anti-Virus for Microsoft Exchange Input Validation Bug in Content Scanner Server Lets Remote Users Deny Service
| [1011141] HP Systems Insight Manager May Not Let Users Login After Applying a Microsoft Security Patch
| [1011067] Microsoft Outlook Express May Disclose 'bcc:' Recipient Addresses
| [1011043] Microsoft Internet Explorer Local File IFRAME Error Response Lets Remote Users Determine if Files or Directories Exist
| [1010996] Microsoft Windows XP SP2 Local Computer Scripting Restrictions Can Be Bypassed With a Specially Crafted MHT File
| [1010992] Microsoft Internet Security and Acceleration Server Does Not Block FTP Bounce Attacks
| [1010959] Microsoft Windows Explorer (in XP SP2) May Fail to Warn Users When Executing Untrusted Files
| [1010957] Microsoft Internet Explorer Unregistered Protocol State Error Lets Remote Users Spoof Location Bar
| [1010916] Microsoft Outlook Web Access Input Validation Hole in Redirection Query Permits Cross-Site Scripting Attacks
| [1010827] Microsoft Internet Explorer Error in 'mshtml.dll' in Processing GIF Files Lets Remote Users Crash the Browser
| [1010713] Microsoft Systems Management Server (SMS) Client Can Be Crashed By Remote Users
| [1010694] Microsoft IE Lets Remote Users Spoof Filenames Using CLSIDs
| [1010693] Microsoft Internet Explorer 'shell:' Protocol Lets Remote Users Execute Arbitrary Scripting Code in the Local Zone
| [1010690] Microsoft HTML Help Input Validation Error Lets Remote Users Execute Arbitrary Code
| [1010688] Microsoft Windows Task Scheduler Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1010687] Microsoft Windows 2000/NT POSIX Subsystem Buffer Overflow Lets Local Users Gain Elevated Privileges
| [1010686] Microsoft Utility Manager Permits Local Applications to Run With Elevated Privileges
| [1010683] Microsoft Internet Explorer Same Name Javascript Bug Lets Remote Users Execute Arbitrary Javascript in the Domain of an Arbitrary Site
| [1010679] Microsoft Internet Explorer Access Control Flaw in popup.show() Lets Remote Users Execute Mouse-Click Actions
| [1010673] Microsoft Internet Explorer Can Be Crashed By Remote Users With Large Text Files
| [1010550] Microsoft MN-500 Wireless Base Station Lets Remote Users Deny Administrative Access
| [1010491] Microsoft Internet Explorer Crashes When Saving Files With Special Character Strings
| [1010482] Microsoft Internet Explorer '%2F' URL Parsing Error Lets Remote Users Spoof Sites in the Trusted Zone
| [1010479] (US-CERT Issues Advisory) Microsoft Internet Explorer Cross-Domain Redirect Hole Lets Remote Users Execute Arbitrary Code
| [1010427] Microsoft DirectX DirectPlay Input Validation Error Lets Remote Users Crash the Application
| [1010352] Microsoft Windows 2000 Domains With Eight Characters May Let Remote Users With Expired Passwords Login
| [1010314] Microsoft Windows IPSec Filtering Can Be Bypassed By Remote Users
| [1010189] Microsoft Outlook 2003 Scripting Restrictions Can Be Bypassed By Remote Users
| [1010175] Microsoft Visual Basic Buffer Overflow May Let Local Users Gain Elevated Privileges
| [1010166] Microsoft Outlook Express Mail Troubleshooting Function May Disclose SMTP Password to Local Users
| [1010165] Microsoft Internet Explorer Image Map URL Display Error Lets Remote Users Spoof URLs
| [1010157] Microsoft Internet Explorer showHelp Path Search Lets Remote Users Load Existing Local CHM Files
| [1010125] Microsoft Outlook 2003 Lets Remote Users Send E-mail to Cause the Recipient's Client to Contact a Remote Server
| [1010119] Microsoft Help and Support Center HCP URL Validation Error May Let Remote Users Execute Arbitrary Code If User Interactions Occur
| [1010092] Microsoft Internet Explorer 'file://' URL Processing Flaw Lets Remote Users Damage the Registry
| [1010009] Microsoft Internet Explorer SSL Icon Error May Let Remote Users Impersonate Secure Web Sites
| [1009940] Microsoft Windows Explorer Buffer Overflow in Processing SMB Share Names Lets Remote Users Execute Arbitrary Code
| [1009939] Microsoft Internet Explorer Buffer Overflow in Processing SMB Share Names Lets Remote Users Execute Arbitrary Code
| [1009778] Microsoft H.323 Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1009777] Microsoft SSL Library Input Validation Error Lets Remote Users Crash the Service
| [1009776] Microsoft Windows Kernel Local Descriptor Table Flaw Lets Local Users Gain Elevated Privileges
| [1009771] Microsoft Windows Negotiate Security Software Provider (SSP) Buffer Overflow Lets Remote and Local Users Execute Arbitrary Code
| [1009770] Microsoft Windows Management Interface Provider Lets Local Users Gain Elevated Privileges
| [1009769] Microsoft Utility Manager Lets Local Users Run Applications With Elevated Privileges
| [1009768] Microsoft Winlogon Buffer Overflow Lets Certain Remote Users Execute Arbitrary Code
| [1009767] Microsoft Windows 2000 Domain Controller LDAP Flaw May Let Remote Users Restart the Authentication Service
| [1009762] Microsoft Windows COM Internet Services and RPC over HTTP Can Be Crashed By Remote Users
| [1009761] Microsoft Windows COM Object Identifier Creation Flaw May Let Remote Users Cause Applications to Open Network Ports
| [1009760] Microsoft Virtual DOS Machine (VDM) Lets Local Users Gain Elevated Privileges
| [1009758] Microsoft Windows RCP Memory Leak Lets Remote Users Deny Service
| [1009757] Microsoft Jet Database Engine 'msjet40.dll' Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1009754] Microsoft ASN.1 Library (msasn1.dll) Double-Free Memory Allocation Error May Let Remote Users Execute Arbitrary Code
| [1009753] Microsoft SSL Library PCT Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1009752] Microsoft Help and Support Center Input Validation Flaw Lets Remote Users Execute Arbitrary Code in the My Computer Zone
| [1009751] Microsoft LSASS Service Buffer Overflow Lets Remote Users Execute Arbitrary Code With SYSTEM Privileges
| [1009746] Microsoft Internet Explorer Bitmap Memory Allocation Error Lets Remote Users Cause All Available Memory to Be Consumed
| [1009743] Microsoft Outlook Express Can Be Crashed By Remote Users With Specially Crafted EML File
| [1009739] Microsoft Internet Explorer Javascript OLE Object Lets Remote Users Automatically Print Without Authorization
| [1009690] Microsoft Internet Explorer Security Domain Flaw in Accessing CHM Files Lets Remote Users Execute Arbitrary Code
| [1009673] Microsoft Windows XP 'mswebdvd.dll' Buffer Overflow Lets Remote Users Deny Service
| [1009666] Microsoft SharePoint Portal Server Input Validation Holes Permit Cross-Site Scripting Attacks
| [1009604] Microsoft Internet Explorer Does Not Correctly Display Links With Embedded FORM Data
| [1009603] Microsoft Outlook Express Does Not Correctly Display Links With Embedded FORM Data
| [1009546] Microsoft Operating Systems Have Unspecified Flaw That Yields Kernel Level Access to Local Users
| [1009361] Microsoft Internet Explorer Cookie Path Restrictions Can Be Bypassed By Remote Servers
| [1009360] Microsoft MSN Messenger May Disclose Known Files to Remote Users
| [1009359] Microsoft Windows Media Services Can Be Crashed By Remote Users
| [1009358] Microsoft Office XP 'mailto' URL Parsing Bug Lets Remote Users Execute Arbitrary Code in the Local Computer Domain
| [1009357] Microsoft Outlook 'mailto' URL Parsing Bug Lets Remote Users Execute Arbitrary Code in the Local Computer Domain
| [1009243] Microsoft Internet Explorer (IE) May Leak Keystrokes Across Frames
| [1009181] Microsoft Windows Explorer Heap Overflow in Processing '.emf' Files Permits Code Execution
| [1009067] Microsoft Internet Explorer Integer Overflow in Processing Bitmap Files Lets Remote Users Execute Arbitrary Code
| [1009009] Microsoft Virtual PC for Mac Temporary File Flaw Lets Local Users Gain Root Privileges
| [1009008] Microsoft Windows Internet Naming Service (WINS) Length Validation Flaw Lets Remote Users Deny Service
| [1009007] Microsoft ASN.1 Library Heap Overflows Let Remote Users Execute Arbitrary Code With SYSTEM Privileges
| [1008901] Microsoft Internet Explorer Travel Log Input Validation Flaw Lets Remote Users Run Arbitrary Scripting Code in the Local Computer Domain
| [1008699] Microsoft Windows Buffer Overflow in MDAC Lets Remote Users Execute Arbitrary Code
| [1008698] Microsoft Internet Security and Acceleration Server H.323 Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1008586] Microsoft Office Security Features Can Be Bypassed
| [1008583] Microsoft Internet Explorer Flaw in Processing '.lnk' Shortcuts Lets Remote Users Execute Arbitrary Code
| [1008578] Microsoft Internet Explorer showHelp() '\..\' Directory Traversal Flaw Lets Remote Users Execute Files on the Target System
| [1008558] Microsoft Internet Explorer Trusted Domain Default Settings Facilitate Silent Installation of Executables
| [1008554] Microsoft IE for Mac May Disclose Sensitive Information in Secure URLs to Remote Sites via HTTP Referer Field
| [1008510] Openwares.org 'Microsoft IE Security Patch' URL Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1008428] Microsoft ASP.NET Web Services XML Parsing Lets Remote Users Consume CPU Resources With SOAP Requests
| [1008425] Microsoft IE Does Not Properly Display Some URLs
| [1008324] Microsoft Exchange 2003 With Outlook Web Access and Windows SharePoint Services May Grant Incorrect E-mail Account Access to Remote Authenticated Users
| [1008293] Microsoft Internet Explorer Invalid ContentType May Disclose Cache Directory Location to Remote Users
| [1008292] Microsoft Internet Explorer MHT Redirect Flaws Let Remote Users Execute Arbitrary Code
| [1008245] Microsoft SharePoint May Let Remote Users Access Protected Pages Without Authenticating
| [1008151] Microsoft Works Macro Name Length Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1008150] Microsoft Word Macro Name Length Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1008149] Microsoft Excel Macro Security Flaw Lets Remote Users Execute Arbitrary Macro Codes
| [1008148] Microsoft SharePoint Team Services Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1008147] Microsoft FrontPage Server Extensions Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1008146] Microsoft Windows Workstation Service (wkssvc.dll) Buffer Overflow Lets Remote Users Execute Arbitrary Code with System Privileges
| [1008053] Microsoft Internet Explorer IFRAME Refresh Lets Remote HTML Access Local Files
| [1008000] Microsoft Internet Explorer Lets Remote Users Execute Arbitrary Files in the Local Zone Using a Specially Crafted IFRAME/Location Header
| [1007937] Microsoft Exchange Server Buffer Overflow in Processing Extended Verb Requests May Let Remote Users Execute Arbitrary Code
| [1007936] Microsoft Outlook Web Access Input Validation Flaw in 'Compose New Message' Permits Remote Cross-Site Scripting Attacks
| [1007935] Microsoft ListBox and ComboBox 'user32.dll' Buffer Overflow May Allow Local Users to Gain Elevated Privileges
| [1007934] Microsoft Help and Support Center HCP Buffer Overflow Lets Remote and Local Users Execute Arbitrary Code With Local Computer Privileges
| [1007933] Microsoft Windows Messenger Service Buffer Overflow Lets Remote Users Execute Arbitrary Code With Local System Privileges
| [1007932] Microsoft Windows Troubleshooter ActiveX Control Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1007931] Microsoft Authenticode Low Memory Flaw May Let Remote Users Execute Arbitrary Code
| [1007922] Microsoft Windows RPC Multi-threaded Race Condition Lets Remote Users Crash the Service or Execute Arbitrary Code
| [1007905] Microsoft Windows Server 2003 Shell Folders Can Be Referenced Using Directory Traversal Characters
| [1007874] Microsoft Windows OS PostThreadMessage() API Permits Local Users to Terminate Processes That Have Message Queues
| [1007750] Microsoft BizTalk Server Default Directory Permissions May Let Remote Users Deny Service
| [1007689] Microsoft Internet Explorer Media Sidebar Flaw Lets Remote Users Execute Arbitrary Code on the System
| [1007687] Microsoft Internet Explorer Various Cross-Domain Flaws Permit Remote Scripting in Arbitrary Domains
| [1007670] Microsoft Windows Remote Procedure Call (RPC) DCOM Activation Buffer Overflows Let Remote Users Execute Arbitrary Code
| [1007651] RealSecure Server Sensor Unicode Flaw Lets Remote Users Crash the IIS Web Service
| [1007618] Microsoft Visual Basic for Applications (VBA) in Multiple Microsoft Products Permits Remote Code Execution
| [1007617] Microsoft Converter for WordPerfect Has Buffer Overflow That Lets Remote Users Execute Arbitrary Code
| [1007616] Microsoft Word Document Validation Error Lets Macros Run Without Warning
| [1007615] Microsoft Windows NetBIOS Name Service May Disclose Memory Contents to Remote Users
| [1007614] Microsoft Access Snapshot Viewer ActiveX Control Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1007599] Microsoft Outlook May Fail to Delete Outlook Data From the PST File
| [1007538] Microsoft Internet Explorer Buffer Overflow in CR549.DLL ActiveX Control Permits Remote Code Execution
| [1007537] Microsoft Internet Explorer Object Tag Flaw Lets Remote Users Execute Arbitrary Code
| [1007536] Microsoft Internet Explorer Cache Script Flaw Lets Remote Users Execute Code in the My Computer Zone
| [1007535] Microsoft MDAC Database Component Lets Remote Users Execute Arbitrary Code
| [1007507] RSA SecurID Interaction With Microsoft URLScan May Disclose URLScan Configuration to Remote Users
| [1007493] Microsoft Visual Studio Buffer Overflow in 'mciwndx.ocx' May Let Remote Users Execute Arbitrary Code
| [1007388] Microsoft WebServer Beta for Pocket PC Yields Administrative Access to Remote Users
| [1007364] IISShield May Fail to Drop a Specific Malformed HTTP Request
| [1007306] Microsoft Outlook Express Again Executes Scripting Code in Plain Text E-mail Messages
| [1007281] Microsoft Windows NT File Management Flaw May Let Remote Users Crash Certain Applications
| [1007280] Microsoft Data/Desktop Engine Named Pipe and LPC Flaws Let Local Users Execute Arbitrary Code
| [1007279] Microsoft SQL Server Named Pipe and LPC Flaws Let Local Users Execute Arbitrary Code
| [1007278] Microsoft DirectX Heap Overflow in Loading MIDI Files Lets Remote Users Execute Arbitrary Code
| [1007265] Microsoft MDAC ODBC Component May Store Database Passwords in Plaintext in the Registry
| [1007238] Microsoft Outlook Web Access Can Be Crashed By Remote Authenticated Users With an Outlook 2003 Client
| [1007214] Microsoft Windows XP Shell Buffer Overflow in Processing Folder Display Attributes Permits Remote Code Execution
| [1007212] Microsoft Windows Remote Procedure Call (RPC) Service Buffer Overflow in Processing DCOM Requests Allows Remote Code Execution
| [1007206] Microsoft SMTP Service Can Be Crashed By Remote Users Sending Mail With an Invalid FILETIME Header
| [1007205] Microsoft Exchange Server Can Be Crashed By Remote Users Sending Mail With an Invalid FILETIME Header
| [1007190] Microsoft Internet Explorer 'Chromeless' Window May Let Remote Users Spoof Various User Interface Characteristics
| [1007172] Microsoft Jet Database Engine Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1007154] Microsoft SMB Buffer Overflow Lets Remote Authenticated Users Execute Arbitrary Code
| [1007152] Microsoft Windows 2000 Accessibility Utility Manager Lets Local Users Gain Elevated Privileges
| [1007133] Microsoft Outlook Web Access (OWA) May Disclose The User's OWA Password to Remote Users
| [1007126] Microsoft Internet Explorer Can By Crashed By Loading 'C:\aux' URL
| [1007099] Microsoft Windows 2000 ShellExecute() Buffer Overflow May Let Users Execute Arbitrary Code
| [1007098] Microsoft Commerce Server Discloses SQL Server Password to Local Users
| [1007094] Microsoft NetMeeting Directory Traversal Flaw Lets Remote Users Execute Arbitrary Code
| [1007093] Microsoft Active Directory Stack Overflow in 'Lsaas.exe' Lets Remote Users Crash the Windows 2000 Server
| [1007072] Microsoft Internet Explorer Buffer Overflow in Processing Scripted 'HR' Tags Lets Remote Users Execute Arbitrary Code
| [1007057] Microsoft Windows Media Player Access Control Flaw Lets Remote Users View, Modify, and Delete Media Library Metadata
| [1007022] SurfControl for Microsoft ISA Server Discloses Files to Remote Users
| [1007008] Microsoft Internet Explorer XML Parsing Error Lets Remote Users Conduct Cross-Site Scripting Attacks
| [1007007] Microsoft Internet Explorer Custom HTTP Error Pages May Let  Remote Users Execute Scripts in the Local Computer Zone
| [1006959] Microsoft Windows Server 2003 Drivers May Leak Information From Memory Via Ethernet Packets Containing TCP Streams
| [1006924] Microsoft Internet Explorer Input Validation Flaw in Displaying FTP Site Names Lets Remote Users Execute Arbitrary Scripting Code in Arbitrary Domains
| [1006918] Microsoft Internet Explorer (IE) Object Tag Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1006901] Microsoft UrlScan Default Configuration Displays Identifying Characteristics to Remote Users
| [1006894] iisCART2000 Upload Authentication Error Lets Remote Users Upload and Execute Arbitrary Scripts
| [1006844] Microsoft Internet Connection Firewall Fails to Block IP Version 6 Protocol
| [1006829] iisPROTECT Input Validation Hole Lets Remote Users Execute SQL Stored Procedures
| [1006815] iisPROTECT Lets Remote Users Access Protected Files Using URL Encoding
| [1006809] Microsoft Outlook Express Lets Remote Users Silently Install Arbitrary Code Using Audio and Media Files
| [1006808] Microsoft Outlook Express May Be Affected by W32/Palyh@MM Mass-Mailing Worm
| [1006807] Microsoft Outlook May Be Affected by W32/Palyh@MM Mass-Mailing Worm
| [1006803] Microsoft Windows Can Be Crashed By Remote Users via Malformed NetMeeting URLs
| [1006789] Microsoft ISA Server Input Validation Flaw Lets Remote Users Execute Scripting Code in Arbitrary Security Domains
| [1006774] Microsoft Internet Explorer May Execute Arbitrary Code in the Wrong Security Domain When Processing Large Numbers of Download Requests
| [1006771] Microsoft Outlook Express Integer Overflow Lets Remote IMAP Servers Cause the Client to Crash
| [1006748] Microsoft Outlook Express May Be Affected by W32.Fizzer.A@mm Mass-Mailing Worm
| [1006747] Microsoft Outlook May Be Affected by W32.Fizzer.A@mm Mass-Mailing Worm
| [1006728] Microsoft .NET Passport Passwords, Including Hotmail Passwords, Can Be Changed By Remote Users
| [1006696] Microsoft Internet Explorer Web Folder Access Flaw Lets Remote Users Execute Arbitrary Scripting Code in the My Computer Zone
| [1006691] Microsoft MN-500 Wireless Base Station Backup Configuration File Discloses Administrator Password
| [1006686] Microsoft BizTalk Server Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1006634] Microsoft Internet Explorer Bugs (URLMON.DLL Buffer Overflow, File Upload Control Bypass, Plug-in URL Input Validation Flaw, CSS Modal Dialog Input Validation Flaw) Let Remote Users Execute Arbitrary Code or Access Local Files
| [1006608] Microsoft NTLM Authentication Protocol Flaw Lets Malicious SMB Servers Gain Access to Systems
| [1006599] Microsoft REGEDIT.EXE May Let Local Users Gain Elevated Privileges
| [1006588] Microsoft Windows OS Kernel Messaging Buffer Overflow Lets Local Users Gain Full Control of the System
| [1006580] Microsoft Windows 2003 'win2k.sys' Printing Bug Lets Users Crash the System
| [1006534] Microsoft Proxy Service in Proxy Server 2.0 Has Unspecified Flaw That Lets Remote Users Stop Traffic
| [1006533] Microsoft Firewall Service in ISA Server Has Unspecified Flaw That Lets Remote Users Stop Traffic
| [1006532] Microsoft Windows VM Input Validation Flaw in ByteCode Verifier Lets Malicious Java Applets Execute Arbitrary Code
| [1006447] Microsoft Windows Terminal Services RDP Implementation Does Not Validate Server Identity, Allowing Man-in-the-Middle Attacks
| [1006361] Microsoft ActiveSync Application Can Be Crashed By Remote Users
| [1006323] Microsoft Windows Buffer Overflow in Windows Script Engine JScript.DLL Lets Remote Users Execute Arbitrary Code
| [1006322] Microsoft ISA Server DNS Intrusion Detection Flaw Lets Remote Users Block DNS Inbound Requests
| [1006286] Microsoft Windows 2000/XP PostMessage() API Flaw May Let Local Users Grab Passwords from Local Dialog Boxes
| [1006280] Protegrity Secure.Data for Microsoft SQL Server 2000 Contains Buffer Oveflows That Let Remote Users Execute Arbitrary Code
| [1006257] Microsoft Internet Explorer Buffer Overflow in Processing '.MHT' Web Archives Lets Remote Users Execute Arbitrary Code
| [1006179] Microsoft Windows Me Help and Support Center URL Handler Overflow Lets Remote Users Execute Arbitrary Code
| [1006169] Microsoft Internet Explorer Vulnerable Codebase Object Lets Remote Users Execute Arbitrary Code
| [1006148] Microsoft Outlook Express Security Domain Flaw Lets Remote Users Silently Install and Execute Arbitrary Code
| [1006121] Microsoft Windows 'riched20.DLL' Buffer Overflow May Let Remote Users Crash Applications
| [1006046] Microsoft Internet Explorer showHelp() Domain Security Flaw Lets Remote Users Execute Commands
| [1006045] Microsoft Windows XP Redirector Buffer Overflow May Let Local Users Gain System Level Privileges
| [1006036] Microsoft Internet Explorer May Let Remote Users Read or Write Files Via the dragDrop() Method
| [1006023] ColdFusion MX Configuration Error When Used With IIS and NT Authentication May Grant Unauthorized Access to Remote Authenticated Users
| [1005986] Microsoft Windows Terminal Server MSGINA.DLL Flaw Lets Remote Authenticated Users Reboot the Server
| [1005966] Microsoft Outlook May Fail to Encrypt User E-mail, Disclosing the Contents to Remote Users
| [1005964] Microsoft Locator Service Buffer Overflow Lets Remote Users Execute Arbitrary Code with System Level Privileges
| [1005859] Microsoft Windows File Protection Mechanism Weakness in Trusting Code-Signing Certificate Chains Lets Arbitrary Remote Users Sign Code That Will Be Trusted By Windows
| [1005858] Microsoft Windows File Protection Weakness May Let Local Users Replace Code With Previous Vulnerable Versions Without Detection
| [1005857] Microsoft Internet Explorer Bug in Loading Multimedia Files May Let Remote Users Execute Arbitrary Scripting Code in Other Domains
| [1005833] Microsoft Windows XP Shell Buffer Overflow in Processing Audio Files Allows Remote Users to Execute Arbitrary Code
| [1005799] Microsoft Windows OS Bug in Processing WM_TIMER Messages May Let Local Users Gain Elevated Privileges
| [1005796] Microsoft SMB Signing Flaw May Let Remote Users With Access to an SMB Session Gain Control of a Network Client
| [1005761] Microsoft Windows XP Wireless LAN Support May Disclose Access Point Information to Remote Users
| [1005757] Microsoft Outlook Bug in Processing Malformed E-mail Headers Lets Remote Users Crash the Client
| [1005747] Microsoft Internet Explorer showModalDialog() Input Validation Flaw Lets Remote Users Execute Arbitary Scripting Code in Any Security Zone
| [1005699] Microsoft Internet Explorer (IE) Java Class Loader Security Flaw Lets Remote Users Bypass Java Security Restrictions
| [1005698] Microsoft Java Virtual Machine (VM) Class Loader Security Flaw Lets Remote Users Bypass Java Security Restrictions
| [1005674] Microsoft Internet Explorer Buffer Overflow in Processing PNG Images Allows Denial of Service Attacks
| [1005672] Microsoft Internet Explorer MDAC Component Buffer Overflow Allows Remote Users to Execute Arbitrary Code
| [1005671] Microsoft Data Access Components (MDAC) Buffer Overflow Allows Remote Users to Execute Arbitrary Code
| [1005627] IISPop EMail Server Can Be Crashed By Remote Users
| [1005489] Microsoft Outlook Express May Fail to Delete E-mail Messages from Local Storage
| [1005466] Microsoft Internet Explorer Cached Object Flaw Lets Remote Users Execute Arbitrary Programs on the Target User's Computer
| [1005455] Microsoft Windows Remote Procedure Call (RPC) Service Null Pointer Dereference Allows Remote Users to Crash the Service
| [1005454] Microsoft Windows Media Player for Solaris Uses Unsafe Default Permissions
| [1005436] Microsoft Data Engine/Desktop Engine (MSDE) Bugs Let Remote Authenticated Users Create/Delete/Execute Web Tasks With SQL Server Agent Privileges
| [1005435] Microsoft SQL Server Bugs Let Remote Authenticated Users Create/Delete/Execute Web Tasks With SQL Server Agent Privileges
| [1005416] Microsoft Internet Explorer Flaw in WebBrowser Control Document Property Lets Remote Users Run Code in the My Computer Security Zone
| [1005405] Microsoft Outlook Express Buffer Overflow in Parsing S/MIME Messages Lets Remote Users Execute Arbitrary Code
| [1005395] Microsoft Content Management Server Input Validation Bug in 'ManualLogin.asp' Allows Cross-Site Scripting Attacks
| [1005377] Microsoft MSN Hotmail/Passport Login Page May Permit Cookie Stealing Via Cross-Site Scripting Attacks
| [1005343] Microsoft Windows Help System Bug in Processing Compiled HTML Help Files Lets Remote Users Execute Arbitrary Commands in the Local Computer Security Zone
| [1005339] Microsoft Services for Unix Interix SDK Bugs May Allow Denial of Service Conditions or May Execute Arbitrary Code
| [1005338] Microsoft Data/Desktop Engine (MSDE) Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1005337] Microsoft SQL Server Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1005336] Microsoft Windows Operating System Compressed Folders Allow Arbitrary Files to Be Created
| [1005335] Microsoft Windows Operating System Compressed Folders Allow Arbitrary Code to Be Executed
| [1005332] Microsoft Windows Help System Buffer Overflow in 'hhctrl.ocx' Lets Remote Users Execute Arbitrary Code
| [1005296] Microsoft PPTP Service Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1005287] Microsoft FrontPage Server Extensions SmartHTML Interpreter Bugs May Let Remote Users Execute Arbitrary Code with System Privileges
| [1005256] (Vendor Issues Fix) Microsoft Windows XP Remote Desktop Implementation Bug Lets Remote Users Crash the Operating System
| [1005254] Microsoft NT, 2000, and XP Operating Systems May Execute a 16-bit Application Even When The File Has No Execute Permissions
| [1005246] Microsoft Remote Desktop Protocol (RDP) Design Flaw May Disclose Information About the Unencrypted Data to Remote Users and May Let Data Be Modified During Transmission
| [1005243] Microsoft NetMeeting Remote Desktop Sharing Screen Saver Access Control Flaw Lets Physically Local Users Hijack Remote Sessions
| [1005242] Microsoft Windows XP Remote Desktop Can Be Crashed By Remote Users Sending a Modified RDP Packet
| [1005223] (Microsoft Responds) Microsoft Word Document Processing File Include Bug May Let Remote Users Obtain Files From a Target User's System
| [1005207] Microsoft Outlook Express Can Be Crashed By Remote Users Sending HTML Mail With Long Links Embedded
| [1005203] Microsoft Internet Explorer Frame Domain Security Bug Lets Remote Users Execute Arbitrary Code in the Local Computer Zone Via Frame URLs
| [1005200] Microsoft Internet Explorer Implementation Bugs in Java Native Methods May Let Remote Users Execute Arbitrary Code Via Malicious Applets
| [1005182] Microsoft Internet Explorer URL Decoding Inconsistency May Result in a Web Page Loading in the Incorrect Security Domain
| [1005177] Microsoft Visual FoxPro Filename Processing Bug Lets Remote Users Create HTML That Will Cause Arbitrary Code to Be Executed When the HTML is Loaded
| [1005150] Microsoft Windows Operating System Certificate Enrollment ActiveX Control Allows Remote Users to Delete Certificates on a Target User's System
| [1005128] Microsoft Internet Explorer XML Script Element Redirect Bug Lets Remote Users View XML Files on the Target User's Computer
| [1005127] Microsoft Visual Studio .NET Web Projects May Disclose the Web Directory Structure to Remote Users
| [1005123] Microsoft Internet Explorer Buffer Overflow in Unspecified Text Formatting ActiveX Control Lets Remote Users Execute Arbitrary Code
| [1005120] Microsoft Terminal Services Advanced Client (TSAC) ActiveX Control Buffer Overflow Lets Remote Users Execute Arbitrary Code
| [1005119] Microsoft Operating System SMB Protocol Implementation in the Network
| [1005112] Microsoft File Transfer Manager ActiveX Control Buffer Overflow May Let Remote Users Execute Arbitrary Code
| [1005108] Microsoft Windows Media Player Allows Malicious Windows Media Download (.wmd) Files to Silently Create Files in a Known Location and Execute Them
| [1005075] Microsoft Internet Explorer XMLDSO Java Class Lets Remote HTML Code Access Local Files
| [1005071] Microsoft DirectX Files Viewer ActiveX Control Has Buffer Overflow That Allows Remote Users to Execute Arbitrary Code
| [1005070] Microsoft Internet Explorer (IE) Browser Error Message Processing Allows Remote Users to Execute Arbitrary Code on Certain Windows 98 Platforms
| [1005068] Microsoft NTFS Filesystem in Windows NT and Windows 2000 Has Auditing Hole That Lets Local Users Access Files Without the File Access Being Audited
| [1005067] Microsoft Desktop Engine (MSDE) Extended Stored Procedures May Let Local Users Execute Commands With Database Administrator Privileges
| [1005066] Microsoft SQL Server Extended Stored Procedures May Let Local Users Execute Commands With Database Administrator Privileges
| [1005065] Microsoft Network Connection Manager Could Give a Local User System Level Privileges
| [1005063] Microsoft Windows XP Help and Support Center Hole Lets Remote Users Create URLs That, When Loaded, Will Delete Arbitrary Files on Your System
| [1004986] Microsoft Content Management Server Buffer Overflow in Authentication Function May Allow Remote Users to Execute Arbitrary Code With System Level Privileges
| [1004983] Microsoft Visual C++ Flaw in calloc() and Similar Functions May Result in Buffer Overflows in Applications That Use the Compiler or Runtime Library
| [1004965] Microsoft Internet Explorer SSL Implementation Flaw in Following Certificate Chains Allows Remote Users to Conduct Man-in-the-Middle Attacks to Obtain Unencrypted Data from the Browser
| [1004927] Microsoft Terminal Services Can Be Crashed By Remote Users Conducting a TCP SYN Scan in Certain Situations
| [1004917] Microsoft SQL Server MDAC Function Buffer Overflow May Let Remote Users Execute Arbitrary Code to Gain Full Control Over the Database
| [1004877] Microsoft Internet Explorer (IE) Web Browser JavaScript 'Same Origin Policy' Flaw Allows Remote Users to Create Malicious JavaScript to Retrieve Web Data from a Victim's Internal Network
| [1004862] Microsoft Outlook Express Flaw in Parsing XML Using Internet Explorer Allows a Remote User to Silently Deliver and Install an Executable on a Target User's Computer
| [1004831] Microsoft Data Engine (MSDE) Buffer Overflow in Database Consistency Checker May Let Remote Authenticated Users Execute Arbitrary Code with the Privileges of the Database Service
| [1004830] Microsoft SQL Server Buffer Overflow in Database Consistency Checker May Let Remote Authenticated Users Execute Arbitrary Code with the Privileges of the Database Service
| [1004829] Microsoft SQL Server Resolution Service Buffer Overflows Let Remote Users Execute Arbitrary Code with the Privileges of the SQL Service
| [1004828] Microsoft Exchange Server Buffer Overflow in Processing SMTP EHLO Command Lets Remote Users Execute Arbitrary Code on the Server with System Level Privileges
| [1004827] Microsoft Metadirectory Services Authentication Flaw May Let Remote Users Modify Data and Obtain Elevated Privileges on the System
| [1004805] Microsoft Outlook Express (and Possibly Outlook) Has File Attachment Name Bugs That Let Remote Users Send Malicious Mail to Bypass Attachment Type Filters and Modify the Apparent File Name and File Size
| [1004761] Microsoft Foundation Classes (MFC) Information  Server Application Programming Interface (ISAPI) 'mfc42.dll' Contains Buffer Overflows That Can Crash the System or Possibly Allow for the Remote Execution of Arbitrary Code
| [1004746] Microsoft Internet Explorer Flaw in OBJECT Domain Security Enforcement Lets Remote Users Execute Code in Arbitrary Domains
| [1004744] Microsoft SQL Server Install Process May Disclose Sensitive Passwords to Local Users
| [1004739] Microsoft SQL Server Desktop Engine (MSDE) Buffer Overflow and Access Control Bug May Let Remote Authorized Users Execute Code with Elevated Privileges, Possibly Including Local System Privileges
| [1004738] Microsoft SQL Server Buffer Overflow and Access Control Bug May Let Remote Authorized Users Execute Code with Elevated Privileges, Possibly Including Local System Privileges
| [1004637] Microsoft Commerce Server Buffer Overflows and Other Flaws Let Remote Users Execute Arbitrary Code with LocalSystem Privileges
| [1004618] Microsoft Internet Explorer Can Be Crashed By Malicious AVI Object in HTML
| [1004595] Microsoft Word Documents May Execute Remotely Supplied Macro Code Under Certain Conditions
| [1004594] Microsoft Excel Spreadsheet May Execute Remotely Supplied Macro Code Within Malicious Documents
| [1004587] Microsoft SQL Server 2000 Buffer Overflow in OpenDataSource() Function May Let Remote Users Gain SYSTEM Privileges on the Server
| [1004569] Microsoft Visual Studio .NET Korean Language Version Contains Nimda Virus
| [1004544] Microsoft SQL Server Buffer Overflow in 'pwdencrypt()' Function May Let Remote Authorized Users Execute Arbitrary Code
| [1004542] Lumigent Log Explorer Buffer Overflow May Let Remote Users Crash the Microsoft SQL Server Service or Execute Arbitrary Code on the System
| [1004541] Compaq Insight Manager May Include a Vulnerable Default Configuration of Microsoft MSDE/SQL Server That Allows Remote Users to Execute Commands on the System
| [1004529] Microsoft Remote Access Service (RAS) Phonebook Buffer Overflow May Let Local Users Execute Arbitrary Code with Local System Privileges
| [1004528] Microsoft SQLXML Component of Microsoft SQL Server 2000 Contains an Input Validation Flaw in an XML SQL Tag That Allows Cross-Site Scripting Attacks
| [1004527] Microsoft SQLXML Component of Microsoft SQL Server 2000 Contains a Buffer Overflow That Lets Remote Users Take Full Control of the System
| [1004518] Microsoft Proxy Server Buffer Overflow in Processing Gopher Protocol Responses Allows Remote Users to Execute Code on the Server to Gain Full Control of the Server
| [1004517] Microsoft Internet Security and Acceleration Server (ISA) Buffer Overflow in Processing Gopher Protocol Responses Allows Remote Users to Execute Code on the Server to Gain Full Control of the Server
| [1004486] Microsoft ASP.NET Buffer Overflow in Processing Cookies in StateServer Mode May Let Remote Users Crash the Service or Execute Arbitrary Code on the Server
| [1004479] Microsoft Internet Explorer May Execute Remotely Supplied Scripting in the My Computer Zone if FTP Folder Viewing is Enabled
| [1004464] Microsoft Internet Explorer Buffer Overflow in Processing Gopher Protocol Responses Allows Remote Users to Execute Code on the Victim's Computer
| [1004441] Microsoft Windows Help System Buffer Overflows in 'htctrl.ocx' ActiveX Control May Let Remote Users Execute Arbitrary Code on a Target User's Computer By Sending Malicious HTML
| [1004436] Microsoft Internet Explorer Allows HTML-Delivered Compiled Help Files to Be Automatically Executed on the Target User's Computer
| [1004407] Microsoft Exchange 2000 Flaw in Processing a Certain Malformed SMTP Command Allows Remote Users to Deny Service to the Server
| [1004372] Microsoft Excel Spreadsheet XML Stylesheet ActiveX Object Flaw Lets Remote Users Create Malicious Excel Spreadsheets That May Execute Arbitrary Code When Opened With the XML Stylesheet Option
| [1004369] Microsoft Active Directory May Have Bug That Allows Remote Users to Crash the Directory
| [1004361] Microsoft Date Engine (MSDE) Default Configuration Leaves Blank Password for System Administrator Account
| [1004360] Opty-Way Enterprise Glassworks Management Application Installs Microsoft Data Engine Insecurely, Allowing Remote Users to Execute Commands on the System
| [1004357] Microsoft Windows Debugging Facility for Windows NT4 and 2000 Has Authentication Hole That Lets Local Users Execute Arbitrary Code with SYSTEM Privileges
| [1004304] Microsoft Internet Explorer (IE) New Content-Disposition Bugs May Let Remote Users Execute Arbitrary Code on the Victim's Computer
| [1004300] Microsoft Internet Explorer (IE) Zone Spoofing Hole Lets Remote Users Create HTML That, When Loaded, May Run in a Less-Secure IE Security Zone
| [1004290] Microsoft Internet Explorer Bugs in 'BGSOUND' and 'IFRAME' Tags Let Remote Users Create HTML That Will Cause Denial of Service Conditions or Will Access Special DOS Devices
| [1004251] Microsoft Exchange Instant Messenger ActiveX Control Has 'ResDLL' Parameter Buffer Overflow That Lets Remote Users Execute Arbitrary Code
| [1004250] Microsoft MSN Messenger Includes an ActiveX Control That Has 'ResDLL' Parameter Buffer Overflow That Lets Remote Users Execute Arbitrary Code
| [1004249] Microsoft MSN Chat Control ActiveX Control Has 'ResDLL' Parameter Buffer Overflow That Lets Remote Users Execute Arbitrary Code
| [1004236] L.Y.S.I.A.S. Lidik Web Server for Microsoft Windows Systems Lets Remote Users View Files Located Anywhere on the Partition
| [1004229] Microsoft Office 'Word Mail Merge' Feature Allows Remote Users to Cause Arbitrary Programs to Be Executed on the Target User's Computer
| [1004226] Microsoft MSN Messenger Instant Messaging Client Malformed Header Processing Flaw Lets Remote Users Crash the Client
| [1004197] Microsoft Internet Explorer Can Be Crashed By Incorrectly Sized XBM Graphics Files
| [1004157] Microsoft Outlook Weak Security Enforcement When Editing Messages with Microsoft Word Lets Remote Users Send Malicious Code to Outlook Recipients That Will Be Executed When Forwarded or Replied To
| [1004146] Microsoft Internet Explorer Browser Can Be Crashed By Remote HTML Containing Malicious Image Tags That Cause Infinite Processing Loops
| [1004130] Microsoft MSN Messenger Instant Messaging Client Discloses Buddy List to Local Users
| [1004121] Microsoft Internet Explorer Web Browser Can Be Crashed By Remote Users With OLE OBJECT Element Dependency Loops
| [1004109] Microsoft Distributed Transaction Coordinator Can Be Crashed By Remote Users Sending Malformed Packets
| [1004090] Microsoft Back Office Web Administration Authentication Mechanism Can Be Bypassed By Remote Users
| [1004083] Microsoft Windows 2000 'microsoft-ds' Service Flaw Allows Remote Users to Create Denial of Service Conditions By Sending Malformed Packets
| [1004079] Microsoft Internet Explorer (IE) 'dialogArguments' Flaw Lets Remote Users Conduct Cross-Site Scripting Attacks Against IE Users
| [1004051] Microsoft Outlook Express for Mac OS Has Buffer Overflow in Processing the 'file://' URL That Allows Remote Users to Cause Arbitrary Code to Be Executed
| [1004050] Microsoft Office for Mac OS Has Buffer Overflow in Processing the 'file://' URL That Allows Remote Users to Cause Arbitrary Code to Be Executed
| [1004049] Microsoft Internet Explorer for Mac OS Has Buffer Overflow in Processing the 'file://' URL That Allows Remote Users to Cause Arbitrary Code to Be Executed
| [1004048] Microsoft Word Object Creation Flaw Lets Remote Users Create ActiveX That Will Consume Memory on the Victim's Computer
| [1004022] Microsoft Windows 2000 Group Policy Object Enforcement Can Be Circumvented if User License Limits are Exceeded
| [1004014] Microsoft Internet Information Server ASP HTTP Header Processing Buffer Overflow Lets Remote Users Execute Arbitrary Code on the Server
| [1004008] Microsoft Internet Information Server Comes With Code That Allows Remote Users to Conduct Cross-Site Scripting Attacks
| [1004005] Microsoft Internet Information Server Buffer Overflow in Chunked Encoding Mechanism Lets Remote Users Run Arbitrary Code on the Server
| [1004002] Microsoft Office Web Components Let Remote Users Determine if Specified Files Exist on Another User's Host
| [1004001] Microsoft Office Web Components Let Remote Users Gain Full Read and Write Control Over Another User's Clipboard, Even if Clipboard Access Via Scripts is Disabled
| [1004000] Microsoft Office Web Components Let Remote Users Write Code to Run in the Victim's Local Security Domain and Access Local or Remote Files
| [1003999] Microsoft Office Web Components in Office XP Lets Remote Users Cause Malicious Scripting to Be Executed By Another User's Browser Even If Scripting is Disabled
| [1003975] Microsoft Windows NT, 2000, and XP Kernel Buffer Overflow in Processing Multiple UNC Provider (MUP) Requests May Let Local Users Obtain System Level Privileges
| [1003949] Microsoft Windows 2000 DCOM Implementation Flaw May Disclose Memory Contents to Remote Users
| [1003948] Microsoft Internet Explorer Cascading Style Sheets (CSS) Invalid Attribute Bug Lets Remote Users Read Portions of Files on the Victim's Computer
| [1003932] Microsoft Office XP Active Content Bug Lets Remote Users Cause Code to Be Executed on an Office User's Computer
| [1003922] Microsoft Outlook Web Access With SecurID Authentication May Allow Remote Users to Avoid the SecurID Authentication in Certain Cases
| [1003915] Microsoft Internet Explorer Browser Security Zone Flaw Lets Remote Users Cause Cookie-based Scripts to Be Executed on Another User's Browser in the Incorrect Security Domain
| [1003907] Microsoft Internet Explorer Discloses The Existence of and Details of Local Files to Remote Users
| [1003871] Microsoft .NET Unspecified Vulnerabilities May Allow a Remote User to Cause Arbitrary Code to Be Executed on Another User's Systems
| [1003856] Microsoft Internet Explorer Can Be Crashed By Malicious 'location.replace' Javascript
| [1003839] Microsoft Internet Explorer (IE) 6 Lets Remote Users Cause Files to Be Downloaded and Executed Without the Knowledge or Consent of the Victim
| [1003816] Microsoft Windows 2000 Automatic Log Off Policy Fails to Expire Sessions in Progress
| [1003800] A Multitude of Microsoft SQL Server Extended Stored Procedures Have Buffer Overflows That Allow Remote Users to Crash the Database Server or Execute Arbitrary Code on the Server to Gain Full Control of the System
| [1003764] Microsoft Windows Operating System Shell URL Handler Bug Lets Remote Users Create HTML That Could Cause Arbitrary Code to Be Executed on Another User's System in Certain Situations
| [1003756] Microsoft Internet Information Server 4.0 .HTR Web Application Lets Users Change Their Passwords When the NT Security Policy is Configured to Prohibit Password Changing
| [1003744] Microsoft SQL Server 'xp_dirtree' Buffer Overflow Lets Users Crash the Database Service
| [1003730] Microsoft Java Virtual Machine in Internet Explorer Lets Remote Malicious Applets Redirect Web Proxy Connections
| [1003688] Microsoft Exchange Server 2000 Command Processing Bug Lets Remote Users Cause the SMTP Service to Crash
| [1003687] Microsoft Windows 2000 and Windows XP SMTP Service Command Processing Bug Lets Remote Users Cause the SMTP Service to Crash
| [1003686] Microsoft Windows SMTP Service Lets Remote Users Send or Relay Unauthorized Mail (including SPAM) Via the Server
| [1003685] Microsoft Exchange Server Lets Remote Users Send or Relay Unauthorized Mail (including SPAM) Via the Server
| [1003634] Microsoft XML Core Services in SQL Server 2000 Lets Remote Scripts Access and Send Local Files
| [1003633] Microsoft XML Core Services in Microsoft Windows XP Operating System Lets Remote Scripts Access and Send Local Files
| [1003630] Microsoft Internet Explorer Has Another Frame Domain Security Bug That Lets Remote Users View Files or Other Personal Information from a Victim's Computer By Using Malicious VBScripts
| [1003629] Microsoft Commerce Server 2000 AuthFilter Buffer Overflow Lets Remote Users Execute Arbitrary Code on the Server With LocalSystem Privileges to Gain Full Control of the Server
| [1003611] Gator Plugin for Microsoft Internet Explorer Lets Remote Users Install Arbitrary Software on the User's Host
| [1003605] Microsoft SQL Server Buffer Overflow Lets Remote Users Crash the Server and May Allow Remote Code to Be Executed on the Database Server
| [1003597] Microsoft Outlook Web Access Discloses 'Include' Archive Files in the 'lib' Directory to Remote Users
| [1003591] Microsoft Windows Terminal Services May Cause the System's Screen Saver Lockout Mechanism to Fail in Certain Situations
| [1003582] Microsoft Internet Security  Acceleration Server Can Be Affected By Remote Users Conducting a LAND Flood Attack
| [1003556] Microsoft Visual C++ Compiler Buffer Security Mode Does Not Eliminate Buffer Overflows in Compiled Applications
| [1003546] Microsoft Outlook E-mail Client May Display Potentially Malicious File Attachments Illegally Embedded Within Mail Headers
| [1003540] Microsoft Internet Explorer Browser MIME Flaw Causes 'text/plain' Pages to Be Displayed as HTML and Any Embedded Scripting to Be Executed By the Browser
| [1003538] NetWin CWMail Web-Mail Server Buffer Overflow Lets Remote Users Execute Arbitrary Code on the System With the Privileges of the IIS Web Server
| [1003519] Microsoft Internet Explorer (IE) HTML Directive Buffer Overflow Lets Remote Users Cause Arbitrary Code to Be Executed on Another User's Computer
| [1003517] Microsoft Internet Explorer (IE) 'Content-Type' Processing Hole Lets Remote Users Open Applications on Another User's Computer
| [1003516] Microsoft Internet Explorer (IE) Web Browser Has New Frame Domain Verification Bug That Lets Remote Users Obtain Files from Another User's Local File System
| [1003472] Microsoft Telnet Server for Windows 2000 and for Interix Has a Buffer Overflow That May Let Remote Users Execute Code on the Server with System Level Privileges
| [1003469] Microsoft Exchange 2000 Server Allows Remote Users to View and Possibly Modify Registry Settings
| [1003462] Microsoft Internet Explorer Web Browser Allows Cross-site Scripting Attacks Via Non-HTTP Servers
| [1003458] Microsoft Office v. X for Mac OS X Can Be Crashed By Remote Users Sending Malformed Product Identification Packets
| [1003446] Microsoft Internet Information Server Can Be Stopped By Local Users Removing Virtual Directories in a Shared Hosting Environment
| [1003434] Microsoft ASP.NET Web Application Framework Allows Cross Site Scritping Attacks and Discloses Path Information to Remote Users
| [1003420] Microsoft Site Server Commerce Edition Discloses Potentially Sensitive Administration Information and Source Code to Remote Users With Valid Accounts and Discloses User Passwords from the LDAP Directory to Anonymous Remote Users
| [1003419] Microsoft Site Server Commerce Edition Lets Remote Users With Valid NT Accounts Upload and Then Execute ASP Scripts on the Server or Consume Disk Space on the Server
| [1003415] Microsoft Distributed Transaction Coordinator (MSDTC) Service Can Be Crashed By Remote Users
| [1003402] Microsoft Windows NT 4.0 and Windows 2000 Domain Controllers May Give Elevated Privileges to Remote Users Who Are Valid Administrators on Other Trusted Domains
| [1003369] PGPfire Personal Firewall for Microsoft Windows Discloses Identifying Information to Remote Users
| [1003326] Microsoft Internet Explorer for Macintosh OS Executes Remotely Supplied Commands in AppleScripts
| [1003310] Microsoft Windows NT/2000 Authentication Lockout Bug May Record Successful Logins as Failed Login Attempts in Certain Situations
| [1003308] Microsoft Windows XP Manifest Processing Bug Lets Local Users Corrupt the System and Cause the Boot Process to Fail
| [1003257] Microsoft Windows XP Upgrade Effectively Removes Patches from Internet Explorer (IE) During Upgrade, Leaving Users Exposed to IE Vulnerabilities
| [1003239] Python Language Implementation on Microsoft Windows Allows a Remote Server to Access Files on a Web Surfing User's PC
| [1003228] Microsoft Windows Media Player Discloses Unique ID to Remote Users in the Default Configuration, Allowing Web Sites to Track Users
| [1003221] Microsoft Internet Explorer (IE) Default Configuration Allows HTML-based Scripts to Access Your Windows Clipboard Contents
| [1003215] Microsoft Internet Explorer Popup Object Tag Flaw Lets Remote Users Execute Programs on the Browser's Host
| [1003201] Microsoft Windows 95 Backup Utility Has Buffer Overflow That Could Cause Denial of Service Conditions
| [1003135] Microsoft Internet Explorer Can Be Crashed By Remote Users With Javascript That Calls an Endless Loop of Modeless Dialogs
| [1003121] Microsoft Windows XP Task Manager Will Not Kill Certain Processes
| [1003109] Microsoft Internet Explorer (IE) May Allow Malicious Javascript to Poll a User's System for Known Files
| [1003084] Microsoft Internet Explorer GetObject() Active Scripting Bug Lets Remote Code Access Files on the PC
| [1003050] Microsoft Internet Explorer Web Browser Can Be Crashed By Malicious Image Source Tag Javascript Supplied By Remote Users
| [1003049] Microsoft Internet Explorer (IE) Text Form Processing Flaw May Cause IE to Crash
| [1003043] PGP Plug-in For Microsoft Outlook May Fail to Encrypt E-mail in Certain Situations
| [1003042] Microsoft Internet Explorer Web Browser SSL Security Flaw Lets Remote Users Conduct Man-in-the-Middle Attacks to Access Sensitive Information
| [1003041] Microsoft Windows XP Remote Desktop Client May Disclose Recently Used Account Names to Remote Users
| [1003040] Microsoft Excel Password Protection Flaw Lets Local Users Obtain Contents of Password-Protect Cells
| [1003033] Microsoft C Runtime Format String Flaw Lets Remote Users Crash the Microsoft SQL Server Service
| [1003032] Microsoft SQL Server Buffer Overflow Lets Remote Users Execute Arbitrary Code in the Security Context of the SQL Server
| [1003028] Microsoft Windows Universal Plug and Play Component Buffer Overflow Gives Remote Users System Level Access to Windows XP and 98/ME Hosts
| [1003024] Microsoft Internet Explorer (IE) Web Browser 'document.open()' Scripting Flaw Lets Remote Users Steal Cookies, Read Local Files, and Spoof Web Sites
| [1003003] Microsoft Windows XP Hot Key Function Lets Physically Local Users Execute Administrator Hot Key Functions in Certain Situations
| [1002986] Microsoft Internet Explorer Version 6 Lets Remote Scripts Access and Send Local Files
| [1002979] Microsoft Windows Explorer Discloses Stored FTP Passwords to Local Users
| [1002973] Microsoft Internet Explorer (IE 6) Browser May Automatically and Silently Execute Arbitrary Code from a Remote Web Site When the User Views a Web Page or HTML-based E-mail
| [1002957] Microsoft Internet Information Server Can Be Crashed By Remote Users With HTTP Requests Containing Invalid Content-Length Values
| [1002942] Microsoft Internet Explorer May Execute Javascript Contained Within an 'About:' URL in an Unauthorized Security Domain When the URL Contains an Extraneous '%' Character
| [1002926] Microsoft Windows Operating System File Locking Design May Allow Local Users to Block Group Policy Scripts
| [1002922] Microsoft Windows 2000 Internet Key Exchange (IKE) Service Can Be Crashed By Remote Users
| [1002919] Microsoft Internet Explorer Browser Can Be Crashed By Certain Image Tags
| [1002915] Microsoft Outlook Web Access for Exchange May Execute Remotely Supplied Scripts When a Recipient Views a Malicious E-mail Message
| [1002885] Microsoft Internet Explorer Can Be Crashed By Malicious Javascript Causing a Stack Overflow in setTimeout() Function
| [1002823] Microsoft Internet Explorer Fails to Enforce Cookie Prompting Preferences for Local Security Zone
| [1002820] Microsoft Internet Explorer Allows Malicious Web Pages to Spoof Downloadable File Types And Execute Code on the User's Computer When Opened Directly from the Browser
| [1002819] Microsoft Internet Explorer ActiveX Flaw Permits Remote Malicious HTML Code Containing an 'htmlfile' or 'htmlfile_FullWindowEmbed' Object to Access Local Files and Potentially Execute Commands
| [1002802] Microsoft Help and Support Center Software (helpctr.exe) Has Buffer Overflow That May Allow a Remote User to Cause Arbitrary Code to Be Executed on a User's PC
| [1002773] Titan Application Firewall for IIS Web Server Fails to Decode URLs, Letting Remote Users Bypass URL-based Firewall Restrictions
| [1002772] Microsoft Internet Explorer Cookie Disclosure Fix Discloses Patch Information to Remote Users
| [1002754] Terminal Services on Microsoft Windows 2000 and XP Allow Remote Users to Log Bogus IP Addresses Instead of the User's Genuine Address
| [1002731] Microsoft Windows 2000 RunAs Service May Disclose Authentication Credentials to Local Users
| [1002730] Microsoft Windows 2000 RunAs Utility May Disclose Sensitive Information to Local Users
| [1002729] Microsoft Windows 2000 RunAs Service Allows Local Users to Disable the Service
| [1002728] Microsoft SQL Server May Disclose Database Passwords When Creating Data Transformation Service (DTS) Packages
| [1002702] Microsoft Passport May Disclose Wallet Contents, Including Credit Card and Contact Information, to Remote Users
| [1002693] Microsoft Internet Security and Acceleration Server UDP Fragmentation Processing Can Cause 100% of CPU Resources to Be Consumed
| [1002601] Microsoft Windows Me Universal Plug and Play (UPnP) Ssdpsrv.exe Server Component Can Be Crashed by Remote Users
| [1002595] Microsoft Internet Explorer Has Fixed Security Zone for about: URLs and Has Shared Cookie Flaw That Diminishes Cross-Site Scripting Protections
| [1002594] Microsoft Internet Explorer for Mac OS X is Configured to Automatically Execute Downloaded Files
| [1002581] Microsoft Terminal Servers Can Be Crashed By Remote Users Sending Certain Remote Desktop Protocol (RDP) Packets
| [1002560] Internet Explorer Sends Potentially Sensitive Web Browser Contents to Microsoft via the Network When an Error Occurs
| [1002559] Microsoft Office XP Sends Potentially Sensitive Information to Microsoft Via the Network When an Error Occurs
| [1002526] Microsoft Internet Explorer (IE) Web Browser Has Multiple URL-related Flaws That May Allow for Remote Code Execution, Remote HTTP Request Generation, and Application of Incorrect Security Restrictions
| [1002519] TYPSoft FTP Server for Microsoft Windows Can Be Crashed by Remote Users
| [1002487] Microsoft PowerPoint Macro Security Features Can Be Bypassed by Malformed PowerPoint Documents
| [1002486] Microsoft Excel Macro Security Features Can Be Bypassed by Malformed Excel Documents
| [1002456] Microsoft Outlook Web Access Directory Validation Flaw Lets Remote Users Consume CPU Resources by Requesting Mail from Nested Folders
| [1002421] Microsoft Index Server Sample File Discloses File Information to Remote Users
| [1002418] Counterpane's Password Safe Password Encryption Utility for Microsoft Windows May Disclose Passwords to Local Users in Certain Situations
| [1002413] Microsoft Outlook Express Will Execute Active Scripting in Plain Text E-mail Messages, Circumventing Some Scripting Controls
| [1002394] Microsoft Windows NT Remote Procedure Call (RPC) Services Can Be Crashed With Malformed Packets
| [1002385] Norton Anti-Virus For Microsoft Exchange Discloses User Path Information to Remote Users
| [1002356] Microsoft Outlook 2000 Animated Assistant Prevents the Screen Saver from Activating, Allowing Physically Local Users to Access the System
| [1002331] Internet Security Systems RealSecure Intrusion Detection Misses '%u' Encoded Attacks Against Microsoft Web Servers
| [1002330] Cisco Catalyst 6000 Intrusion Detection System Module Fails to Detect '%u' Encoding Obfuscation Attacks Against Microsoft Web Servers
| [1002329] Dragon Sensor Intrusion Detection System Does Not Detect Certain Attacks Against Microsoft Web Servers
| [1002327] Snort Network Intrusion Detection System Will Not Detect '%u' URL Encoding Attacks Against Microsoft Web Servers
| [1002326] Cisco Secure Intrusion Detection System (NetRanger) Fails to Detect Certain Attacks Against Microsoft Web Servers
| [1002317] Microsoft DNS Server Software Susceptible to DNS Cache Poisoning in Default Configuration, Allowing Remote Users to Inject False DNS Records in Certain Situations
| [1002269] Microsoft Outlook Web Access with SSL Can Be Crashed by Remote Users
| [1002206] Microsoft Internet Security and Acceleration (ISA) Server 2000 Can Be Disrupted By Remote Users Due to Memory Leaks and Also Allows Cross-Site Scripting Attacks
| [1002201] Microsoft Windows TCP/IP Stack Vulnerable to a Certain Man-in-the-Middle Denial of Service Attack
| [1002197] Microsoft Windows NNTP Network News Service Has a Memory Leak That Allows Remote Users to Cause the Server to Crash
| [1002124] Microsoft Windows 98 Operating System Can Be Crashed When Running a Web Server or Other Servers And the AUX Device is Accessed By the Program
| [1002106] Microsoft Windows 2000 and Windows NT 4.0 RPC Input Validation Failure Lets Remote Users Destabilize the Operating System
| [1002105] Microsoft SQL Database Server RPC Input Validation Failure Lets Remote Users Crash the Database Service
| [1002104] Microsoft Exchange Server RPC Input Validation Failure Lets Remote Users Crash the Exchange Service
| [1002099] Microsoft Windows 2000 Telnet Service Can Be Crashed By Remote Users
| [1002098] Windows Terminal Services in Microsoft Windows 2000 and NT 4.0 Can Be Crashed By Remote Users Due to a Memory Leak
| [1002075] Microsoft Services for Unix Memory Leak in Telnet and NFS Services Allows Remote Users to Crash the Operating System
| [1002028] Microsoft Exchange LDAP Service Can Be Crashed By Remote Users
| [1001993] Microsoft Windows 2000, Linux 2.4, NetBSD, FreeBSD, and OpenBSD May Let Remote Users Affect TCP Performance
| [1001992] Microsoft Windows NT Lets Remote Users Cause Increased Packet Overhead and Increased CPU Resource Consumption
| [1001984] Microsoft Outlook Allows Rogue HTML to Execute Arbitrary Commands on the User's Host
| [1001931] Microsoft Windows 2000 SMTP Service May Allow Unauthorized Remote Users to Relay E-mail via the Service
| [1001923] Microsoft's Internet Information Server's ASP Processor Can Be Crashed by Remote Users in Certain Situations
| [1001832] Microsoft Windows 2000 LDAP Server Lets Remote Users Gain Administrator Access to the Domain Controller When Configured to Support LDAP over SSL
| [1001819] Microsoft NetMeeting Can Be Crashed By Remote Users
| [1001816] Microsoft Visual Studio RAD Support Component of FrontPage Lets Remote Users Execute Arbitrary Code on the FrontPage Server
| [1001815] Microsoft Word May Execute Macros in Malformed Word Documents Without Warning Even if Macros are Disabled
| [1001775] Microsoft Index Server Lets Remote Users Execute Arbitrary Code With System Level Privileges, Giving Remote Users Full Control of the Operating System
| [1001734] Microsoft SQL Server May Let Remote Authenticated Users Take Full Control of the Database Server and the Underlying Operating System
| [1001701] Microsoft Windows 2000 Telnet Server Allows Local Users to Gain System-Level Privileges and Lets Remote Users Crash the Server
| [1001699] Microsoft Internet Explorer Web Browser May Allow Remote Users to Read Some Text Files on the Browser's Hard Drive
| [1001696] Microsoft Exchange Server's Outlook Web Access (OWA) Lets Remote Users Execute Arbitrary Code on the OWA User's Web Browser
| [1001687] Microsoft Outlook Express May Allow A Remote User to Obtain E-mail Destined for a Different User
| [1001661] Microsoft Hotmail May Allow a Worm to Send Mail to Other Destinations Listed in a Remote User's Inbox
| [1001605] Microsoft Windows 2000 Allows Local Users to Elevate Privileges
| [1001603] Microsoft Windows Media Player May Allow Remote Users to Execute Code Contained in Internet Shortcuts and View Files on the Media Player's Host
| [1001587] Microsoft Word for Windows and for Mac May Run Macros Linked By RTF Documents Without Warning
| [1001572] Apache Web Server on Microsoft Windows Platforms Allows Remote Users to Crash the Web Server
| [1001562] Microsoft Internet Explorer Allows Remote Web Sites to Cause a Different Web URL Address to Be Displayed in the Browser's Address Bar, Allowing Rogue Web Sites to Spoof the Browser and Masquerade as Different Web Sites
| [1001561] Microsoft Internet Explorer Web Browser Fails To Validate Digital Certificates in Some Configurations, Allowing Rogue Secure Web Sites to Spoof the Browser and Masquerade as a Different Secure Web Site
| [1001538] Older Version of Microsoft Internet Explorer Web Browser Can Be Crashed By Remote Users
| [1001537] Microsoft's Internet Information Server's FTP Services May Give Remote Users Information About User Account Names on the Server's Domain and Trusted Domains
| [1001535] Microsoft's Internet Information Server's FTP Services Can Be Crashed By Remote Users
| [1001513] Microsoft Windows 2000 Indexing Service Allows Remote Users to View Include Programming Files
| [1001512] Microsoft Index Server for NT Can Be Crashed By Local Users, Allows Local Users to Execute Arbitrary Code With System Level Privileges, and Lets Remote Users View Certain Include Files
| [1001501] Microsoft Windows 2000 Domain Controllers Can Be Effectively Halted By Remote Users
| [1001467] Microsoft Windows Media Player ASX Processing Vulnerability Lets Remote Users Execute Arbitrary Code on the Player's Host System
| [1001445] Microsoft Internet Security and Acceleration Server May Allow Remote Users to Execute Arbitrary Code on the Firewall
| [1001424] Microsoft Internet Explorer Can Consume All Memory Due to Malicious HTML Code
| [1001380] Microsoft Internet Explorer and Outlook Express May Execute Arbitrary Code Without User Authorization or Intervention
| [1001360] Microsoft Windows Operating System DLL May Allow Malicious Remote Scripts to Run Code on the User's Host Without the User's Intervention
| [1001344] Microsoft Internet Explorer May Not Display File Extensions in Certain Cases
| [1001330] Microsoft ActiveSync Software for Portable Computing Devices Allows Portable Devices to Access Files on a Locked Server
| [1001319] Microsoft Internet Security and Acceleration Server Can Be Crashed By Remote Users
| [1001311] Netscape's SmartDownload Can Automatically Execute Arbitrary Code Without User Intervention or Knowledge for Both Netscape and Microsoft Browsers
| [1001255] Microsoft's Ping.exe Allows Local Users to Cause Certain Applications to Crash
| [1001240] Microsoft FTP Client for Windows 2000 Still Vulnerable to Executing Arbitrary Code in Limited Situations
| [1001221] E-Mail Clients that use Microsoft Internet Explorer to Process HTML May Disguise Executable Attachments as Data Files
| [1001219] Microsoft's Internet Security and Acceleration Server Performance Can Be Significantly Affected By Remote Users Under Certain Configurations
| [1001216] Microsoft Internet Explorer Can Be Made to Execute Arbitrary Files on the User's Computer
| [1001211] TrendMicro's ScanMail E-Mail Virus Scanner for Microsoft Exchange Discloses Administrative System Usernames and Passwords
| [1001210] Microsoft Internet Explorer Allows Malicious Web Pages to Retrieve Files from the User's Computer
| [1001209] Microsoft Telnet Can Be Crashed Locally, Causing Other Applications Including Outlook Express To Crash
| [1001197] Microsoft Internet Explorer May Automatically Execute Certain E-mail Attachments
| [1001187] Microsoft Internet Explorer Is Vulnerable to Malicious Web Pages That May Obtain the User's Exchange E-mail Messages and May Access Restricted Web Server Directory Listings
| [1001186] Microsoft Windows Me Operating System and Windows 98 with the Plus! 98 Package Disclose Data Compression Passwords
| [1001172] Microsoft Visual Studio Could Allow Users to Crash the Debugger or to Execute Code on the Server
| [1001163] Microsoft's Dr. Watson Diagnostic Utility May Reveal Passwords and Other Sensitive Information
| [1001147] Microsoft Outlook Express Crashes When Reading Certain E-mail Messages
| [1001142] Microsoft Internet Explorer Does Not Check for Revoked Digital Certificates (Two Fraudlent Certificates Are Known to Exist)
| [1001139] SurfControl for Microsoft Proxy Server May Fail to Block Sites
| [1001123] Microsoft's FTP Server May Allow Remote Users to Deny Service on the Server
| [1001110] A Microsoft German-Language Hotfix for Windows NT 4 Incorrectly Displays Some Security Events as Other Security Events
| [1001088] Microsoft Internet Explorer with Services for Unix 2.0 Can Create Malicious Files on the User's Host
| 
| OSVDB - http://www.osvdb.org:
| [91195] Microsoft Windows 7 Unspecified ASLR Protection Mechanism Bypass
| [91194] Microsoft Windows 7 Kernel Unspecified Local Privilege Escalation (pwn2own)
| [91193] Microsoft Windows 7 Unspecified ASLR / DEP Protection Mechanism Bypass (pwn2own)
| [85619] Microsoft Windows Phone 7 X.509 Certificate Subject's Common Name (CN) Field Domain Name Validation Multiple Protocol SSL Server MitM Spoofing Weakness
| [67783] Microsoft Windows SDK for Windows 7 / .NET Framework 4 GraphEdit Path Subversion Arbitrary DLL Injection Code Execution
| [87555] Adobe ColdFusion for Microsoft IIS Unspecified DoS
| [87262] Microsoft IIS FTP Command Injection Information Disclosure
| [87261] Microsoft IIS Log File Permission Weakness Local Password Disclosure
| [86899] Microsoft IIS 302 Redirect Message Internal IP Address Remote Disclosure
| [83771] Microsoft IIS Tilde Character Request Parsing File / Folder Name Information Disclosure
| [83454] Microsoft IIS ODBC Tool ctguestb.idc Unauthenticated Remote DSN Initialization
| [83386] Microsoft IIS Non-existent IDC File Request Web Root Path Disclosure
| [82848] Microsoft IIS $INDEX_ALLOCATION Data Stream Request Authentication Bypass
| [76237] Microsoft Forefront Unified Access Gateway IIS NULL Session Cookie Parsing Remote DoS
| [71856] Microsoft IIS Status Header Handling Remote Overflow
| [70167] Microsoft IIS FTP Server Telnet IAC Character Handling Overflow
| [67980] Microsoft IIS Unspecified Remote Directory Authentication Bypass
| [67979] Microsoft IIS FastCGI Request Header Handling Remote Overflow
| [67978] Microsoft IIS Repeated Parameter Request Unspecified Remote DoS
| [66160] Microsoft IIS Basic Authentication NTFS Stream Name Permissions Bypass
| [65216] Microsoft IIS Extended Protection for Authentication Memory Corruption
| [62229] Microsoft IIS Crafted DNS Response Inverse Lookup Log Corruption XSS
| [61432] Microsoft IIS Colon Safe Extension NTFS ADS Filename Syntax Arbitrary Remote File Creation
| [61294] Microsoft IIS ASP Crafted semicolon Extension Security Bypass
| [61249] Microsoft IIS ctss.idc table Parameter SQL Injection
| [59892] Microsoft IIS Malformed Host Header Remote DoS
| [59621] Microsoft IIS CodeBrws.asp Off-By-One File Check Bypass Source Disclosure
| [59561] Microsoft IIS CodeBrws.asp Encoded Traversal Arbitrary File Source Disclosure
| [59360] Microsoft IIS ASP Page Visual Basic Script Malformed Regex Parsing DoS
| [57753] Microsoft IIS FTP Server Crafted Recursive Listing Remote DoS
| [57589] Microsoft IIS FTP Server NLST Command Remote Overflow
| [56474] Microsoft IIS WebDAV Extension URL Decode Crafted HTTP Request Authentication Bypass
| [55269] Microsoft IIS Traversal GET Request Remote DoS
| [54555] Microsoft IIS WebDAV Unicode URI Request Authentication Bypass
| [52924] Microsoft IIS WebDAV PROPFIND Method Forced Directory Listing
| [52680] Microsoft IIS httpext.dll WebDav LOCK Method Nonexistent File Request Parsing Memory Exhaustion Remote DoS
| [52238] Microsoft IIS IDC Extension XSS
| [49899] Microsoft IIS iissext.dll Unspecified ActiveX SetPassword Method Remote Password Manipulation
| [49730] Microsoft IIS ActiveX (adsiis.dll) GetObject Method Remote DoS
| [49059] Microsoft IIS IPP Service Unspecified Remote Overflow
| [45583] Microsoft IIS w/ Visual Interdev Unspecified Authentication Bypass
| [43451] Microsoft IIS HTTP Request Smuggling
| [41456] Microsoft IIS File Change Handling Local Privilege Escalation
| [41445] Microsoft IIS ASP Web Page Input Unspecified Arbitrary Code Execution
| [41091] Microsoft IIS webhits.dll Hit-Highlighting Authentication Bypass
| [41063] Microsoft IIS ODBC Tool newdsn.exe Remote DSN Creation
| [41057] Microsoft IIS w/ .NET MS-DOS Device Request Blacklist Bypass
| [35950] Microsoft IIS IUSR_Machine Account Arbitrary Non-EXE Command Execution
| [33457] Microsoft IIS Crafted TCP Connection Range Header DoS
| [28260] Microsoft IIS FrontPage Server Extensions (FPSE) shtml.exe Path Disclosure
| [27152] Microsoft Windows IIS ASP Page Processing Overflow
| [27087] Microsoft IIS SMTP Encapsulated SMTP Address Open Relay
| [23590] Microsoft IIS Traversal Arbitrary FPSE File Access
| [21805] Microsoft IIS Crafted URL Remote DoS
| [21537] Microsoft IIS Log File Permission Weakness Remote Modification
| [18926] Microsoft IIS SERVER_NAME Variable Spoofing Filter Bypass
| [17124] Microsoft IIS Malformed WebDAV Request DoS
| [17123] Microsoft IIS Multiple Unspecified Admin Pages XSS
| [17122] Microsoft IIS Permission Weakness .COM File Upload
| [15749] Microsoft IIS / Site Server code.asp Arbitrary File Access
| [15342] Microsoft IIS Persistent FTP Banner Information Disclosure
| [14229] Microsoft IIS asp.dll Scripting.FileSystemObject Malformed Program DoS
| [13985] Microsoft IIS Malformed HTTP Request Log Entry Spoofing
| [13760] Microsoft IIS Malformed URL Request DoS
| [13759] Microsoft IIS ISAPI .ASP Parser Script Tag LANGUAGE Argument Overflow
| [13634] Microsoft IIS Inetinfo.exe Malformed Long Mail File Name DoS
| [13558] Microsoft IIS SSL Request Resource Exhaustion DoS
| [13507] Microsoft IIS showfile.asp FileSystemObject Arbitrary File Access
| [13479] Microsoft IIS for Far East Parsed Page Source Disclosure
| [13473] Microsoft IIS on FAT Partition Local ASP Source Disclosure
| [13439] Microsoft IIS HTTP Request Malformed Content-Length Parsing Remote DoS
| [13433] Microsoft IIS WebDAV MKCOL Method Location Server Header Internal IP Disclosure
| [13432] Microsoft IIS WebDAV WRITE Location Server Header Internal IP Disclosure
| [13431] Microsoft IIS WebDAV Malformed PROPFIND Request Internal IP Disclosure
| [13430] Microsoft IIS aexp4.htr Password Policy Bypass
| [13429] Microsoft IIS aexp3.htr Password Policy Bypass
| [13428] Microsoft IIS aexp2b.htr Password Policy Bypass
| [13427] Microsoft IIS aexp2.htr Password Policy Bypass
| [13426] Microsoft IIS NTLM Authentication Request Parsing Remote Information Disclosure
| [13385] Microsoft IIS WebDAV Long PROPFIND/SEARCH Request DoS
| [11455] Microsoft IIS / PWS DOS Filename Request Access Bypass
| [11452] Microsoft IIS Double Byte Code Arbitrary Source Disclosure
| [11277] Microsoft IIS SSL ISAPI Filter Cleartext Information Disclosure
| [11257] Microsoft IIS Malformed GET Request DoS
| [11157] Microsoft IIS FTP Service PASV Connection Saturation DoS
| [11101] Microsoft IIS Multiple Slash ASP Page Request DoS
| [9315] Microsoft IIS getdrvs.exe ODBC Sample Information Disclosure
| [9314] Microsoft IIS mkilog.exe ODBC Sample Arbitrary Command Execution
| [9200] Microsoft IIS Unspecified XSS Variant
| [9199] Microsoft IIS shtml.dll XSS
| [8098] Microsoft IIS Virtual Directory ASP Source Disclosure
| [7807] Microsoft IIS ISAPI Virtual Directory UNC Mapping ASP Source Disclosure
| [7737] Microsoft IIS ASP Redirection Function XSS
| [7265] Microsoft IIS .ASP Session ID Disclosure and Hijacking
| [5851] Microsoft IIS Single Dot Source Code Disclosure
| [5736] Microsoft IIS Relative Path System Privilege Escalation
| [5693] Microsoft MS00-060 Patch IIS Malformed Request DoS
| [5633] Microsoft IIS Invalid WebDAV Request DoS
| [5606] Microsoft IIS WebDAV PROPFIND Request DoS
| [5584] Microsoft IIS URL Redirection Malformed Length DoS
| [5566] Microsoft IIS Form_VBScript.asp XSS
| [5316] Microsoft IIS ISAPI HTR Chunked Encoding Overflow
| [4864] Microsoft IIS TRACK Logging Failure
| [4863] Microsoft IIS Active Server Page Header DoS
| [4791] Microsoft IIS Response Object DoS
| [4655] Microsoft IIS ssinc.dll Long Filename Overflow
| [4535] Microsoft Media Services ISAPI nsiislog.dll POST Overflow
| [3512] Microsoft IIS ODBC Tool getdrvrs.exe Remote DSN Creation
| [3500] Microsoft IIS fpcount.exe Remote Overflow
| [3341] Microsoft IIS Redirect Response XSS
| [3339] Microsoft IIS HTTP Error Page XSS
| [3338] Microsoft IIS Help File XSS
| [3328] Microsoft IIS FTP Status Request DoS
| [3326] Microsoft IIS w3svc.dll ISAPI Filter URL Handling Remote DoS
| [3325] Microsoft IIS HTR ISAPI Overflow
| [3323] Microsoft IIS ISAPI .printer Extension Host Header Overflow
| [3320] Microsoft IIS ASP Server-Side Include Buffer Overflow
| [3316] Microsoft IIS HTTP Header Field Delimiter Overflow
| [3301] Microsoft IIS ASP Chunked Encoding Variant Heap Overflow
| [3284] Microsoft IIS Winmsdp.exe Arbitrary File Retrieval
| [3231] Microsoft IIS Log Bypass
| [2106] Microsoft Media Services ISAPI nsiislog.dll Overflow
| [1931] Microsoft IIS MIME Content-Type Header DoS
| [1930] Microsoft IIS SSI ssinc.dll Filename Handling Overflow
| [1826] Microsoft IIS Domain Guest Account Disclosure
| [1824] Microsoft IIS FTP DoS
| [1804] Microsoft IIS Long Request Parsing Remote DoS
| [1770] Microsoft IIS WebDAV Malformed PROPFIND Request Remote DoS
| [1750] Microsoft IIS File Fragment Disclosure
| [1543] Microsoft NT/IIS Invalid URL Request DoS
| [1504] Microsoft IIS File Permission Canonicalization Bypass
| [1465] Microsoft IIS .htr Missing Variable DoS
| [1325] Microsoft IIS Malformed Filename Request File Fragment Disclosure
| [1322] Microsoft IIS Malformed .htr Request DoS
| [1281] Microsoft IIS Escaped Character Saturation Remote DoS
| [1261] Microsoft IIS Chunked Transfer Encoding Remote Overflow DoS
| [1210] Microsoft IIS WebHits.dll ISAPI Filter Traversal Arbitrary File Access
| [1170] Microsoft IIS Escape Character URL Access Bypass
| [1083] Microsoft IIS FTP NO ACCESS Read/Delete File
| [1082] Microsoft IIS Domain Resolution Access Bypass
| [1041] Microsoft IIS Malformed HTTP Request Header DoS
| [1020] Microsoft IIS ISAPI GetExtensionVersion() Privilege Escalation
| [930] Microsoft IIS Shared ASP Cache Information Disclosure
| [929] Microsoft IIS FTP Server NLST Command Overflow
| [928] Microsoft IIS Long Request Log Evasion
| [815] Microsoft IIS ASP.NET trace.axd Application Tracing Information Disclosure
| [814] Microsoft IIS global.asa Remote Information Disclosure
| [782] Microsoft IIS / Site Server codebrws.asp Arbitrary File Access
| [771] Microsoft IIS Hosting Process (dllhost.exe) Out of Process Application Unspecified Privilege Escalation
| [768] Microsoft IIS ASP Chunked Encoding Heap Overflow
| [636] Microsoft IIS sqlqhit.asp Sample Script CiScope Parameter Information Disclosure
| [630] Microsoft IIS Multiple Malformed Header Field Internal IP Address Disclosure
| [568] Microsoft IIS idq.dll IDA/IDQ ISAPI Remote Overflow
| [564] Microsoft IIS ISM.dll Fragmented Source Disclosure
| [556] Microsoft IIS/PWS Encoded Filename Arbitrary Command Execution
| [525] Microsoft IIS Webserver Invalid Filename Request Arbitrary Command Execution
| [482] Microsoft IIS FrontPage Server Extensions (FPSE) Malformed Form DoS
| [475] Microsoft IIS bdir.htr Arbitrary Directory Listing
| [474] Microsoft IIS / Site Server viewcode.asp Arbitrary File Access
| [473] Microsoft IIS Multiple .cnf File Information Disclosure
| [471] Microsoft IIS ServerVariables_Jscript.asp Path Disclosure
| [470] Microsoft IIS Form_JScript.asp XSS
| [463] Microsoft IIS Phone Book Service /pbserver/pbserver.dll Remote Overflow
| [436] Microsoft IIS Unicode Remote Command Execution
| [425] Microsoft IIS WebDAV SEARCH Method Arbitrary Directory Forced Listing
| [391] Microsoft IIS IDA/IDQ Document Root Path Disclosure
| [390] Microsoft IIS Translate f: Request ASP Source Disclosure
| [308] Microsoft IIS Malformed File Extension URL DoS
| [285] Microsoft IIS repost.asp File Upload
| [284] Microsoft IIS IISADMPWD Virtual Directory Information Enumeration
| [283] Microsoft IIS /iissamples Multiple Sample Scripts Installed
| [277] Microsoft IIS / PWS %2e Request ASP Source Disclosure
| [276] Microsoft IIS ASP::$DATA Stream Request ASP Source Disclosure
| [275] Microsoft IIS newdsn.exe Remote Arbitrary File Creation
| [274] Microsoft IIS ctss.idc ODBC Sample Arbitrary Command Execution
| [273] Microsoft IIS Upgrade ism.dll Local Privilege Escalation
| [272] Microsoft IIS MDAC RDS Arbitrary Remote Command Execution
| [271] Microsoft IIS WebHits null.htw .asp Source Disclosure
| [98] Microsoft IIS perl.exe HTTP Path Disclosure
| [97] Microsoft IIS ISM.DLL HTR Request Overflow
| [96] Microsoft IIS idq.dll Traversal Arbitrary File Access
| [7] Microsoft IIS / Site Server showcode.asp source Parameter Traversal Arbitrary File Access
| [4] Microsoft IIS ExAir advsearch.asp Direct Request Remote DoS
| [3] Microsoft IIS ExAir query.asp Direct Request Remote DoS
| [2] Microsoft IIS ExAir search.asp Direct Request DoS
|_
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  1 13:20:55 2020 -- 1 IP address (1 host up) scanned in 14.60 seconds
````

Como podemos ver trouxe bastante coisa no results

Primeiro vou focar no result do VulnDB

```
| vulscan: VulDB - https://vuldb.com:
| [68404] Microsoft IIS 7.5 Error Message mypage cross site scripting
| [6924] Microsoft IIS 7.5 Log File Permission information disclosure
| [5623] Microsoft IIS up to 7.5 File Name Tilde privilege escalation
| [4234] Microsoft IIS 7.5 FTP Server Telnet IAC Character Heap-based denial of service
| [4179] Microsoft IIS 7.5 FastCGI Request Header memory corruption
| [98097] Microsoft IIS 7.0/7.5/8.0/8.5/10 /uncpath/ cross site scripting
| [6925] Microsoft IIS 7.0/7.5 FTP Command information disclosure
| [4484] Microsoft Windows Phone 7.5 SMS Service denial of service
```

De acordo com a descricao, essas abaixo sao mais interessantes

```
| [6924] Microsoft IIS 7.5 Log File Permission information disclosure
| [5623] Microsoft IIS up to 7.5 File Name Tilde privilege escalation
```

Entao comecei a pesquisar sobre essas duas vulns 

Testei e nada de funcionar, nao era vuln.

Vamos voltar ao gobuster e tentar novamente...

Entao depois de um tempo algo interessante aparece

`gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -x txt,html,php,asp,aspx,jsp -t 30 -u http://10.10.10.93`

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/3.jpg)

```
/aspnet_client (Status: 301)
[ERROR] 2020/07/01 17:12:34 [!] Get http://10.10.10.93/gfx4_v4gfxed.asp: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2020/07/01 17:13:16 [!] net/http: request canceled (Client.Timeout exceeded while reading body)
/transfer.aspx (Status: 200)
/uploadedfiles (Status: 301)
```

Vamos, tentar fazer upload de uma shell

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/4.jpg)

Ja fui logo tentando uma webshell em .aspx mas nao passou , precisamos fazer bypass

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/5.jpg)

NOSSA! ENTREI EM UMA TOCA DO COELHO quase que nao saia.....

Varios metodos de bypass e nada dava certo, eu consegui bypassar mas nao carregava o payload conforme o esperado...

depois de muito tempo, enviando arquivos e modificando a request o server gerou um error que me tirou do buracoo

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/6.jpg)

REQUEST:

```
POST /transfer.aspx HTTP/1.1
Host: 10.10.10.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.93/transfer.aspx
Content-Type: multipart/form-data; boundary=---------------------------1913420059401053279383526251
Content-Length: 828
Connection: close
Upgrade-Insecure-Requests: 1


-----------------------------1913420059401053279383526251
Content-Disposition: form-data; name="__VIEWSTATE"


/wEPDwUKMTI3ODM5MzQ0Mg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YRYCAgUPDxYGHgRUZXh0BR5JbnZhbGlkIEZpbGUuIFBsZWFzZSB0cnkgYWdhaW4eCUZvcmVDb2xvcgqNAR4EXyFTQgIEZGRkq0GqB5cFI7nIrPt0yWe2NZHfR4E=
-----------------------------1913420059401053279383526251
Content-Disposition: form-data; name="__EVENTVALIDATION"


/wEWAgKRguSEBwLt3oXMA+Z7jSeG5nKMage1rlOMIbTwvX2Q
-----------------------------1913420059401053279383526251
Content-Disposition: form-data; name="FileUpload1"; filename=""
Content-Type: application/octet-stream




-----------------------------1913420059401053279383526251
Content-Disposition: form-data; name="btnUpload"


Upload
-----------------------------1913420059401053279383526251--
```

Fui entao pesquisar mais sobre ele e sua relacao com o IIS 7.5 

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/7.jpg)

Comecei entao a explorar e rapidamente ja tinha uma webshell






