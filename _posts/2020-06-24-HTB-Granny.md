---
title:     "Hack The Box -Granny"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/1.jpg)

## Enumeration

Iniciamos nossa maquina usando o nmap para enumeracao inicial

```
root@kali:~/HTB-Windows/granny# nmap -Pn -p- -oN nmap/allports_tcp 10.10.10.15
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:39 EDT
Stats: 0:07:25 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.87% done; ETC: 13:47 (0:00:01 remaining)
Nmap scan report for 10.10.10.15
Host is up (0.20s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 446.75 seconds
```

wowww apenas uma porta aberta ,,,,, 


```
root@kali:~/HTB-Windows/granny# nmap -sC -sV -p80 -oN nmap/scripts_default 10.10.10.15
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:49 EDT
Nmap scan report for 10.10.10.15
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Wed, 24 Jun 2020 17:52:36 GMT
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.30 seconds
```

A versao do webserver **(Microsoft IIS httpd 6.0)** eh bem antiga, alem disso no webdav temos diversos metodos habilitados **(|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK)**

Vamos continuar nossa enumeracao... Existe projeto bem interessante que desenvolveu um script bem interessante para buscar vulns usando o proprio nmap

**reference** https://medium.com/@alexander.tyutin/continuous-vulnerability-scanning-with-nmap-ea8821d587b0


```
root@kali:~/HTB-Windows/granny# git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
Cloning into '/usr/share/nmap/scripts/vulners'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 68 (delta 1), reused 0 (delta 0), pack-reused 62
Unpacking objects: 100% (68/68), 427.88 KiB | 550.00 KiB/s, done.
root@kali:~/HTB-Windows/granny# nmap --script-updatedb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:56 EDT
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.67 seconds
```

Usando e verificando os resultados obtidos

```
root@kali:~/HTB-Windows/granny# nmap -sV -Pn 10.10.10.15 --script=vulners/vulners.nse -p 80
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 14:01 EDT
Nmap scan report for 10.10.10.15
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| vulners: 
|   cpe:/a:microsoft:iis:6.0: 
|_      IIS_PHP_AUTH_BYPASS.NASL        7.5     https://vulners.com/nessus/IIS_PHP_AUTH_BYPASS.NASL
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.96 seconds
```

Bom, eu particulamente nao achei muito eficiente pra essa maquina.. Mas isso eh normal acontecer.. O recomendado eh voce testar nao so os scripts conhecidos mais outros tambem....

Continuando...


