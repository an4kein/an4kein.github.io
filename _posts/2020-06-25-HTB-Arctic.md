---
title:     "Hack The Box - Arctic"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/1.jpg)

## Enumeration

Iniciamos com nosso nmap 

```
root@kali:~/HTB-Windows/arctic# nmap -Pn -p- -T4 -oN nmap/allports_tcp 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 18:27 EDT
Stats: 0:02:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 55.64% done; ETC: 18:32 (0:02:06 remaining)
Nmap scan report for 10.10.10.11
Host is up (0.21s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 299.41 seconds
```

3 portas abertas, vamos continuar com a enumeracao

