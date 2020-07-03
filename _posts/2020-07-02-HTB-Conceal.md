---
title:     "Hack The Box - Conceal"
tags: [windows,hard]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/1.jpg)

## Enumeration

Vamos comecar

```
root@kali:~/HTB-Windows/conceal# nmap -PS --top-ports 20  -oN nmap/init 10.10.10.116 -Pn                                                                  [113/264]
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-02 21:11 EDT                      
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan      
SYN Stealth Scan Timing: About 99.99% done; ETC: 21:11 (0:00:00 remaining)                                                                                                 
Nmap scan report for 10.10.10.116                                                    
Host is up.                                                                          
                                                                                                                                                                           
PORT     STATE    SERVICE                                                            
21/tcp   filtered ftp                                                                
22/tcp   filtered ssh                                                                                                                                                      
23/tcp   filtered telnet                                                             
25/tcp   filtered smtp                                                               
53/tcp   filtered domain                                                                                                                                                   
80/tcp   filtered http                                                               
110/tcp  filtered pop3                                                               
111/tcp  filtered rpcbind                                                            
135/tcp  filtered msrpc                                                              
139/tcp  filtered netbios-ssn                                                        
143/tcp  filtered imap                                                               
443/tcp  filtered https                                                              
445/tcp  filtered microsoft-ds                                                       
993/tcp  filtered imaps                                                              
995/tcp  filtered pop3s                                                              
1723/tcp filtered pptp                                                               
3306/tcp filtered mysql                                                              
3389/tcp filtered ms-wbt-server
5900/tcp filtered vnc
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 5.30 seconds
```

Realizei outros scan no entanto nada encontrado nas  portas `TCP`nao vou colocar todos os results para nao sujar muito

Realizar um scan nas portas UDP agora...

```
root@kali:~/HTB-Windows/conceal# nmap -sU --top-ports 20  -oN nmap/udp_ports 10.10.10.116 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-02 21:12 EDT
Nmap scan report for 10.10.10.116
Host is up (0.23s latency).

PORT      STATE         SERVICE
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
500/udp   open          isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 15.00 seconds
```

Encontrado a porta  `500 isakmp` vamos enumerar isso..

```
root@kali:~/HTB-Windows/conceal# nmap -sU -sC -A -p500 -oN nmap/port500_udp 10.10.10.116
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-02 21:32 EDT
Nmap scan report for 10.10.10.116
Host is up (0.21s latency).

PORT    STATE SERVICE VERSION
500/udp open  isakmp?
|_ike-version: ERROR: Script execution failed (use -d to debug)
Too many fingerprints match this host to give specific OS details
Network Distance: 8 hops

TRACEROUTE (using port 500/udp)
HOP RTT       ADDRESS
1   223.44 ms 10.10.14.1
2   ... 7
8   208.37 ms 10.10.10.116

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.15 seconds
```

preciso pesquisar mais como funciona isso...

pesquisando no google como enumerar encontrei algumas coisas interessantes...

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/2.jpg)
