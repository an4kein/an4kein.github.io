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

Estou usando isso como referencia


https://etutorials.org/Networking/network+security+assessment/Chapter+11.+Assessing+IP+VPN+Services/11.2+Attacking+IPsec+VPNs/

https://github.com/SpiderLabs/ikeforce

usando o ike-scan default no kali obtenho algumas informacoes

```
root@kali:~/HTB-Windows/conceal# ike-scan 10.10.10.116
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116    Main Mode Handshake returned HDR=(CKY-R=d50cedb591589c4a) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080) VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8) VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T) VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n) VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation) VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable) VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.213 seconds (4.68 hosts/sec).  1 returned handshake; 0 returned notify
```

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/3.jpg)

verificando o resultado obtido, temos `(Windows-8)` temos tambem algumas hashes, verificando com o `hash-identify` vejo que trata-se de `MD5` vou copiar todas elas em um arquivo e usar algum decrypt online e ver se consigo quebrar.

```
4a131c81070358455c5728f20e95452f
90cb80913ebb696e086381b5ec427b1f
4048b7d56ebce88525e7de7f00d6c2d3
fb1de3cdf341b7ea16b7e5be0855f120
e3a5966a76379fe707228231e5ce8652
```
https://crackstation.net/
![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/4.jpg)

`4048b7d56ebce88525e7de7f00d6c2d3:FRAGMENTATION`

Dando continuidade na enumeracao do IKE encontrei um outro site good 

https://book.hacktricks.xyz/pentesting/ipsec-ike-vpn-pentesting

```
root@kali:~/HTB-Windows/conceal# ike-scan -M 10.10.10.116 
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116    Main Mode Handshake returned
        HDR=(CKY-R=3e7e59cd10722ca3)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.204 seconds (4.91 hosts/sec).  1 returned handshake; 0 returned notify
```

agora vamos fazer um brute force, para encontrar uma transformacao valida... ja sabemos que o tipo de auth eh PSK e exige uma config de VPN..

```
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt ;done ;done ;done ;done
```
depois de criada a lista com o comando acima com as possiveis transformacoes, vamos proceguir com o bruteforce, isso pode demorar bastante, entao voi tomar um cafe ..

```
while read line; do (echo "Valid trans found: $line" && sudo ike-scan -M $line 10.10.10.116) | grep -B14 "1 returned handshake" | grep "Valid trans found" ; done < ike-dict.txt
```

Ate o momento so foi encontrada uma

`Valid trans found: --trans=5,2,1,2`

Finalmente concluido

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/5.jpg)

```
root@kali:~/HTB-Windows/conceal# while read line; do (echo "Valid trans found: $line" && ike-scan -M $line 10.10.10.116) | grep -B14 "1 returned handshake" | grep "Valid t
rans found" ; done < ike-dict.txt
^AValid trans found: --trans=5,2,1,2
Valid trans found: --trans=7/128,2,1,2
```

De volta a maquina, haha

Bom, vamos fazer uma enumeracao decente certo? a maquina eh HARD e com os procedimentos realizados anteriormente nao fui muito longe, pois deve esta faltando algo...

enumerar, enumerar e enumerar...

Conforme falei anteriormente, maquinas assim exisge um recon pesado.. Alem disso, enumeracao eh a chave, uma boa enumeracao sempre vai levar voce pro lugar certo..

Eu utilizei uma dessas tools de recon de forma automatica, existe varias

https://github.com/RoliSoft/ReconScan

https://github.com/codingo/Reconnoitre

https://github.com/welchbj/bscan

https://github.com/Tib3rius/AutoRecon

Entre outras...

Depois de enumerar, encontrei mais uma porta UDP open `161` e trouxe bastante informacao


snmpwalk port 161

```
Created directory: /var/lib/snmp/mib_indexes
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (74043) 0:12:20.43
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3
iso.3.6.1.2.1.2.2.1.1.4 = INTEGER: 4
iso.3.6.1.2.1.2.2.1.1.5 = INTEGER: 5
iso.3.6.1.2.1.2.2.1.1.6 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.1.7 = INTEGER: 7
iso.3.6.1.2.1.2.2.1.1.8 = INTEGER: 8
iso.3.6.1.2.1.2.2.1.1.9 = INTEGER: 9
iso.3.6.1.2.1.2.2.1.1.10 = INTEGER: 10
iso.3.6.1.2.1.2.2.1.1.11 = INTEGER: 11
iso.3.6.1.2.1.2.2.1.1.12 = INTEGER: 12
iso.3.6.1.2.1.2.2.1.1.13 = INTEGER: 13
iso.3.6.1.2.1.2.2.1.1.14 = INTEGER: 14
iso.3.6.1.2.1.2.2.1.1.15 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.2.1 = Hex-STRING: 53 6F 66 74 77 61 72 65 20 4C 6F 6F 70 62 61 63 
6B 20 49 6E 74 65 72 66 61 63 65 20 31 00 
iso.3.6.1.2.1.2.2.1.2.2 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 49 4B 
45 76 32 29 00 
iso.3.6.1.2.1.2.2.1.2.3 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 50 50 
54 50 29 00 
iso.3.6.1.2.1.2.2.1.2.4 = Hex-STRING: 4D 69 63 72 6F 73 6F 66 74 20 4B 65 72 6E 65 6C 
20 44 65 62 75 67 20 4E 65 74 77 6F 72 6B 20 41 
64 61 70 74 65 72 00 
iso.3.6.1.2.1.2.2.1.2.5 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 4C 32 
54 50 29 00 
iso.3.6.1.2.1.2.2.1.2.6 = Hex-STRING: 54 65 72 65 64 6F 20 54 75 6E 6E 65 6C 69 6E 67 
20 50 73 65 75 64 6F 2D 49 6E 74 65 72 66 61 63 
65 00 
iso.3.6.1.2.1.2.2.1.2.7 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 49 50 
29 00 
iso.3.6.1.2.1.2.2.1.2.8 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 53 53 
54 50 29 00 
iso.3.6.1.2.1.2.2.1.2.9 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 49 50 
76 36 29 00 
iso.3.6.1.2.1.2.2.1.2.10 = Hex-STRING: 49 6E 74 65 6C 28 52 29 20 38 32 35 37 34 4C 20 
47 69 67 61 62 69 74 20 4E 65 74 77 6F 72 6B 20 
43 6F 6E 6E 65 63 74 69 6F 6E 00 
iso.3.6.1.2.1.2.2.1.2.11 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 50 50 
50 4F 45 29 00 
iso.3.6.1.2.1.2.2.1.2.12 = Hex-STRING: 57 41 4E 20 4D 69 6E 69 70 6F 72 74 20 28 4E 65 
74 77 6F 72 6B 20 4D 6F 6E 69 74 6F 72 29 00 
iso.3.6.1.2.1.2.2.1.2.13 = Hex-STRING: 49 6E 74 65 6C 28 52 29 20 38 32 35 37 34 4C 20 
47 69 67 61 62 69 74 20 4E 65 74 77 6F 72 6B 20 
43 6F 6E 6E 65 63 74 69 6F 6E 2D 57 46 50 20 4E 
61 74 69 76 65 20 4D 41 43 20 4C 61 79 65 72 20 
4C 69 67 68 74 57 65 69 67 68 74 20 46 69 6C 74 
65 72 2D 30 30 30 30 00 
iso.3.6.1.2.1.2.2.1.2.14 = Hex-STRING: 49 6E 74 65 6C 28 52 29 20 38 32 35 37 34 4C 20 
47 69 67 61 62 69 74 20 4E 65 74 77 6F 72 6B 20 
43 6F 6E 6E 65 63 74 69 6F 6E 2D 51 6F 53 20 50 
61 63 6B 65 74 20 53 63 68 65 64 75 6C 65 72 2D 
30 30 30 30 00 
iso.3.6.1.2.1.2.2.1.2.15 = Hex-STRING: 49 6E 74 65 6C 28 52 29 20 38 32 35 37 34 4C 20 
47 69 67 61 62 69 74 20 4E 65 74 77 6F 72 6B 20 
43 6F 6E 6E 65 63 74 69 6F 6E 2D 57 46 50 20 38 
30 32 2E 33 20 4D 41 43 20 4C 61 79 65 72 20 4C 
69 67 68 74 57 65 69 67 68 74 20 46 69 6C 74 65 
72 2D 30 30 30 30 00 
iso.3.6.1.2.1.2.2.1.3.1 = INTEGER: 24
iso.3.6.1.2.1.2.2.1.3.2 = INTEGER: 131
iso.3.6.1.2.1.2.2.1.3.3 = INTEGER: 131
iso.3.6.1.2.1.2.2.1.3.4 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.5 = INTEGER: 131
iso.3.6.1.2.1.2.2.1.3.6 = INTEGER: 131
iso.3.6.1.2.1.2.2.1.3.7 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.8 = INTEGER: 131
iso.3.6.1.2.1.2.2.1.3.9 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.10 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.11 = INTEGER: 23
iso.3.6.1.2.1.2.2.1.3.12 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.13 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.14 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.3.15 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.4.1 = INTEGER: 1500
iso.3.6.1.2.1.2.2.1.4.2 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.3 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.4 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.5 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.6 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.7 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.8 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.9 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.10 = INTEGER: 1500
iso.3.6.1.2.1.2.2.1.4.11 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.12 = INTEGER: 0
iso.3.6.1.2.1.2.2.1.4.13 = INTEGER: 1500
iso.3.6.1.2.1.2.2.1.4.14 = INTEGER: 1500
iso.3.6.1.2.1.2.2.1.4.15 = INTEGER: 1500
iso.3.6.1.2.1.2.2.1.5.1 = Gauge32: 1073741824
iso.3.6.1.2.1.2.2.1.5.2 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.3 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.4 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.5 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.6 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.7 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.8 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.9 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.10 = Gauge32: 1000000000
iso.3.6.1.2.1.2.2.1.5.11 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.12 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.5.13 = Gauge32: 1000000000
iso.3.6.1.2.1.2.2.1.5.14 = Gauge32: 1000000000
iso.3.6.1.2.1.2.2.1.5.15 = Gauge32: 1000000000
iso.3.6.1.2.1.2.2.1.6.1 = ""
iso.3.6.1.2.1.2.2.1.6.2 = ""
iso.3.6.1.2.1.2.2.1.6.3 = ""
iso.3.6.1.2.1.2.2.1.6.4 = ""
iso.3.6.1.2.1.2.2.1.6.5 = ""
iso.3.6.1.2.1.2.2.1.6.6 = Hex-STRING: 00 00 00 00 00 00 00 E0 
iso.3.6.1.2.1.2.2.1.6.7 = ""
iso.3.6.1.2.1.2.2.1.6.8 = ""
iso.3.6.1.2.1.2.2.1.6.9 = ""
iso.3.6.1.2.1.2.2.1.6.10 = Hex-STRING: 00 50 56 B9 03 7B 
iso.3.6.1.2.1.2.2.1.6.11 = ""
iso.3.6.1.2.1.2.2.1.6.12 = ""
iso.3.6.1.2.1.2.2.1.6.13 = Hex-STRING: 00 50 56 B9 03 7B 
iso.3.6.1.2.1.2.2.1.6.14 = Hex-STRING: 00 50 56 B9 03 7B 
iso.3.6.1.2.1.2.2.1.6.15 = Hex-STRING: 00 50 56 B9 03 7B 
iso.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.7.2 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.3 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.4 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.5 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.6 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.7 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.8 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.9 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.10 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.7.11 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.12 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.7.13 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.7.14 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.7.15 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.8.2 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.3 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.4 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.5 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.6 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.7 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.8 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.9 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.10 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.8.11 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.12 = INTEGER: 6
iso.3.6.1.2.1.2.2.1.8.13 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.8.14 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.8.15 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.9.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.5 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.6 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.7 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.8 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.9 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.11 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.12 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.13 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.14 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.9.15 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.2.2.1.10.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.10 = Counter32: 982981
iso.3.6.1.2.1.2.2.1.10.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.10.13 = Counter32: 982981
iso.3.6.1.2.1.2.2.1.10.14 = Counter32: 982981
iso.3.6.1.2.1.2.2.1.10.15 = Counter32: 982981
iso.3.6.1.2.1.2.2.1.11.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.10 = Counter32: 13490
iso.3.6.1.2.1.2.2.1.11.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.11.13 = Counter32: 13490
iso.3.6.1.2.1.2.2.1.11.14 = Counter32: 13490
iso.3.6.1.2.1.2.2.1.11.15 = Counter32: 13490
iso.3.6.1.2.1.2.2.1.12.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.12.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.13.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.14.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.15.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.10 = Counter32: 285294
iso.3.6.1.2.1.2.2.1.16.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.16.13 = Counter32: 285294
iso.3.6.1.2.1.2.2.1.16.14 = Counter32: 285294
iso.3.6.1.2.1.2.2.1.16.15 = Counter32: 285294
iso.3.6.1.2.1.2.2.1.17.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.10 = Counter32: 2936
iso.3.6.1.2.1.2.2.1.17.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.17.13 = Counter32: 2975
iso.3.6.1.2.1.2.2.1.17.14 = Counter32: 2975
iso.3.6.1.2.1.2.2.1.17.15 = Counter32: 2975
iso.3.6.1.2.1.2.2.1.18.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.18.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.19.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.1 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.2 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.3 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.4 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.5 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.6 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.7 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.8 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.9 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.10 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.11 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.12 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.13 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.14 = Counter32: 0
iso.3.6.1.2.1.2.2.1.20.15 = Counter32: 0
iso.3.6.1.2.1.2.2.1.21.1 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.2 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.3 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.4 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.5 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.6 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.7 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.8 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.9 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.10 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.11 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.12 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.13 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.14 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.21.15 = Gauge32: 0
iso.3.6.1.2.1.2.2.1.22.1 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.2 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.3 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.4 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.5 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.6 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.7 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.8 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.9 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.10 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.11 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.12 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.13 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.14 = OID: ccitt.0
iso.3.6.1.2.1.2.2.1.22.15 = OID: ccitt.0
iso.3.6.1.2.1.4.1.0 = INTEGER: 2
iso.3.6.1.2.1.4.2.0 = INTEGER: 128
iso.3.6.1.2.1.4.3.0 = Counter32: 16792
iso.3.6.1.2.1.4.4.0 = Counter32: 0
iso.3.6.1.2.1.4.5.0 = Counter32: 0
iso.3.6.1.2.1.4.6.0 = Counter32: 0
iso.3.6.1.2.1.4.7.0 = Counter32: 0
iso.3.6.1.2.1.4.8.0 = Counter32: 774
iso.3.6.1.2.1.4.9.0 = Counter32: 16133
iso.3.6.1.2.1.4.10.0 = Counter32: 3015
iso.3.6.1.2.1.4.11.0 = Counter32: 0
iso.3.6.1.2.1.4.12.0 = Counter32: 0
iso.3.6.1.2.1.4.13.0 = INTEGER: 60
iso.3.6.1.2.1.4.14.0 = Counter32: 0
iso.3.6.1.2.1.4.15.0 = Counter32: 0
iso.3.6.1.2.1.4.16.0 = Counter32: 0
iso.3.6.1.2.1.4.17.0 = Counter32: 0
iso.3.6.1.2.1.4.18.0 = Counter32: 0
iso.3.6.1.2.1.4.19.0 = Counter32: 0
iso.3.6.1.2.1.4.20.1.1.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.20.1.2.10.10.10.116 = INTEGER: 10
iso.3.6.1.2.1.4.20.1.2.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.20.1.3.10.10.10.116 = IpAddress: 255.255.255.0
iso.3.6.1.2.1.4.20.1.3.127.0.0.1 = IpAddress: 255.0.0.0
iso.3.6.1.2.1.4.20.1.4.10.10.10.116 = INTEGER: 1
iso.3.6.1.2.1.4.20.1.4.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.20.1.5.10.10.10.116 = INTEGER: 65535
iso.3.6.1.2.1.4.20.1.5.127.0.0.1 = INTEGER: 65535
iso.3.6.1.2.1.4.21.1.1.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.4.21.1.1.10.10.10.0 = IpAddress: 10.10.10.0
iso.3.6.1.2.1.4.21.1.1.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.21.1.1.10.10.10.255 = IpAddress: 10.10.10.255
iso.3.6.1.2.1.4.21.1.1.127.0.0.0 = IpAddress: 127.0.0.0
iso.3.6.1.2.1.4.21.1.1.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.1.127.255.255.255 = IpAddress: 127.255.255.255
iso.3.6.1.2.1.4.21.1.1.224.0.0.0 = IpAddress: 224.0.0.0
iso.3.6.1.2.1.4.21.1.1.255.255.255.255 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.2.0.0.0.0 = INTEGER: 10
iso.3.6.1.2.1.4.21.1.2.10.10.10.0 = INTEGER: 10
iso.3.6.1.2.1.4.21.1.2.10.10.10.116 = INTEGER: 10
iso.3.6.1.2.1.4.21.1.2.10.10.10.255 = INTEGER: 10
iso.3.6.1.2.1.4.21.1.2.127.0.0.0 = INTEGER: 1
iso.3.6.1.2.1.4.21.1.2.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.21.1.2.127.255.255.255 = INTEGER: 1
iso.3.6.1.2.1.4.21.1.2.224.0.0.0 = INTEGER: 1
iso.3.6.1.2.1.4.21.1.2.255.255.255.255 = INTEGER: 1
iso.3.6.1.2.1.4.21.1.3.0.0.0.0 = INTEGER: 281
iso.3.6.1.2.1.4.21.1.3.10.10.10.0 = INTEGER: 281
iso.3.6.1.2.1.4.21.1.3.10.10.10.116 = INTEGER: 281
iso.3.6.1.2.1.4.21.1.3.10.10.10.255 = INTEGER: 281
iso.3.6.1.2.1.4.21.1.3.127.0.0.0 = INTEGER: 331
iso.3.6.1.2.1.4.21.1.3.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.21.1.3.127.255.255.255 = INTEGER: 331
iso.3.6.1.2.1.4.21.1.3.224.0.0.0 = INTEGER: 331
iso.3.6.1.2.1.4.21.1.3.255.255.255.255 = INTEGER: 331
iso.3.6.1.2.1.4.21.1.4.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.10.10.10.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.10.10.10.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.127.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.127.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.224.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.4.255.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.10.10.10.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.10.10.10.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.127.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.127.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.224.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.5.255.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.10.10.10.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.10.10.10.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.127.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.127.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.224.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.6.255.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.7.0.0.0.0 = IpAddress: 10.10.10.2
iso.3.6.1.2.1.4.21.1.7.10.10.10.0 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.21.1.7.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.21.1.7.10.10.10.255 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.21.1.7.127.0.0.0 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.7.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.7.127.255.255.255 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.7.224.0.0.0 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.7.255.255.255.255 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.21.1.8.0.0.0.0 = INTEGER: 4
iso.3.6.1.2.1.4.21.1.8.10.10.10.0 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.10.10.10.116 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.10.10.10.255 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.127.0.0.0 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.127.255.255.255 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.224.0.0.0 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.8.255.255.255.255 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.9.0.0.0.0 = INTEGER: 3
iso.3.6.1.2.1.4.21.1.9.10.10.10.0 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.10.10.10.116 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.127.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.127.255.255.255 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.224.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.9.255.255.255.255 = INTEGER: 2
iso.3.6.1.2.1.4.21.1.10.0.0.0.0 = INTEGER: 907
iso.3.6.1.2.1.4.21.1.10.10.10.10.0 = INTEGER: 903
iso.3.6.1.2.1.4.21.1.10.10.10.10.116 = INTEGER: 903
iso.3.6.1.2.1.4.21.1.10.10.10.10.255 = INTEGER: 903
iso.3.6.1.2.1.4.21.1.10.127.0.0.0 = INTEGER: 915
iso.3.6.1.2.1.4.21.1.10.127.0.0.1 = INTEGER: 915
iso.3.6.1.2.1.4.21.1.10.127.255.255.255 = INTEGER: 915
iso.3.6.1.2.1.4.21.1.10.224.0.0.0 = INTEGER: 915
iso.3.6.1.2.1.4.21.1.10.255.255.255.255 = INTEGER: 915
iso.3.6.1.2.1.4.21.1.11.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.4.21.1.11.10.10.10.0 = IpAddress: 255.255.255.0
iso.3.6.1.2.1.4.21.1.11.10.10.10.116 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.11.10.10.10.255 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.11.127.0.0.0 = IpAddress: 255.0.0.0
iso.3.6.1.2.1.4.21.1.11.127.0.0.1 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.11.127.255.255.255 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.11.224.0.0.0 = IpAddress: 240.0.0.0
iso.3.6.1.2.1.4.21.1.11.255.255.255.255 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.21.1.12.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.10.10.10.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.10.10.10.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.127.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.127.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.224.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.12.255.255.255.255 = INTEGER: 0
iso.3.6.1.2.1.4.21.1.13.0.0.0.0 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.10.10.10.0 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.10.10.10.116 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.10.10.10.255 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.127.0.0.0 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.127.255.255.255 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.224.0.0.0 = OID: ccitt.0
iso.3.6.1.2.1.4.21.1.13.255.255.255.255 = OID: ccitt.0
iso.3.6.1.2.1.4.22.1.1.1.224.0.0.22 = INTEGER: 1
iso.3.6.1.2.1.4.22.1.1.1.239.255.255.250 = INTEGER: 1
iso.3.6.1.2.1.4.22.1.1.10.10.10.10.2 = INTEGER: 10
iso.3.6.1.2.1.4.22.1.1.10.10.10.10.255 = INTEGER: 10
iso.3.6.1.2.1.4.22.1.1.10.224.0.0.22 = INTEGER: 10
iso.3.6.1.2.1.4.22.1.1.10.224.0.0.252 = INTEGER: 10
iso.3.6.1.2.1.4.22.1.1.10.239.255.255.250 = INTEGER: 10
iso.3.6.1.2.1.4.22.1.2.1.224.0.0.22 = ""
iso.3.6.1.2.1.4.22.1.2.1.239.255.255.250 = ""
iso.3.6.1.2.1.4.22.1.2.10.10.10.10.2 = Hex-STRING: 00 50 56 B9 95 03 
iso.3.6.1.2.1.4.22.1.2.10.10.10.10.255 = Hex-STRING: FF FF FF FF FF FF 
iso.3.6.1.2.1.4.22.1.2.10.224.0.0.22 = Hex-STRING: 01 00 5E 00 00 16 
iso.3.6.1.2.1.4.22.1.2.10.224.0.0.252 = Hex-STRING: 01 00 5E 00 00 FC 
iso.3.6.1.2.1.4.22.1.2.10.239.255.255.250 = Hex-STRING: 01 00 5E 7F FF FA 
iso.3.6.1.2.1.4.22.1.3.1.224.0.0.22 = IpAddress: 224.0.0.22
iso.3.6.1.2.1.4.22.1.3.1.239.255.255.250 = IpAddress: 239.255.255.250
iso.3.6.1.2.1.4.22.1.3.10.10.10.10.2 = IpAddress: 10.10.10.2
iso.3.6.1.2.1.4.22.1.3.10.10.10.10.255 = IpAddress: 10.10.10.255
iso.3.6.1.2.1.4.22.1.3.10.224.0.0.22 = IpAddress: 224.0.0.22
iso.3.6.1.2.1.4.22.1.3.10.224.0.0.252 = IpAddress: 224.0.0.252
iso.3.6.1.2.1.4.22.1.3.10.239.255.255.250 = IpAddress: 239.255.255.250
iso.3.6.1.2.1.4.22.1.4.1.224.0.0.22 = INTEGER: 4
iso.3.6.1.2.1.4.22.1.4.1.239.255.255.250 = INTEGER: 4
iso.3.6.1.2.1.4.22.1.4.10.10.10.10.2 = INTEGER: 3
iso.3.6.1.2.1.4.22.1.4.10.10.10.10.255 = INTEGER: 4
iso.3.6.1.2.1.4.22.1.4.10.224.0.0.22 = INTEGER: 4
iso.3.6.1.2.1.4.22.1.4.10.224.0.0.252 = INTEGER: 4
iso.3.6.1.2.1.4.22.1.4.10.239.255.255.250 = INTEGER: 4
iso.3.6.1.2.1.4.23.0 = Counter32: 0
iso.3.6.1.2.1.4.24.1.0 = Gauge32: 11
iso.3.6.1.2.1.4.24.2.1.1.0.0.0.0.3.0.10.10.10.2 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.4.24.2.1.1.10.10.10.0.2.0.10.10.10.116 = IpAddress: 10.10.10.0
iso.3.6.1.2.1.4.24.2.1.1.10.10.10.116.2.0.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.24.2.1.1.10.10.10.255.2.0.10.10.10.116 = IpAddress: 10.10.10.255
iso.3.6.1.2.1.4.24.2.1.1.127.0.0.0.2.0.127.0.0.1 = IpAddress: 127.0.0.0
iso.3.6.1.2.1.4.24.2.1.1.127.0.0.1.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.1.127.255.255.255.2.0.127.0.0.1 = IpAddress: 127.255.255.255
iso.3.6.1.2.1.4.24.2.1.1.224.0.0.0.2.0.127.0.0.1 = IpAddress: 224.0.0.0
iso.3.6.1.2.1.4.24.2.1.1.255.255.255.255.2.0.127.0.0.1 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.2.0.0.0.0.3.0.10.10.10.2 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.4.24.2.1.2.10.10.10.0.2.0.10.10.10.116 = IpAddress: 255.255.255.0
iso.3.6.1.2.1.4.24.2.1.2.10.10.10.116.2.0.10.10.10.116 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.2.10.10.10.255.2.0.10.10.10.116 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.2.127.0.0.0.2.0.127.0.0.1 = IpAddress: 255.0.0.0
iso.3.6.1.2.1.4.24.2.1.2.127.0.0.1.2.0.127.0.0.1 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.2.127.255.255.255.2.0.127.0.0.1 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.2.224.0.0.0.2.0.127.0.0.1 = IpAddress: 240.0.0.0
iso.3.6.1.2.1.4.24.2.1.2.255.255.255.255.2.0.127.0.0.1 = IpAddress: 255.255.255.255
iso.3.6.1.2.1.4.24.2.1.3.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.3.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.4.0.0.0.0.3.0.10.10.10.2 = IpAddress: 10.10.10.2
iso.3.6.1.2.1.4.24.2.1.4.10.10.10.0.2.0.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.24.2.1.4.10.10.10.116.2.0.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.24.2.1.4.10.10.10.255.2.0.10.10.10.116 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.4.24.2.1.4.127.0.0.0.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.4.127.0.0.1.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.4.127.255.255.255.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.4.224.0.0.0.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.4.255.255.255.255.2.0.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.24.2.1.5.0.0.0.0.3.0.10.10.10.2 = INTEGER: 10
iso.3.6.1.2.1.4.24.2.1.5.10.10.10.0.2.0.10.10.10.116 = INTEGER: 10
iso.3.6.1.2.1.4.24.2.1.5.10.10.10.116.2.0.10.10.10.116 = INTEGER: 10
iso.3.6.1.2.1.4.24.2.1.5.10.10.10.255.2.0.10.10.10.116 = INTEGER: 10
iso.3.6.1.2.1.4.24.2.1.5.127.0.0.0.2.0.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.24.2.1.5.127.0.0.1.2.0.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.24.2.1.5.127.255.255.255.2.0.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.24.2.1.5.224.0.0.0.2.0.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.24.2.1.5.255.255.255.255.2.0.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.24.2.1.6.0.0.0.0.3.0.10.10.10.2 = INTEGER: 4
iso.3.6.1.2.1.4.24.2.1.6.10.10.10.0.2.0.10.10.10.116 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.10.10.10.116.2.0.10.10.10.116 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.10.10.10.255.2.0.10.10.10.116 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.127.0.0.0.2.0.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.127.0.0.1.2.0.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.127.255.255.255.2.0.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.224.0.0.0.2.0.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.6.255.255.255.255.2.0.127.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.7.0.0.0.0.3.0.10.10.10.2 = INTEGER: 3
iso.3.6.1.2.1.4.24.2.1.7.10.10.10.0.2.0.10.10.10.116 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.10.10.10.116.2.0.10.10.10.116 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.10.10.10.255.2.0.10.10.10.116 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.127.0.0.0.2.0.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.127.0.0.1.2.0.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.127.255.255.255.2.0.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.224.0.0.0.2.0.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.7.255.255.255.255.2.0.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.24.2.1.8.0.0.0.0.3.0.10.10.10.2 = INTEGER: 947
iso.3.6.1.2.1.4.24.2.1.8.10.10.10.0.2.0.10.10.10.116 = INTEGER: 944
iso.3.6.1.2.1.4.24.2.1.8.10.10.10.116.2.0.10.10.10.116 = INTEGER: 944
iso.3.6.1.2.1.4.24.2.1.8.10.10.10.255.2.0.10.10.10.116 = INTEGER: 944
iso.3.6.1.2.1.4.24.2.1.8.127.0.0.0.2.0.127.0.0.1 = INTEGER: 956
iso.3.6.1.2.1.4.24.2.1.8.127.0.0.1.2.0.127.0.0.1 = INTEGER: 956
iso.3.6.1.2.1.4.24.2.1.8.127.255.255.255.2.0.127.0.0.1 = INTEGER: 956
iso.3.6.1.2.1.4.24.2.1.8.224.0.0.0.2.0.127.0.0.1 = INTEGER: 956
iso.3.6.1.2.1.4.24.2.1.8.255.255.255.255.2.0.127.0.0.1 = INTEGER: 956
iso.3.6.1.2.1.4.24.2.1.9.0.0.0.0.3.0.10.10.10.2 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.10.10.10.0.2.0.10.10.10.116 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.10.10.10.116.2.0.10.10.10.116 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.10.10.10.255.2.0.10.10.10.116 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.127.0.0.0.2.0.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.127.0.0.1.2.0.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.127.255.255.255.2.0.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.224.0.0.0.2.0.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.9.255.255.255.255.2.0.127.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.4.24.2.1.10.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.10.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.11.0.0.0.0.3.0.10.10.10.2 = INTEGER: 281
iso.3.6.1.2.1.4.24.2.1.11.10.10.10.0.2.0.10.10.10.116 = INTEGER: 281
iso.3.6.1.2.1.4.24.2.1.11.10.10.10.116.2.0.10.10.10.116 = INTEGER: 281
iso.3.6.1.2.1.4.24.2.1.11.10.10.10.255.2.0.10.10.10.116 = INTEGER: 281
iso.3.6.1.2.1.4.24.2.1.11.127.0.0.0.2.0.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.24.2.1.11.127.0.0.1.2.0.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.24.2.1.11.127.255.255.255.2.0.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.24.2.1.11.224.0.0.0.2.0.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.24.2.1.11.255.255.255.255.2.0.127.0.0.1 = INTEGER: 331
iso.3.6.1.2.1.4.24.2.1.12.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.12.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.13.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.14.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.0.0.0.0.3.0.10.10.10.2 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.10.10.10.0.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.10.10.10.116.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.10.10.10.255.2.0.10.10.10.116 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.127.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.127.0.0.1.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.127.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.224.0.0.0.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.4.24.2.1.15.255.255.255.255.2.0.127.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.5.1.0 = Counter32: 984
iso.3.6.1.2.1.5.2.0 = Counter32: 0
iso.3.6.1.2.1.5.3.0 = Counter32: 12
iso.3.6.1.2.1.5.4.0 = Counter32: 0
iso.3.6.1.2.1.5.5.0 = Counter32: 0
iso.3.6.1.2.1.5.6.0 = Counter32: 0
iso.3.6.1.2.1.5.7.0 = Counter32: 0
iso.3.6.1.2.1.5.8.0 = Counter32: 973
iso.3.6.1.2.1.5.9.0 = Counter32: 0
iso.3.6.1.2.1.5.10.0 = Counter32: 0
iso.3.6.1.2.1.5.11.0 = Counter32: 0
iso.3.6.1.2.1.5.12.0 = Counter32: 0
iso.3.6.1.2.1.5.13.0 = Counter32: 0
iso.3.6.1.2.1.5.14.0 = Counter32: 1067
iso.3.6.1.2.1.5.15.0 = Counter32: 0
iso.3.6.1.2.1.5.16.0 = Counter32: 99
iso.3.6.1.2.1.5.17.0 = Counter32: 0
iso.3.6.1.2.1.5.18.0 = Counter32: 2
iso.3.6.1.2.1.5.19.0 = Counter32: 0
iso.3.6.1.2.1.5.20.0 = Counter32: 0
iso.3.6.1.2.1.5.21.0 = Counter32: 0
iso.3.6.1.2.1.5.22.0 = Counter32: 968
iso.3.6.1.2.1.5.23.0 = Counter32: 0
iso.3.6.1.2.1.5.24.0 = Counter32: 0
iso.3.6.1.2.1.5.25.0 = Counter32: 0
iso.3.6.1.2.1.5.26.0 = Counter32: 0
iso.3.6.1.2.1.5.27.1.3.1.0 = Counter32: 991
iso.3.6.1.2.1.5.27.1.3.2.0 = Counter32: 6
iso.3.6.1.2.1.5.27.1.4.1.0 = Counter32: 0
iso.3.6.1.2.1.5.27.1.4.2.0 = Counter32: 0
iso.3.6.1.2.1.5.27.1.5.1.0 = Counter32: 1070
iso.3.6.1.2.1.5.27.1.5.2.0 = Counter32: 10
iso.3.6.1.2.1.5.27.1.6.1.0 = Counter32: 0
iso.3.6.1.2.1.5.27.1.6.2.0 = Counter32: 0
iso.3.6.1.2.1.5.28.1.5.1.0.0.256 = Counter32: 0
iso.3.6.1.2.1.5.28.1.5.1.0.3.256 = Counter32: 12
iso.3.6.1.2.1.5.28.1.5.1.0.8.256 = Counter32: 979
iso.3.6.1.2.1.5.28.1.5.1.0.12.256 = Counter32: 0
iso.3.6.1.2.1.5.28.1.5.2.0.133.256 = Counter32: 0
iso.3.6.1.2.1.5.28.1.5.2.0.134.256 = Counter32: 3
iso.3.6.1.2.1.5.28.1.5.2.0.135.256 = Counter32: 1
iso.3.6.1.2.1.5.28.1.5.2.0.136.256 = Counter32: 2
iso.3.6.1.2.1.5.28.1.6.1.0.0.256 = Counter32: 969
iso.3.6.1.2.1.5.28.1.6.1.0.3.256 = Counter32: 99
iso.3.6.1.2.1.5.28.1.6.1.0.8.256 = Counter32: 0
iso.3.6.1.2.1.5.28.1.6.1.0.12.256 = Counter32: 2
iso.3.6.1.2.1.5.28.1.6.2.0.133.256 = Counter32: 1
iso.3.6.1.2.1.5.28.1.6.2.0.134.256 = Counter32: 0
iso.3.6.1.2.1.5.28.1.6.2.0.135.256 = Counter32: 5
iso.3.6.1.2.1.5.28.1.6.2.0.136.256 = Counter32: 4
iso.3.6.1.2.1.6.1.0 = INTEGER: 3
iso.3.6.1.2.1.6.2.0 = INTEGER: 10
iso.3.6.1.2.1.6.3.0 = INTEGER: -1
iso.3.6.1.2.1.6.4.0 = INTEGER: -1
iso.3.6.1.2.1.6.5.0 = Counter32: 2
iso.3.6.1.2.1.6.6.0 = Counter32: 0
iso.3.6.1.2.1.6.7.0 = Counter32: 2
iso.3.6.1.2.1.6.8.0 = Counter32: 0
iso.3.6.1.2.1.6.9.0 = Gauge32: 0
iso.3.6.1.2.1.6.10.0 = Counter32: 11562
iso.3.6.1.2.1.6.11.0 = Counter32: 8
iso.3.6.1.2.1.6.12.0 = Counter32: 4
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.21.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.80.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.135.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.445.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49664.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49665.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49666.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49667.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49668.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49669.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.49670.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.1.10.10.10.116.139.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.21.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.80.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.135.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.445.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49664.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49665.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49666.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49667.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49668.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49669.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.49670.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.2.10.10.10.116.139.0.0.0.0.0 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.21.0.0.0.0.0 = INTEGER: 21
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.80.0.0.0.0.0 = INTEGER: 80
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49664.0.0.0.0.0 = INTEGER: 49664
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49665.0.0.0.0.0 = INTEGER: 49665
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49666.0.0.0.0.0 = INTEGER: 49666
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49667.0.0.0.0.0 = INTEGER: 49667
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49668.0.0.0.0.0 = INTEGER: 49668
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49669.0.0.0.0.0 = INTEGER: 49669
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.49670.0.0.0.0.0 = INTEGER: 49670
iso.3.6.1.2.1.6.13.1.3.10.10.10.116.139.0.0.0.0.0 = INTEGER: 139
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.21.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.80.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.135.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.445.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49664.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49665.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49666.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49667.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49668.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49669.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.49670.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.4.10.10.10.116.139.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.21.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.80.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.135.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.445.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49664.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49665.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49666.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49667.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49668.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49669.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.49670.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.13.1.5.10.10.10.116.139.0.0.0.0.0 = INTEGER: 0
iso.3.6.1.2.1.6.14.0 = Counter32: 0
iso.3.6.1.2.1.6.15.0 = Counter32: 6
iso.3.6.1.2.1.6.19.1.7.0.0.21.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.0.0.80.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.0.0.445.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.135.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49664.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49665.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49666.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49667.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49668.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49669.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.0.0.0.0.49670.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.1.4.10.10.10.116.139.1.4.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.135.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49664.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49665.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49666.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49667.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49668.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49669.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.19.1.7.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.49670.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.7.1.0 = Counter32: 2664
iso.3.6.1.2.1.7.2.0 = Counter32: 749
iso.3.6.1.2.1.7.3.0 = Counter32: 5
iso.3.6.1.2.1.7.4.0 = Counter32: 2598
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.123 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.161 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.500 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.4500 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.5050 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.5353 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.0.0.0.0.5355 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.7.5.1.1.10.10.10.116.137 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.7.5.1.1.10.10.10.116.138 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.7.5.1.1.10.10.10.116.1900 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.7.5.1.1.10.10.10.116.50906 = IpAddress: 10.10.10.116
iso.3.6.1.2.1.7.5.1.1.127.0.0.1.1900 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.7.5.1.1.127.0.0.1.50907 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.123 = INTEGER: 123
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.161 = INTEGER: 161
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.500 = INTEGER: 500
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.4500 = INTEGER: 4500
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.5050 = INTEGER: 5050
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.5353 = INTEGER: 5353
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.5355 = INTEGER: 5355
iso.3.6.1.2.1.7.5.1.2.10.10.10.116.137 = INTEGER: 137
iso.3.6.1.2.1.7.5.1.2.10.10.10.116.138 = INTEGER: 138
iso.3.6.1.2.1.7.5.1.2.10.10.10.116.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.5.1.2.10.10.10.116.50906 = INTEGER: 50906
iso.3.6.1.2.1.7.5.1.2.127.0.0.1.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.5.1.2.127.0.0.1.50907 = INTEGER: 50907
iso.3.6.1.2.1.7.7.1.3.0.0.51170 = INTEGER: 51170
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.123 = INTEGER: 123
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.161 = INTEGER: 161
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.500 = INTEGER: 500
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.4500 = INTEGER: 4500
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.5050 = INTEGER: 5050
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.5353 = INTEGER: 5353
iso.3.6.1.2.1.7.7.1.3.1.4.0.0.0.0.5355 = INTEGER: 5355
iso.3.6.1.2.1.7.7.1.3.1.4.10.10.10.116.137 = INTEGER: 137
iso.3.6.1.2.1.7.7.1.3.1.4.10.10.10.116.138 = INTEGER: 138
iso.3.6.1.2.1.7.7.1.3.1.4.10.10.10.116.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.7.1.3.1.4.10.10.10.116.50906 = INTEGER: 50906
iso.3.6.1.2.1.7.7.1.3.1.4.127.0.0.1.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.7.1.3.1.4.127.0.0.1.50907 = INTEGER: 50907
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.123 = INTEGER: 123
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.161 = INTEGER: 161
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.500 = INTEGER: 500
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4500 = INTEGER: 4500
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5353 = INTEGER: 5353
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5355 = INTEGER: 5355
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.7.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.50905 = INTEGER: 50905
iso.3.6.1.2.1.7.7.1.3.2.20.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20.0.0.0.10.1900 = INTEGER: 1900
iso.3.6.1.2.1.7.7.1.3.2.20.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20.0.0.0.10.50904 = INTEGER: 50904
iso.3.6.1.2.1.11.1.0 = Counter32: 2341
iso.3.6.1.2.1.11.2.0 = Counter32: 2215
iso.3.6.1.2.1.11.3.0 = Counter32: 6
iso.3.6.1.2.1.11.4.0 = Counter32: 119
iso.3.6.1.2.1.11.5.0 = Counter32: 1
iso.3.6.1.2.1.11.6.0 = Counter32: 6
iso.3.6.1.2.1.11.8.0 = Counter32: 0
iso.3.6.1.2.1.11.9.0 = Counter32: 0
iso.3.6.1.2.1.11.10.0 = Counter32: 0
iso.3.6.1.2.1.11.11.0 = Counter32: 0
iso.3.6.1.2.1.11.12.0 = Counter32: 0
iso.3.6.1.2.1.11.13.0 = Counter32: 2221
iso.3.6.1.2.1.11.14.0 = Counter32: 0
iso.3.6.1.2.1.11.15.0 = Counter32: 9
iso.3.6.1.2.1.11.16.0 = Counter32: 2219
iso.3.6.1.2.1.11.17.0 = Counter32: 0
iso.3.6.1.2.1.11.18.0 = Counter32: 0
iso.3.6.1.2.1.11.19.0 = Counter32: 0
iso.3.6.1.2.1.11.20.0 = Counter32: 0
iso.3.6.1.2.1.11.21.0 = Counter32: 8
iso.3.6.1.2.1.11.22.0 = Counter32: 0
iso.3.6.1.2.1.11.24.0 = Counter32: 0
iso.3.6.1.2.1.11.25.0 = Counter32: 0
iso.3.6.1.2.1.11.26.0 = Counter32: 0
iso.3.6.1.2.1.11.27.0 = Counter32: 0
iso.3.6.1.2.1.11.28.0 = Counter32: 2239
iso.3.6.1.2.1.11.29.0 = Counter32: 0
iso.3.6.1.2.1.11.30.0 = INTEGER: 1
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (105090) 0:17:30.90
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E4 07 03 14 2A 12 01 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.4.0 = ""
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 55
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.2.2.0 = INTEGER: 2096628
iso.3.6.1.2.1.25.2.3.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.2.3.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.25.2.3.1.1.3 = INTEGER: 3
iso.3.6.1.2.1.25.2.3.1.1.4 = INTEGER: 4
iso.3.6.1.2.1.25.2.3.1.2.1 = OID: iso.3.6.1.2.1.25.2.1.4
iso.3.6.1.2.1.25.2.3.1.2.2 = OID: iso.3.6.1.2.1.25.2.1.7
iso.3.6.1.2.1.25.2.3.1.2.3 = OID: iso.3.6.1.2.1.25.2.1.3
iso.3.6.1.2.1.25.2.3.1.2.4 = OID: iso.3.6.1.2.1.25.2.1.2
iso.3.6.1.2.1.25.2.3.1.3.1 = STRING: "C:\\ Label:  Serial Number 9606be7b"
iso.3.6.1.2.1.25.2.3.1.3.2 = STRING: "D:\\"
iso.3.6.1.2.1.25.2.3.1.3.3 = STRING: "Virtual Memory"
iso.3.6.1.2.1.25.2.3.1.3.4 = STRING: "Physical Memory"
iso.3.6.1.2.1.25.2.3.1.4.1 = INTEGER: 4096
iso.3.6.1.2.1.25.2.3.1.4.2 = INTEGER: 0
iso.3.6.1.2.1.25.2.3.1.4.3 = INTEGER: 65536
iso.3.6.1.2.1.25.2.3.1.4.4 = INTEGER: 65536
iso.3.6.1.2.1.25.2.3.1.5.1 = INTEGER: 15600127
iso.3.6.1.2.1.25.2.3.1.5.2 = INTEGER: 0
iso.3.6.1.2.1.25.2.3.1.5.3 = INTEGER: 51191
iso.3.6.1.2.1.25.2.3.1.5.4 = INTEGER: 32759
iso.3.6.1.2.1.25.2.3.1.6.1 = INTEGER: 2770553
iso.3.6.1.2.1.25.2.3.1.6.2 = INTEGER: 0
iso.3.6.1.2.1.25.2.3.1.6.3 = INTEGER: 13265
iso.3.6.1.2.1.25.2.3.1.6.4 = INTEGER: 12913
iso.3.6.1.2.1.25.2.3.1.7.1 = Counter32: 0
iso.3.6.1.2.1.25.2.3.1.7.2 = Counter32: 0
iso.3.6.1.2.1.25.2.3.1.7.3 = Counter32: 0
iso.3.6.1.2.1.25.2.3.1.7.4 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.1.3 = INTEGER: 3
iso.3.6.1.2.1.25.3.2.1.1.4 = INTEGER: 4
iso.3.6.1.2.1.25.3.2.1.1.5 = INTEGER: 5
iso.3.6.1.2.1.25.3.2.1.1.6 = INTEGER: 6
iso.3.6.1.2.1.25.3.2.1.1.7 = INTEGER: 7
iso.3.6.1.2.1.25.3.2.1.1.8 = INTEGER: 8
iso.3.6.1.2.1.25.3.2.1.1.9 = INTEGER: 9
iso.3.6.1.2.1.25.3.2.1.1.10 = INTEGER: 10
iso.3.6.1.2.1.25.3.2.1.1.11 = INTEGER: 11
iso.3.6.1.2.1.25.3.2.1.1.12 = INTEGER: 12
iso.3.6.1.2.1.25.3.2.1.1.13 = INTEGER: 13
iso.3.6.1.2.1.25.3.2.1.1.14 = INTEGER: 14
iso.3.6.1.2.1.25.3.2.1.1.15 = INTEGER: 15
iso.3.6.1.2.1.25.3.2.1.1.16 = INTEGER: 16
iso.3.6.1.2.1.25.3.2.1.1.17 = INTEGER: 17
iso.3.6.1.2.1.25.3.2.1.1.18 = INTEGER: 18
iso.3.6.1.2.1.25.3.2.1.1.19 = INTEGER: 19
iso.3.6.1.2.1.25.3.2.1.1.20 = INTEGER: 20
iso.3.6.1.2.1.25.3.2.1.1.21 = INTEGER: 21
iso.3.6.1.2.1.25.3.2.1.1.22 = INTEGER: 22
iso.3.6.1.2.1.25.3.2.1.1.23 = INTEGER: 23
iso.3.6.1.2.1.25.3.2.1.2.1 = OID: iso.3.6.1.2.1.25.3.1.5
iso.3.6.1.2.1.25.3.2.1.2.2 = OID: iso.3.6.1.2.1.25.3.1.5
iso.3.6.1.2.1.25.3.2.1.2.3 = OID: iso.3.6.1.2.1.25.3.1.5
iso.3.6.1.2.1.25.3.2.1.2.4 = OID: iso.3.6.1.2.1.25.3.1.3
iso.3.6.1.2.1.25.3.2.1.2.5 = OID: iso.3.6.1.2.1.25.3.1.3
iso.3.6.1.2.1.25.3.2.1.2.6 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.7 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.8 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.9 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.10 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.11 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.12 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.13 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.14 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.15 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.16 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.17 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.18 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.19 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.20 = OID: iso.3.6.1.2.1.25.3.1.4
iso.3.6.1.2.1.25.3.2.1.2.21 = OID: iso.3.6.1.2.1.25.3.1.6
iso.3.6.1.2.1.25.3.2.1.2.22 = OID: iso.3.6.1.2.1.25.3.1.6
iso.3.6.1.2.1.25.3.2.1.2.23 = OID: iso.3.6.1.2.1.25.3.1.13
iso.3.6.1.2.1.25.3.2.1.3.1 = STRING: "Microsoft XPS Document Writer v4"
iso.3.6.1.2.1.25.3.2.1.3.2 = STRING: "Microsoft Print To PDF"
iso.3.6.1.2.1.25.3.2.1.3.3 = STRING: "Microsoft Shared Fax Driver"
iso.3.6.1.2.1.25.3.2.1.3.4 = STRING: "Unknown Processor Type"
iso.3.6.1.2.1.25.3.2.1.3.5 = STRING: "Unknown Processor Type"
iso.3.6.1.2.1.25.3.2.1.3.6 = STRING: "Software Loopback Interface 1"
iso.3.6.1.2.1.25.3.2.1.3.7 = STRING: "WAN Miniport (IKEv2)"
iso.3.6.1.2.1.25.3.2.1.3.8 = STRING: "WAN Miniport (PPTP)"
iso.3.6.1.2.1.25.3.2.1.3.9 = STRING: "Microsoft Kernel Debug Network Adapter"
iso.3.6.1.2.1.25.3.2.1.3.10 = STRING: "WAN Miniport (L2TP)"
iso.3.6.1.2.1.25.3.2.1.3.11 = STRING: "Teredo Tunneling Pseudo-Interface"
iso.3.6.1.2.1.25.3.2.1.3.12 = STRING: "WAN Miniport (IP)"
iso.3.6.1.2.1.25.3.2.1.3.13 = STRING: "WAN Miniport (SSTP)"
iso.3.6.1.2.1.25.3.2.1.3.14 = STRING: "WAN Miniport (IPv6)"
iso.3.6.1.2.1.25.3.2.1.3.15 = STRING: "Intel(R) 82574L Gigabit Network Connection"
iso.3.6.1.2.1.25.3.2.1.3.16 = STRING: "WAN Miniport (PPPOE)"
iso.3.6.1.2.1.25.3.2.1.3.17 = STRING: "WAN Miniport (Network Monitor)"
iso.3.6.1.2.1.25.3.2.1.3.18 = STRING: "Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer "
iso.3.6.1.2.1.25.3.2.1.3.19 = STRING: "Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-"
iso.3.6.1.2.1.25.3.2.1.3.20 = STRING: "Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer L"
iso.3.6.1.2.1.25.3.2.1.3.21 = STRING: "D:\\"
iso.3.6.1.2.1.25.3.2.1.3.22 = STRING: "Fixed Disk"
iso.3.6.1.2.1.25.3.2.1.3.23 = STRING: "IBM enhanced (101- or 102-key) keyboard, Subtype=(0)"
iso.3.6.1.2.1.25.3.2.1.4.1 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.2 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.3 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.4 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.5 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.6 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.7 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.8 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.9 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.10 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.11 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.12 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.13 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.14 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.15 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.16 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.17 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.18 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.19 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.20 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.21 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.22 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.4.23 = OID: ccitt.0
iso.3.6.1.2.1.25.3.2.1.5.1 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.3 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.4 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.5 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.6 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.7 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.8 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.9 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.10 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.11 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.12 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.13 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.14 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.15 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.16 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.17 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.18 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.19 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.20 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.21 = INTEGER: 1
iso.3.6.1.2.1.25.3.2.1.5.22 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.5.23 = INTEGER: 2
iso.3.6.1.2.1.25.3.2.1.6.1 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.2 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.3 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.4 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.5 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.6 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.7 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.8 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.9 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.10 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.11 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.12 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.13 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.14 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.15 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.16 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.17 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.18 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.19 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.20 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.21 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.22 = Counter32: 0
iso.3.6.1.2.1.25.3.2.1.6.23 = Counter32: 0
iso.3.6.1.2.1.25.3.3.1.1.4 = OID: ccitt.0
iso.3.6.1.2.1.25.3.3.1.1.5 = OID: ccitt.0
iso.3.6.1.2.1.25.3.3.1.2.4 = INTEGER: 39
iso.3.6.1.2.1.25.3.3.1.2.5 = INTEGER: 64
iso.3.6.1.2.1.25.3.4.1.1.6 = INTEGER: 1
iso.3.6.1.2.1.25.3.4.1.1.7 = INTEGER: 2
iso.3.6.1.2.1.25.3.4.1.1.8 = INTEGER: 3
iso.3.6.1.2.1.25.3.4.1.1.9 = INTEGER: 4
iso.3.6.1.2.1.25.3.4.1.1.10 = INTEGER: 5
iso.3.6.1.2.1.25.3.4.1.1.11 = INTEGER: 6
iso.3.6.1.2.1.25.3.4.1.1.12 = INTEGER: 7
iso.3.6.1.2.1.25.3.4.1.1.13 = INTEGER: 8
iso.3.6.1.2.1.25.3.4.1.1.14 = INTEGER: 9
iso.3.6.1.2.1.25.3.4.1.1.15 = INTEGER: 10
iso.3.6.1.2.1.25.3.4.1.1.16 = INTEGER: 11
iso.3.6.1.2.1.25.3.4.1.1.17 = INTEGER: 12
iso.3.6.1.2.1.25.3.4.1.1.18 = INTEGER: 13
iso.3.6.1.2.1.25.3.4.1.1.19 = INTEGER: 14
iso.3.6.1.2.1.25.3.4.1.1.20 = INTEGER: 15
iso.3.6.1.2.1.25.3.5.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.5.1.1.2 = INTEGER: 1
iso.3.6.1.2.1.25.3.5.1.1.3 = INTEGER: 1
iso.3.6.1.2.1.25.3.5.1.2.1 = Hex-STRING: 00 
iso.3.6.1.2.1.25.3.5.1.2.2 = Hex-STRING: 00 
iso.3.6.1.2.1.25.3.5.1.2.3 = Hex-STRING: 00 
iso.3.6.1.2.1.25.3.6.1.1.21 = INTEGER: 2
iso.3.6.1.2.1.25.3.6.1.1.22 = INTEGER: 1
iso.3.6.1.2.1.25.3.6.1.2.21 = INTEGER: 5
iso.3.6.1.2.1.25.3.6.1.2.22 = INTEGER: 3
iso.3.6.1.2.1.25.3.6.1.3.21 = INTEGER: 1
iso.3.6.1.2.1.25.3.6.1.3.22 = INTEGER: 0
iso.3.6.1.2.1.25.3.6.1.4.21 = INTEGER: 0
iso.3.6.1.2.1.25.3.6.1.4.22 = INTEGER: 4190284
iso.3.6.1.2.1.25.3.7.1.1.22.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.7.1.1.22.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.7.1.2.22.1 = ""
iso.3.6.1.2.1.25.3.7.1.2.22.2 = ""
iso.3.6.1.2.1.25.3.7.1.3.22.1 = Hex-STRING: 01 00 00 00 
iso.3.6.1.2.1.25.3.7.1.3.22.2 = Hex-STRING: 02 00 00 00 
iso.3.6.1.2.1.25.3.7.1.4.22.1 = INTEGER: 512000
iso.3.6.1.2.1.25.3.7.1.4.22.2 = INTEGER: 3680256
iso.3.6.1.2.1.25.3.7.1.5.22.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.7.1.5.22.2 = INTEGER: 1
iso.3.6.1.2.1.25.3.8.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.8.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.8.1.2.1 = ""
iso.3.6.1.2.1.25.3.8.1.2.2 = ""
iso.3.6.1.2.1.25.3.8.1.3.1 = ""
iso.3.6.1.2.1.25.3.8.1.3.2 = ""
iso.3.6.1.2.1.25.3.8.1.4.1 = OID: iso.3.6.1.2.1.25.3.9.9
iso.3.6.1.2.1.25.3.8.1.4.2 = OID: iso.3.6.1.2.1.25.3.9.5
iso.3.6.1.2.1.25.3.8.1.5.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.8.1.5.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.8.1.6.1 = INTEGER: 0
iso.3.6.1.2.1.25.3.8.1.6.2 = INTEGER: 0
iso.3.6.1.2.1.25.3.8.1.7.1 = INTEGER: 1
iso.3.6.1.2.1.25.3.8.1.7.2 = INTEGER: 2
iso.3.6.1.2.1.25.3.8.1.8.1 = Hex-STRING: 00 00 01 01 00 00 00 00 
iso.3.6.1.2.1.25.3.8.1.8.2 = Hex-STRING: 00 00 01 01 00 00 00 00 
iso.3.6.1.2.1.25.3.8.1.9.1 = Hex-STRING: 00 00 01 01 00 00 00 00 
iso.3.6.1.2.1.25.3.8.1.9.2 = Hex-STRING: 00 00 01 01 00 00 00 00 
iso.3.6.1.2.1.25.4.1.0 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.1.4 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.1.68 = INTEGER: 68
iso.3.6.1.2.1.25.4.2.1.1.256 = INTEGER: 256
iso.3.6.1.2.1.25.4.2.1.1.308 = INTEGER: 308
iso.3.6.1.2.1.25.4.2.1.1.324 = INTEGER: 324
iso.3.6.1.2.1.25.4.2.1.1.400 = INTEGER: 400
iso.3.6.1.2.1.25.4.2.1.1.480 = INTEGER: 480
iso.3.6.1.2.1.25.4.2.1.1.492 = INTEGER: 492
iso.3.6.1.2.1.25.4.2.1.1.572 = INTEGER: 572
iso.3.6.1.2.1.25.4.2.1.1.592 = INTEGER: 592
iso.3.6.1.2.1.25.4.2.1.1.624 = INTEGER: 624
iso.3.6.1.2.1.25.4.2.1.1.704 = INTEGER: 704
iso.3.6.1.2.1.25.4.2.1.1.712 = INTEGER: 712
iso.3.6.1.2.1.25.4.2.1.1.728 = INTEGER: 728
iso.3.6.1.2.1.25.4.2.1.1.816 = INTEGER: 816
iso.3.6.1.2.1.25.4.2.1.1.824 = INTEGER: 824
iso.3.6.1.2.1.25.4.2.1.1.908 = INTEGER: 908
iso.3.6.1.2.1.25.4.2.1.1.964 = INTEGER: 964
iso.3.6.1.2.1.25.4.2.1.1.972 = INTEGER: 972
iso.3.6.1.2.1.25.4.2.1.1.1016 = INTEGER: 1016
iso.3.6.1.2.1.25.4.2.1.1.1072 = INTEGER: 1072
iso.3.6.1.2.1.25.4.2.1.1.1124 = INTEGER: 1124
iso.3.6.1.2.1.25.4.2.1.1.1276 = INTEGER: 1276
iso.3.6.1.2.1.25.4.2.1.1.1372 = INTEGER: 1372
iso.3.6.1.2.1.25.4.2.1.1.1384 = INTEGER: 1384
iso.3.6.1.2.1.25.4.2.1.1.1524 = INTEGER: 1524
iso.3.6.1.2.1.25.4.2.1.1.1612 = INTEGER: 1612
iso.3.6.1.2.1.25.4.2.1.1.1696 = INTEGER: 1696
iso.3.6.1.2.1.25.4.2.1.1.1704 = INTEGER: 1704
iso.3.6.1.2.1.25.4.2.1.1.1728 = INTEGER: 1728
iso.3.6.1.2.1.25.4.2.1.1.1788 = INTEGER: 1788
iso.3.6.1.2.1.25.4.2.1.1.1796 = INTEGER: 1796
iso.3.6.1.2.1.25.4.2.1.1.1820 = INTEGER: 1820
iso.3.6.1.2.1.25.4.2.1.1.1828 = INTEGER: 1828
iso.3.6.1.2.1.25.4.2.1.1.1840 = INTEGER: 1840
iso.3.6.1.2.1.25.4.2.1.1.1868 = INTEGER: 1868
iso.3.6.1.2.1.25.4.2.1.1.1896 = INTEGER: 1896
iso.3.6.1.2.1.25.4.2.1.1.2004 = INTEGER: 2004
iso.3.6.1.2.1.25.4.2.1.1.2348 = INTEGER: 2348
iso.3.6.1.2.1.25.4.2.1.1.2452 = INTEGER: 2452
iso.3.6.1.2.1.25.4.2.1.1.2596 = INTEGER: 2596
iso.3.6.1.2.1.25.4.2.1.1.2604 = INTEGER: 2604
iso.3.6.1.2.1.25.4.2.1.1.2644 = INTEGER: 2644
iso.3.6.1.2.1.25.4.2.1.1.2740 = INTEGER: 2740
iso.3.6.1.2.1.25.4.2.1.1.2896 = INTEGER: 2896
iso.3.6.1.2.1.25.4.2.1.1.3016 = INTEGER: 3016
iso.3.6.1.2.1.25.4.2.1.1.3156 = INTEGER: 3156
iso.3.6.1.2.1.25.4.2.1.1.3404 = INTEGER: 3404
iso.3.6.1.2.1.25.4.2.1.1.3604 = INTEGER: 3604
iso.3.6.1.2.1.25.4.2.1.1.3920 = INTEGER: 3920
iso.3.6.1.2.1.25.4.2.1.1.3996 = INTEGER: 3996
iso.3.6.1.2.1.25.4.2.1.1.4008 = INTEGER: 4008
iso.3.6.1.2.1.25.4.2.1.1.4728 = INTEGER: 4728
iso.3.6.1.2.1.25.4.2.1.1.4948 = INTEGER: 4948
iso.3.6.1.2.1.25.4.2.1.1.5016 = INTEGER: 5016
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.68 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.256 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.308 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.324 = STRING: "MpCmdRun.exe"
iso.3.6.1.2.1.25.4.2.1.2.400 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.480 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.492 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.572 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.592 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.624 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.704 = STRING: "fontdrvhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.712 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.728 = STRING: "fontdrvhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.816 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.824 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.908 = STRING: "dwm.exe"
iso.3.6.1.2.1.25.4.2.1.2.964 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.972 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1016 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1072 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1124 = STRING: "vmacthlp.exe"
iso.3.6.1.2.1.25.4.2.1.2.1276 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1372 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1384 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1524 = STRING: "spoolsv.exe"
iso.3.6.1.2.1.25.4.2.1.2.1612 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1696 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1704 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1728 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1788 = STRING: "SecurityHealthService.exe"
iso.3.6.1.2.1.25.4.2.1.2.1796 = STRING: "snmp.exe"
iso.3.6.1.2.1.25.4.2.1.2.1820 = STRING: "VGAuthService.exe"
iso.3.6.1.2.1.25.4.2.1.2.1828 = STRING: "vmtoolsd.exe"
iso.3.6.1.2.1.25.4.2.1.2.1840 = STRING: "ManagementAgentHost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1868 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1896 = STRING: "MsMpEng.exe"
iso.3.6.1.2.1.25.4.2.1.2.2004 = STRING: "Memory Compression"
iso.3.6.1.2.1.25.4.2.1.2.2348 = STRING: "dllhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2452 = STRING: "conhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2596 = STRING: "SearchIndexer.exe"
iso.3.6.1.2.1.25.4.2.1.2.2604 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2644 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2740 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2896 = STRING: "WmiPrvSE.exe"
iso.3.6.1.2.1.25.4.2.1.2.3016 = STRING: "LogonUI.exe"
iso.3.6.1.2.1.25.4.2.1.2.3156 = STRING: "NisSrv.exe"
iso.3.6.1.2.1.25.4.2.1.2.3404 = STRING: "msdtc.exe"
iso.3.6.1.2.1.25.4.2.1.2.3604 = STRING: "WmiPrvSE.exe"
iso.3.6.1.2.1.25.4.2.1.2.3920 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.3996 = STRING: "conhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.4008 = STRING: "MpCmdRun.exe"
iso.3.6.1.2.1.25.4.2.1.2.4728 = STRING: "SearchFilterHost.exe"
iso.3.6.1.2.1.25.4.2.1.2.4948 = STRING: "MpCmdRun.exe"
iso.3.6.1.2.1.25.4.2.1.2.5016 = STRING: "SearchProtocolHost.exe"
iso.3.6.1.2.1.25.4.2.1.3.1 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.4 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.68 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.256 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.308 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.324 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.400 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.480 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.492 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.572 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.592 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.624 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.704 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.712 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.728 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.816 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.824 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.908 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.964 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.972 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1016 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1072 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1124 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1276 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1372 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1384 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1524 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1612 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1696 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1704 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1728 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1788 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1796 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1820 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1828 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1840 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1868 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.1896 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2004 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2348 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2452 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2596 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2604 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2644 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2740 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.2896 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3016 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3156 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3404 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3604 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3920 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.3996 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.4008 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.4728 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.4948 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.3.5016 = OID: ccitt.0
iso.3.6.1.2.1.25.4.2.1.4.1 = ""
iso.3.6.1.2.1.25.4.2.1.4.4 = ""
iso.3.6.1.2.1.25.4.2.1.4.68 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.256 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.308 = ""
iso.3.6.1.2.1.25.4.2.1.4.324 = STRING: "C:\\Program Files\\Windows Defender\\"
iso.3.6.1.2.1.25.4.2.1.4.400 = ""
iso.3.6.1.2.1.25.4.2.1.4.480 = ""
iso.3.6.1.2.1.25.4.2.1.4.492 = ""
iso.3.6.1.2.1.25.4.2.1.4.572 = ""
iso.3.6.1.2.1.25.4.2.1.4.592 = ""
iso.3.6.1.2.1.25.4.2.1.4.624 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.704 = ""
iso.3.6.1.2.1.25.4.2.1.4.712 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.728 = ""
iso.3.6.1.2.1.25.4.2.1.4.816 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.824 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.908 = ""
iso.3.6.1.2.1.25.4.2.1.4.964 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.972 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1016 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1072 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1124 = STRING: "C:\\Program Files\\VMware\\VMware Tools\\"
iso.3.6.1.2.1.25.4.2.1.4.1276 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1372 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1384 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1524 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1612 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1696 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1704 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1728 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1788 = ""
iso.3.6.1.2.1.25.4.2.1.4.1796 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.1820 = STRING: "C:\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\"
iso.3.6.1.2.1.25.4.2.1.4.1828 = STRING: "C:\\Program Files\\VMware\\VMware Tools\\"
iso.3.6.1.2.1.25.4.2.1.4.1840 = STRING: "C:\\Program Files\\VMware\\VMware Tools\\VMware CAF\\pme\\bin\\"
iso.3.6.1.2.1.25.4.2.1.4.1868 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.1896 = ""
iso.3.6.1.2.1.25.4.2.1.4.2004 = ""
iso.3.6.1.2.1.25.4.2.1.4.2348 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.2452 = STRING: "\\??\\C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.2596 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.2604 = ""
iso.3.6.1.2.1.25.4.2.1.4.2644 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.2740 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.2896 = STRING: "C:\\Windows\\system32\\wbem\\"
iso.3.6.1.2.1.25.4.2.1.4.3016 = ""
iso.3.6.1.2.1.25.4.2.1.4.3156 = ""
iso.3.6.1.2.1.25.4.2.1.4.3404 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.3604 = STRING: "C:\\Windows\\system32\\wbem\\"
iso.3.6.1.2.1.25.4.2.1.4.3920 = STRING: "C:\\Windows\\System32\\"
iso.3.6.1.2.1.25.4.2.1.4.3996 = STRING: "\\??\\C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.4008 = STRING: "C:\\Program Files\\Windows Defender\\"
iso.3.6.1.2.1.25.4.2.1.4.4728 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.4.4948 = STRING: "C:\\Program Files\\Windows Defender\\"
iso.3.6.1.2.1.25.4.2.1.4.5016 = STRING: "C:\\Windows\\system32\\"
iso.3.6.1.2.1.25.4.2.1.5.1 = ""
iso.3.6.1.2.1.25.4.2.1.5.4 = ""
iso.3.6.1.2.1.25.4.2.1.5.68 = STRING: "-k LocalSystemNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.256 = STRING: "-k LocalSystemNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.308 = ""
iso.3.6.1.2.1.25.4.2.1.5.324 = STRING: " -IdleTask -TaskName WdCacheMaintenance"
iso.3.6.1.2.1.25.4.2.1.5.400 = ""
iso.3.6.1.2.1.25.4.2.1.5.480 = ""
iso.3.6.1.2.1.25.4.2.1.5.492 = ""
iso.3.6.1.2.1.25.4.2.1.5.572 = ""
iso.3.6.1.2.1.25.4.2.1.5.592 = ""
iso.3.6.1.2.1.25.4.2.1.5.624 = ""
iso.3.6.1.2.1.25.4.2.1.5.704 = ""
iso.3.6.1.2.1.25.4.2.1.5.712 = STRING: "-k DcomLaunch"
iso.3.6.1.2.1.25.4.2.1.5.728 = ""
iso.3.6.1.2.1.25.4.2.1.5.816 = STRING: "-k LocalService"
iso.3.6.1.2.1.25.4.2.1.5.824 = STRING: "-k RPCSS"
iso.3.6.1.2.1.25.4.2.1.5.908 = ""
iso.3.6.1.2.1.25.4.2.1.5.964 = STRING: "-k netsvcs"
iso.3.6.1.2.1.25.4.2.1.5.972 = STRING: "-k LocalServiceNoNetwork"
iso.3.6.1.2.1.25.4.2.1.5.1016 = STRING: "-k LocalServiceNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.1072 = STRING: "-k NetworkService"
iso.3.6.1.2.1.25.4.2.1.5.1124 = ""
iso.3.6.1.2.1.25.4.2.1.5.1276 = STRING: "-k LocalServiceNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.1372 = STRING: "-k LocalServiceNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.1384 = STRING: "-k LocalServiceNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.1524 = ""
iso.3.6.1.2.1.25.4.2.1.5.1612 = STRING: "-k appmodel"
iso.3.6.1.2.1.25.4.2.1.5.1696 = STRING: "-k apphost"
iso.3.6.1.2.1.25.4.2.1.5.1704 = STRING: "-k utcsvc"
iso.3.6.1.2.1.25.4.2.1.5.1728 = STRING: "-k ftpsvc"
iso.3.6.1.2.1.25.4.2.1.5.1788 = ""
iso.3.6.1.2.1.25.4.2.1.5.1796 = ""
iso.3.6.1.2.1.25.4.2.1.5.1820 = ""
iso.3.6.1.2.1.25.4.2.1.5.1828 = ""
iso.3.6.1.2.1.25.4.2.1.5.1840 = ""
iso.3.6.1.2.1.25.4.2.1.5.1868 = STRING: "-k iissvcs"
iso.3.6.1.2.1.25.4.2.1.5.1896 = ""
iso.3.6.1.2.1.25.4.2.1.5.2004 = ""
iso.3.6.1.2.1.25.4.2.1.5.2348 = STRING: "/Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}"
iso.3.6.1.2.1.25.4.2.1.5.2452 = STRING: "0x4"
iso.3.6.1.2.1.25.4.2.1.5.2596 = STRING: "/Embedding"
iso.3.6.1.2.1.25.4.2.1.5.2604 = ""
iso.3.6.1.2.1.25.4.2.1.5.2644 = STRING: "-k NetworkServiceNetworkRestricted"
iso.3.6.1.2.1.25.4.2.1.5.2740 = STRING: "-k LocalServiceAndNoImpersonation"
iso.3.6.1.2.1.25.4.2.1.5.2896 = ""
iso.3.6.1.2.1.25.4.2.1.5.3016 = STRING: " /flags:0x0 /state0:0xa3a04055 /state1:0x41c64e6d"
iso.3.6.1.2.1.25.4.2.1.5.3156 = ""
iso.3.6.1.2.1.25.4.2.1.5.3404 = ""
iso.3.6.1.2.1.25.4.2.1.5.3604 = ""
iso.3.6.1.2.1.25.4.2.1.5.3920 = STRING: "-k smphost"
iso.3.6.1.2.1.25.4.2.1.5.3996 = STRING: "0x4"
iso.3.6.1.2.1.25.4.2.1.5.4008 = STRING: " Scan -ScheduleJob -ScanTrigger 55"
iso.3.6.1.2.1.25.4.2.1.5.4728 = STRING: " 0 692 696 704 8192 700 "
iso.3.6.1.2.1.25.4.2.1.5.4948 = STRING: " Scan -ScheduleJob -RestrictPrivileges -ScanType 1 -ScanTrigger 59 -Reinvoke"
iso.3.6.1.2.1.25.4.2.1.5.5016 = STRING: " Global\\UsGthrFltPipeMssGthrPipe1_ Global\\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646 \"Software\\Microsoft\\Windows Search\" \"Mozil"
iso.3.6.1.2.1.25.4.2.1.6.1 = INTEGER: 2
iso.3.6.1.2.1.25.4.2.1.6.4 = INTEGER: 2
iso.3.6.1.2.1.25.4.2.1.6.68 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.256 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.308 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.324 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.400 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.480 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.492 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.572 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.592 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.624 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.704 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.712 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.728 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.816 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.824 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.908 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.964 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.972 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1016 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1072 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1124 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1276 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1372 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1384 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1524 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1612 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1696 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1704 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1728 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1788 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1796 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1820 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1828 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1840 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1868 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.1896 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2004 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2348 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2452 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2596 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2604 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2644 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2740 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.2896 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3016 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3156 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3404 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3604 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3920 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.3996 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.4008 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.4728 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.4948 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.6.5016 = INTEGER: 4
iso.3.6.1.2.1.25.4.2.1.7.1 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.4 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.68 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.256 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.308 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.324 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.400 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.480 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.492 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.572 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.592 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.624 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.704 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.712 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.728 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.816 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.824 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.908 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.964 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.972 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1016 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1072 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1124 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1276 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1372 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1384 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1524 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1612 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1696 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1704 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1728 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1788 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1796 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1820 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1828 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1840 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1868 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.1896 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2004 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2348 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2452 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2596 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2604 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2644 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2740 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.2896 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3016 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3156 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3404 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3604 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3920 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.3996 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.4008 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.4728 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.4948 = INTEGER: 1
iso.3.6.1.2.1.25.4.2.1.7.5016 = INTEGER: 1
iso.3.6.1.2.1.25.5.1.1.1.1 = INTEGER: 129976
iso.3.6.1.2.1.25.5.1.1.1.4 = INTEGER: 12907
iso.3.6.1.2.1.25.5.1.1.1.68 = INTEGER: 351
iso.3.6.1.2.1.25.5.1.1.1.256 = INTEGER: 1
iso.3.6.1.2.1.25.5.1.1.1.308 = INTEGER: 65
iso.3.6.1.2.1.25.5.1.1.1.324 = INTEGER: 3
iso.3.6.1.2.1.25.5.1.1.1.400 = INTEGER: 243
iso.3.6.1.2.1.25.5.1.1.1.480 = INTEGER: 23
iso.3.6.1.2.1.25.5.1.1.1.492 = INTEGER: 143
iso.3.6.1.2.1.25.5.1.1.1.572 = INTEGER: 412
iso.3.6.1.2.1.25.5.1.1.1.592 = INTEGER: 195
iso.3.6.1.2.1.25.5.1.1.1.624 = INTEGER: 285
iso.3.6.1.2.1.25.5.1.1.1.704 = INTEGER: 28
iso.3.6.1.2.1.25.5.1.1.1.712 = INTEGER: 173
iso.3.6.1.2.1.25.5.1.1.1.728 = INTEGER: 6
iso.3.6.1.2.1.25.5.1.1.1.816 = INTEGER: 396
iso.3.6.1.2.1.25.5.1.1.1.824 = INTEGER: 489
iso.3.6.1.2.1.25.5.1.1.1.908 = INTEGER: 2003
iso.3.6.1.2.1.25.5.1.1.1.964 = INTEGER: 2957
iso.3.6.1.2.1.25.5.1.1.1.972 = INTEGER: 2495
iso.3.6.1.2.1.25.5.1.1.1.1016 = INTEGER: 429
iso.3.6.1.2.1.25.5.1.1.1.1072 = INTEGER: 650
iso.3.6.1.2.1.25.5.1.1.1.1124 = INTEGER: 3
iso.3.6.1.2.1.25.5.1.1.1.1276 = INTEGER: 6
iso.3.6.1.2.1.25.5.1.1.1.1372 = INTEGER: 21
iso.3.6.1.2.1.25.5.1.1.1.1384 = INTEGER: 17
iso.3.6.1.2.1.25.5.1.1.1.1524 = INTEGER: 59
iso.3.6.1.2.1.25.5.1.1.1.1612 = INTEGER: 60
iso.3.6.1.2.1.25.5.1.1.1.1696 = INTEGER: 50
iso.3.6.1.2.1.25.5.1.1.1.1704 = INTEGER: 114
iso.3.6.1.2.1.25.5.1.1.1.1728 = INTEGER: 71
iso.3.6.1.2.1.25.5.1.1.1.1788 = INTEGER: 45
iso.3.6.1.2.1.25.5.1.1.1.1796 = INTEGER: 3690
iso.3.6.1.2.1.25.5.1.1.1.1820 = INTEGER: 25
iso.3.6.1.2.1.25.5.1.1.1.1828 = INTEGER: 3126
iso.3.6.1.2.1.25.5.1.1.1.1840 = INTEGER: 5073
iso.3.6.1.2.1.25.5.1.1.1.1868 = INTEGER: 73
iso.3.6.1.2.1.25.5.1.1.1.1896 = INTEGER: 23767
iso.3.6.1.2.1.25.5.1.1.1.2004 = INTEGER: 498
iso.3.6.1.2.1.25.5.1.1.1.2348 = INTEGER: 175
iso.3.6.1.2.1.25.5.1.1.1.2452 = INTEGER: 1618
iso.3.6.1.2.1.25.5.1.1.1.2596 = INTEGER: 318
iso.3.6.1.2.1.25.5.1.1.1.2604 = INTEGER: 42
iso.3.6.1.2.1.25.5.1.1.1.2644 = INTEGER: 12
iso.3.6.1.2.1.25.5.1.1.1.2740 = INTEGER: 9
iso.3.6.1.2.1.25.5.1.1.1.2896 = INTEGER: 359
iso.3.6.1.2.1.25.5.1.1.1.3016 = INTEGER: 379
iso.3.6.1.2.1.25.5.1.1.1.3156 = INTEGER: 257
iso.3.6.1.2.1.25.5.1.1.1.3388 = INTEGER: 15
iso.3.6.1.2.1.25.5.1.1.1.3404 = INTEGER: 345
iso.3.6.1.2.1.25.5.1.1.1.3604 = INTEGER: 785
iso.3.6.1.2.1.25.5.1.1.1.3920 = INTEGER: 9
iso.3.6.1.2.1.25.5.1.1.1.3996 = INTEGER: 1426
iso.3.6.1.2.1.25.5.1.1.1.4008 = INTEGER: 70
iso.3.6.1.2.1.25.5.1.1.1.4948 = INTEGER: 3
iso.3.6.1.2.1.25.5.1.1.1.5116 = INTEGER: 1
iso.3.6.1.2.1.25.5.1.1.2.1 = INTEGER: 8
iso.3.6.1.2.1.25.5.1.1.2.4 = INTEGER: 124
iso.3.6.1.2.1.25.5.1.1.2.68 = INTEGER: 16224
iso.3.6.1.2.1.25.5.1.1.2.256 = INTEGER: 5908
iso.3.6.1.2.1.25.5.1.1.2.308 = INTEGER: 900
iso.3.6.1.2.1.25.5.1.1.2.324 = INTEGER: 2016
iso.3.6.1.2.1.25.5.1.1.2.400 = INTEGER: 3936
iso.3.6.1.2.1.25.5.1.1.2.480 = INTEGER: 5680
iso.3.6.1.2.1.25.5.1.1.2.492 = INTEGER: 3560
iso.3.6.1.2.1.25.5.1.1.2.572 = INTEGER: 18240
iso.3.6.1.2.1.25.5.1.1.2.592 = INTEGER: 6360
iso.3.6.1.2.1.25.5.1.1.2.624 = INTEGER: 9832
iso.3.6.1.2.1.25.5.1.1.2.704 = INTEGER: 3100
iso.3.6.1.2.1.25.5.1.1.2.712 = INTEGER: 13172
iso.3.6.1.2.1.25.5.1.1.2.728 = INTEGER: 3500
iso.3.6.1.2.1.25.5.1.1.2.816 = INTEGER: 22820
iso.3.6.1.2.1.25.5.1.1.2.824 = INTEGER: 9292
iso.3.6.1.2.1.25.5.1.1.2.908 = INTEGER: 21424
iso.3.6.1.2.1.25.5.1.1.2.964 = INTEGER: 46596
iso.3.6.1.2.1.25.5.1.1.2.972 = INTEGER: 21344
iso.3.6.1.2.1.25.5.1.1.2.1016 = INTEGER: 16036
iso.3.6.1.2.1.25.5.1.1.2.1072 = INTEGER: 14356
iso.3.6.1.2.1.25.5.1.1.2.1124 = INTEGER: 5628
iso.3.6.1.2.1.25.5.1.1.2.1276 = INTEGER: 6808
iso.3.6.1.2.1.25.5.1.1.2.1372 = INTEGER: 6464
iso.3.6.1.2.1.25.5.1.1.2.1384 = INTEGER: 5436
iso.3.6.1.2.1.25.5.1.1.2.1524 = INTEGER: 12720
iso.3.6.1.2.1.25.5.1.1.2.1612 = INTEGER: 12680
iso.3.6.1.2.1.25.5.1.1.2.1696 = INTEGER: 8328
iso.3.6.1.2.1.25.5.1.1.2.1704 = INTEGER: 16500
iso.3.6.1.2.1.25.5.1.1.2.1728 = INTEGER: 8744
iso.3.6.1.2.1.25.5.1.1.2.1788 = INTEGER: 11868
iso.3.6.1.2.1.25.5.1.1.2.1796 = INTEGER: 7564
iso.3.6.1.2.1.25.5.1.1.2.1820 = INTEGER: 7204
iso.3.6.1.2.1.25.5.1.1.2.1828 = INTEGER: 15572
iso.3.6.1.2.1.25.5.1.1.2.1840 = INTEGER: 7748
iso.3.6.1.2.1.25.5.1.1.2.1868 = INTEGER: 8692
iso.3.6.1.2.1.25.5.1.1.2.1896 = INTEGER: 87612
iso.3.6.1.2.1.25.5.1.1.2.2004 = INTEGER: 24752
iso.3.6.1.2.1.25.5.1.1.2.2348 = INTEGER: 10048
iso.3.6.1.2.1.25.5.1.1.2.2452 = INTEGER: 1980
iso.3.6.1.2.1.25.5.1.1.2.2596 = INTEGER: 16892
iso.3.6.1.2.1.25.5.1.1.2.2604 = INTEGER: 6472
iso.3.6.1.2.1.25.5.1.1.2.2644 = INTEGER: 6452
iso.3.6.1.2.1.25.5.1.1.2.2740 = INTEGER: 7384
iso.3.6.1.2.1.25.5.1.1.2.2896 = INTEGER: 17116
iso.3.6.1.2.1.25.5.1.1.2.3016 = INTEGER: 54512
iso.3.6.1.2.1.25.5.1.1.2.3156 = INTEGER: 1996
iso.3.6.1.2.1.25.5.1.1.2.3388 = INTEGER: 11836
iso.3.6.1.2.1.25.5.1.1.2.3404 = INTEGER: 8072
iso.3.6.1.2.1.25.5.1.1.2.3604 = INTEGER: 19228
iso.3.6.1.2.1.25.5.1.1.2.3920 = INTEGER: 13320
iso.3.6.1.2.1.25.5.1.1.2.3996 = INTEGER: 1992
iso.3.6.1.2.1.25.5.1.1.2.4008 = INTEGER: 2124
iso.3.6.1.2.1.25.5.1.1.2.4948 = INTEGER: 6196
iso.3.6.1.2.1.25.5.1.1.2.5116 = INTEGER: 6396
iso.3.6.1.2.1.25.6.1.0 = Timeticks: (122551) 0:20:25.51
iso.3.6.1.2.1.25.6.2.0 = Timeticks: (122589) 0:20:25.89
iso.3.6.1.2.1.25.6.3.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.25.6.3.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.25.6.3.1.1.3 = INTEGER: 3
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161"
iso.3.6.1.2.1.25.6.3.1.3.1 = OID: ccitt.0
iso.3.6.1.2.1.25.6.3.1.3.2 = OID: ccitt.0
iso.3.6.1.2.1.25.6.3.1.3.3 = OID: ccitt.0
iso.3.6.1.2.1.25.6.3.1.4.1 = INTEGER: 4
iso.3.6.1.2.1.25.6.3.1.4.2 = INTEGER: 4
iso.3.6.1.2.1.25.6.3.1.4.3 = INTEGER: 4
iso.3.6.1.2.1.25.6.3.1.5.1 = Hex-STRING: 07 E2 0A 0C 14 0A 1E 00 
iso.3.6.1.2.1.25.6.3.1.5.2 = Hex-STRING: 07 E2 0A 0C 14 0B 02 00 
iso.3.6.1.2.1.25.6.3.1.5.3 = Hex-STRING: 07 E2 0A 0C 14 0A 16 00 
iso.3.6.1.2.1.31.1.1.1.1.1 = STRING: "loopback_0"
iso.3.6.1.2.1.31.1.1.1.1.2 = STRING: "tunnel_32769"
iso.3.6.1.2.1.31.1.1.1.1.3 = STRING: "tunnel_32771"
iso.3.6.1.2.1.31.1.1.1.1.4 = STRING: "ethernet_32768"
iso.3.6.1.2.1.31.1.1.1.1.5 = STRING: "tunnel_32770"
iso.3.6.1.2.1.31.1.1.1.1.6 = STRING: "tunnel_32772"
iso.3.6.1.2.1.31.1.1.1.1.7 = STRING: "ethernet_32770"
iso.3.6.1.2.1.31.1.1.1.1.8 = STRING: "tunnel_32768"
iso.3.6.1.2.1.31.1.1.1.1.9 = STRING: "ethernet_32771"
iso.3.6.1.2.1.31.1.1.1.1.10 = STRING: "ethernet_32769"
iso.3.6.1.2.1.31.1.1.1.1.11 = STRING: "ppp_32768"
iso.3.6.1.2.1.31.1.1.1.1.12 = STRING: "ethernet_32772"
iso.3.6.1.2.1.31.1.1.1.1.13 = STRING: "ethernet_0"
iso.3.6.1.2.1.31.1.1.1.1.14 = STRING: "ethernet_1"
iso.3.6.1.2.1.31.1.1.1.1.15 = STRING: "ethernet_2"
iso.3.6.1.2.1.31.1.1.1.2.1 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.2 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.3 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.4 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.5 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.6 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.7 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.8 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.9 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.10 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.11 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.12 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.13 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.14 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.2.15 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.1 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.2 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.3 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.4 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.5 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.6 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.7 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.8 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.9 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.10 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.11 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.12 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.13 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.14 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.3.15 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.1 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.2 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.3 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.4 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.5 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.6 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.7 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.8 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.9 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.10 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.11 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.12 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.13 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.14 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.4.15 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.1 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.2 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.3 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.4 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.5 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.6 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.7 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.8 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.9 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.10 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.11 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.12 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.13 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.14 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.5.15 = Counter32: 0
iso.3.6.1.2.1.31.1.1.1.14.1 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.2 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.3 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.4 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.5 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.6 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.7 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.8 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.9 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.10 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.11 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.12 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.13 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.14 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.14.15 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.15.1 = Gauge32: 1073
iso.3.6.1.2.1.31.1.1.1.15.2 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.3 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.4 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.5 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.6 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.7 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.8 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.9 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.10 = Gauge32: 1000
iso.3.6.1.2.1.31.1.1.1.15.11 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.12 = Gauge32: 0
iso.3.6.1.2.1.31.1.1.1.15.13 = Gauge32: 1000
iso.3.6.1.2.1.31.1.1.1.15.14 = Gauge32: 1000
iso.3.6.1.2.1.31.1.1.1.15.15 = Gauge32: 1000
iso.3.6.1.2.1.31.1.1.1.16.1 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.2 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.3 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.4 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.5 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.6 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.7 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.8 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.9 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.10 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.11 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.12 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.13 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.14 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.16.15 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.1 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.2 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.3 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.4 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.5 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.6 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.7 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.8 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.9 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.10 = INTEGER: 1
iso.3.6.1.2.1.31.1.1.1.17.11 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.12 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.13 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.14 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.17.15 = INTEGER: 2
iso.3.6.1.2.1.31.1.1.1.18.1 = STRING: "Loopback Pseudo-Interface 1"
iso.3.6.1.2.1.31.1.1.1.18.2 = STRING: "Local Area Connection* 2"
iso.3.6.1.2.1.31.1.1.1.18.3 = STRING: "Local Area Connection* 4"
iso.3.6.1.2.1.31.1.1.1.18.4 = STRING: "Ethernet (Kernel Debugger)"
iso.3.6.1.2.1.31.1.1.1.18.5 = STRING: "Local Area Connection* 3"
iso.3.6.1.2.1.31.1.1.1.18.6 = STRING: "Teredo Tunneling Pseudo-Interface"
iso.3.6.1.2.1.31.1.1.1.18.7 = STRING: "Local Area Connection* 6"
iso.3.6.1.2.1.31.1.1.1.18.8 = STRING: "Local Area Connection* 1"
iso.3.6.1.2.1.31.1.1.1.18.9 = STRING: "Local Area Connection* 7"
iso.3.6.1.2.1.31.1.1.1.18.10 = STRING: "Ethernet0"
iso.3.6.1.2.1.31.1.1.1.18.11 = STRING: "Local Area Connection* 5"
iso.3.6.1.2.1.31.1.1.1.18.12 = STRING: "Local Area Connection* 8"
iso.3.6.1.2.1.31.1.1.1.18.13 = STRING: "Ethernet0-WFP Native MAC Layer LightWeight Filter-0000"
iso.3.6.1.2.1.31.1.1.1.18.14 = STRING: "Ethernet0-QoS Packet Scheduler-0000"
iso.3.6.1.2.1.31.1.1.1.18.15 = STRING: "Ethernet0-WFP 802.3 MAC Layer LightWeight Filter-0000"
iso.3.6.1.2.1.31.1.1.1.19.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.5 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.6 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.7 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.8 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.9 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.11 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.12 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.13 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.14 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.1.1.19.15 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.5.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.31.1.6.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.1.0 = INTEGER: 2
iso.3.6.1.2.1.55.1.2.0 = INTEGER: 128
iso.3.6.1.2.1.55.1.3.0 = Gauge32: 2
iso.3.6.1.2.1.55.1.4.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.5.1.2.1 = STRING: "Software Loopback Interface 1"
iso.3.6.1.2.1.55.1.5.1.2.10 = STRING: "Intel(R) 82574L Gigabit Network Connection"
iso.3.6.1.2.1.55.1.5.1.3.1 = OID: ccitt.0
iso.3.6.1.2.1.55.1.5.1.3.10 = OID: ccitt.0
iso.3.6.1.2.1.55.1.5.1.4.1 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.5.1.4.10 = Gauge32: 1500
iso.3.6.1.2.1.55.1.5.1.5.1 = Gauge32: 65535
iso.3.6.1.2.1.55.1.5.1.5.10 = Gauge32: 65535
iso.3.6.1.2.1.55.1.5.1.6.1 = ""
iso.3.6.1.2.1.55.1.5.1.6.10 = ""
iso.3.6.1.2.1.55.1.5.1.7.1 = INTEGER: 0
iso.3.6.1.2.1.55.1.5.1.7.10 = INTEGER: 0
iso.3.6.1.2.1.55.1.5.1.8.1 = ""
iso.3.6.1.2.1.55.1.5.1.8.10 = Hex-STRING: 00 50 56 B9 03 7B 
iso.3.6.1.2.1.55.1.5.1.9.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.5.1.9.10 = INTEGER: 1
iso.3.6.1.2.1.55.1.5.1.10.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.5.1.10.10 = INTEGER: 1
iso.3.6.1.2.1.55.1.5.1.11.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.5.1.11.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.6.1.1.0 = Counter32: 155
iso.3.6.1.2.1.55.1.6.1.2.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.3.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.4.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.5.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.6.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.7.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.8.0 = Counter32: 6
iso.3.6.1.2.1.55.1.6.1.9.0 = Counter32: 158
iso.3.6.1.2.1.55.1.6.1.10.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.11.0 = Counter32: 34
iso.3.6.1.2.1.55.1.6.1.12.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.13.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.14.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.15.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.16.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.17.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.18.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.19.0 = Counter32: 0
iso.3.6.1.2.1.55.1.6.1.20.0 = Counter32: 0
iso.3.6.1.2.1.55.1.7.1.3.1.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.3.10.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.3.10.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.3.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.4.1.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.4.10.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.4.10.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.4.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = INTEGER: 1
iso.3.6.1.2.1.55.1.7.1.5.1.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.7.1.5.10.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64 = Gauge32: 86358
iso.3.6.1.2.1.55.1.7.1.5.10.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.7.1.5.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.7.1.6.1.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.7.1.6.10.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64 = Gauge32: 86358
iso.3.6.1.2.1.55.1.7.1.6.10.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.7.1.6.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8 = Gauge32: 4294967295
iso.3.6.1.2.1.55.1.8.1.2.1.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 64
iso.3.6.1.2.1.55.1.8.1.2.10.16.222.173.190.239.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 64
iso.3.6.1.2.1.55.1.8.1.2.10.16.222.173.190.239.0.0.0.0.61.80.88.106.127.119.11.142 = INTEGER: 64
iso.3.6.1.2.1.55.1.8.1.2.10.16.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 64
iso.3.6.1.2.1.55.1.8.1.3.1.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.3.10.16.222.173.190.239.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.3.10.16.222.173.190.239.0.0.0.0.61.80.88.106.127.119.11.142 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.3.10.16.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.4.1.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.55.1.8.1.4.10.16.222.173.190.239.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 2
iso.3.6.1.2.1.55.1.8.1.4.10.16.222.173.190.239.0.0.0.0.61.80.88.106.127.119.11.142 = INTEGER: 2
iso.3.6.1.2.1.55.1.8.1.4.10.16.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 2
iso.3.6.1.2.1.55.1.8.1.5.1.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.5.10.16.222.173.190.239.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.5.10.16.222.173.190.239.0.0.0.0.61.80.88.106.127.119.11.142 = INTEGER: 1
iso.3.6.1.2.1.55.1.8.1.5.10.16.254.128.0.0.0.0.0.0.1.187.175.149.48.255.99.20 = INTEGER: 1
iso.3.6.1.2.1.55.1.9.0 = Gauge32: 8
iso.3.6.1.2.1.55.1.10.0 = Counter32: 0
iso.3.6.1.2.1.55.1.11.1.4.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 10
iso.3.6.1.2.1.55.1.11.1.4.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = INTEGER: 10
iso.3.6.1.2.1.55.1.11.1.4.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = INTEGER: 10
iso.3.6.1.2.1.55.1.11.1.4.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = INTEGER: 1
iso.3.6.1.2.1.55.1.11.1.4.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = INTEGER: 10
iso.3.6.1.2.1.55.1.11.1.5.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Hex-STRING: FE 80 00 00 00 00 00 00 02 50 56 FF FE B9 95 03 
iso.3.6.1.2.1.55.1.11.1.5.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = Hex-STRING: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
iso.3.6.1.2.1.55.1.11.1.5.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = Hex-STRING: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
iso.3.6.1.2.1.55.1.11.1.5.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = Hex-STRING: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
iso.3.6.1.2.1.55.1.11.1.5.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = Hex-STRING: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
iso.3.6.1.2.1.55.1.11.1.6.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 4
iso.3.6.1.2.1.55.1.11.1.6.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.6.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.6.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.6.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.7.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.7.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = INTEGER: 3
iso.3.6.1.2.1.55.1.11.1.7.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = INTEGER: 2
iso.3.6.1.2.1.55.1.11.1.7.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = INTEGER: 2
iso.3.6.1.2.1.55.1.11.1.7.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = INTEGER: 2
iso.3.6.1.2.1.55.1.11.1.8.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 0
iso.3.6.1.2.1.55.1.11.1.8.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = INTEGER: 0
iso.3.6.1.2.1.55.1.11.1.8.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = INTEGER: 0
iso.3.6.1.2.1.55.1.11.1.8.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = INTEGER: 0
iso.3.6.1.2.1.55.1.11.1.8.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = INTEGER: 0
iso.3.6.1.2.1.55.1.11.1.9.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.9.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.9.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.9.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.9.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.10.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.10.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.10.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.10.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.11.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Gauge32: 256
iso.3.6.1.2.1.55.1.11.1.11.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = Gauge32: 256
iso.3.6.1.2.1.55.1.11.1.11.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = Gauge32: 256
iso.3.6.1.2.1.55.1.11.1.11.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = Gauge32: 256
iso.3.6.1.2.1.55.1.11.1.11.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = Gauge32: 256
iso.3.6.1.2.1.55.1.11.1.12.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.12.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.12.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.12.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.12.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = Gauge32: 0
iso.3.6.1.2.1.55.1.11.1.13.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = OID: ccitt.0
iso.3.6.1.2.1.55.1.11.1.13.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = OID: ccitt.0
iso.3.6.1.2.1.55.1.11.1.13.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = OID: ccitt.0
iso.3.6.1.2.1.55.1.11.1.13.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = OID: ccitt.0
iso.3.6.1.2.1.55.1.11.1.13.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = OID: ccitt.0
iso.3.6.1.2.1.55.1.11.1.14.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.11.1.14.16.222.173.190.239.0.0.0.0.0.0.0.0.0.0.0.0.64.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.11.1.14.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.0.64.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.11.1.14.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.4 = INTEGER: 1
iso.3.6.1.2.1.55.1.11.1.14.16.255.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.2.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = ""
iso.3.6.1.2.1.55.1.12.1.2.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = ""
iso.3.6.1.2.1.55.1.12.1.2.10.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.149.3 = Hex-STRING: 00 50 56 B9 95 03 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Hex-STRING: 33 33 00 00 00 01 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 33 33 00 00 00 02 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = Hex-STRING: 33 33 00 00 00 16 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = Hex-STRING: 33 33 00 01 00 02 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.3 = Hex-STRING: 33 33 00 01 00 03 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.119.11.142 = Hex-STRING: 33 33 FF 77 0B 8E 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.185.149.3 = Hex-STRING: 33 33 FF B9 95 03 
iso.3.6.1.2.1.55.1.12.1.2.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.255.99.20 = Hex-STRING: 33 33 FF FF 63 14 
iso.3.6.1.2.1.55.1.12.1.3.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.149.3 = INTEGER: 2
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.2 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.3 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.119.11.142 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.185.149.3 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.3.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.255.99.20 = INTEGER: 3
iso.3.6.1.2.1.55.1.12.1.4.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.149.3 = INTEGER: 2
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.119.11.142 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.185.149.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.4.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.255.99.20 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.5.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.149.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.119.11.142 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.185.149.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.5.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.255.99.20 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.55.1.12.1.6.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.1.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.149.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.22 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.2 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.0.0.1.0.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.119.11.142 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.185.149.3 = INTEGER: 1
iso.3.6.1.2.1.55.1.12.1.6.10.16.255.2.0.0.0.0.0.0.0.0.0.1.255.255.99.20 = INTEGER: 1
```

Temos algumas informacoes importantes

```
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
iso.3.6.1.2.1.25.3.2.1.3.7 = STRING: "WAN Miniport (IKEv2)"
```

Coontinuandoo

```
# Nmap 7.80 scan initiated Fri Jul  3 15:37:33 2020 as: nmap -vv --reason -Pn -sU -sV -p 161 "--script=banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /root/HTB-Windows/conceal/results/10.10.10.116/scans/udp_161_snmp-nmap.txt -oX /root/HTB-Windows/conceal/results/10.10.10.116/scans/xml/udp_161_snmp_nmap.xml 10.10.10.116
Nmap scan report for 10.10.10.116
Host is up, received user-set.
Scanned at 2020-07-03 15:37:34 EDT for 58s

PORT    STATE SERVICE REASON       VERSION
161/udp open  snmp    udp-response SNMPv1 server (public)
| snmp-interfaces: 
|   Software Loopback Interface 1\x00
|     Type: softwareLoopback  Speed: 1 Gbps
|   WAN Miniport (IKEv2)\x00
|     Type: tunnel  Speed: 0 Kbps
|   WAN Miniport (PPTP)\x00
|     Type: tunnel  Speed: 0 Kbps
|   Microsoft Kernel Debug Network Adapter\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|   WAN Miniport (L2TP)\x00
|     Type: tunnel  Speed: 0 Kbps
|   Teredo Tunneling Pseudo-Interface\x00
|     MAC address: Unknown
|     Type: tunnel  Speed: 0 Kbps
|   WAN Miniport (IP)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|   WAN Miniport (SSTP)\x00
|     Type: tunnel  Speed: 0 Kbps
|   WAN Miniport (IPv6)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|   Intel(R) 82574L Gigabit Network Connection\x00
|     MAC address: 00:50:56:b9:03:7b (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|   WAN Miniport (PPPOE)\x00
|     Type: ppp  Speed: 0 Kbps
|   WAN Miniport (Network Monitor)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|   Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b9:03:7b (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|   Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000\x00
|     MAC address: 00:50:56:b9:03:7b (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|   Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b9:03:7b (VMware)
|_    Type: ethernetCsmacd  Speed: 1 Gbps
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  0.0.0.0:60400        *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:50906   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:50907      *:*
| snmp-processes: 
|   1: 
|     Name: System Idle Process
|   4: 
|     Name: System
|   68: 
|     Name: svchost.exe
|   256: 
|     Name: svchost.exe
|   308: 
|     Name: smss.exe
|   324: 
|     Name: MpCmdRun.exe
|   400: 
|     Name: csrss.exe
|   480: 
|     Name: wininit.exe
|   492: 
|     Name: csrss.exe
|   572: 
|     Name: winlogon.exe
|   592: 
|     Name: services.exe
|   624: 
|     Name: lsass.exe
|   680: 
|     Name: ngentask.exe
|   704: 
|     Name: fontdrvhost.exe
|   712: 
|     Name: svchost.exe
|   728: 
|     Name: fontdrvhost.exe
|   816: 
|     Name: svchost.exe
|   824: 
|     Name: svchost.exe
|   908: 
|     Name: dwm.exe
|   964: 
|     Name: svchost.exe
|   972: 
|     Name: svchost.exe
|   984: 
|     Name: taskhostw.exe
|   1016: 
|     Name: svchost.exe
|   1072: 
|     Name: svchost.exe
|   1124: 
|     Name: vmacthlp.exe
|   1276: 
|     Name: svchost.exe
|   1372: 
|     Name: svchost.exe
|   1384: 
|     Name: svchost.exe
|   1404: 
|     Name: taskhostw.exe
|   1524: 
|     Name: spoolsv.exe
|   1540: 
|     Name: svchost.exe
|   1612: 
|     Name: svchost.exe
|   1696: 
|     Name: svchost.exe
|   1704: 
|     Name: svchost.exe
|   1728: 
|     Name: svchost.exe
|   1788: 
|     Name: SecurityHealthService.exe
|   1796: 
| 
|   1820: 
| 
|   1828: 
| 
|   1840: 
| 
|   1868: 
| 
|   1896: 
| 
|   2004: 
| 
|   2348: 
| 
|   2452: 
| 
|   2596: 
| 
|   2644: 
| 
|   2740: 
| 
|   2784: 
| 
|   2896: 
| 
|   3012: 
| 
|   3016: 
| 
|   3156: 
| 
|   3404: 
| 
|   3604: 
| 
|   3692: 
| 
|   3900: 
| 
|   3920: 
| 
|   3932: 
| 
|   3996: 
| 
|   4008: 
| 
|   4140: 
| 
|   4180: 
| 
|   4260: 
| 
|   4332: 
| 
|_  4948: 
| snmp-sysdescr: Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
|_  System uptime: 12m23.95s (74395 timeticks)
| snmp-win32-services: 
|   AppX Deployment Service (AppXSVC)
|   Application Host Helper Service
|   Background Intelligent Transfer Service
|   Background Tasks Infrastructure Service
|   Base Filtering Engine
|   CNG Key Isolation
|   COM+ Event System
|   COM+ System Application
|   Client License Service (ClipSVC)
|   Connected Devices Platform Service
|   Connected User Experiences and Telemetry
|   CoreMessaging
|   Cryptographic Services
|   DCOM Server Process Launcher
|   DHCP Client
|   DNS Client
|   Data Sharing Service
|   Data Usage
|   Device Setup Manager
|   Diagnostic Policy Service
|   Diagnostic Service Host
|   Diagnostic System Host
|   Distributed Link Tracking Client
|   Distributed Transaction Coordinator
|   Geolocation Service
|   Group Policy Client
|   IKE and AuthIP IPsec Keying Modules
|   IP Helper
|   IPsec Policy Agent
|   Local Session Manager
|   Microsoft Account Sign-in Assistant
|   Microsoft FTP Service
|   Microsoft Storage Spaces SMP
|   Network Connection Broker
|   Network List Service
|   Network Location Awareness
|   Network Store Interface Service
|   Optimise drives
|   Plug and Play
|   Power
|   Print Spooler
|   Program Compatibility Assistant Service
|   RPC Endpoint Mapper
|   Remote Procedure Call (RPC)
|   SNMP Service
|   SSDP Discovery
|   Security Accounts Manager
|   Security Center
|   Server
|   Shell Hardware Detection
|   State Repository Service
|   Storage Service
|   Superfetch
|   System Event Notification Service
|   System Events Broker
|   TCP/IP NetBIOS Helper
|   Task Scheduler
|   Themes
|   Time Broker
|   TokenBroker
|   User Manager
|   User Profile Service
|   VMware Alias Manager and Ticket Service
|   VMware CAF Management Agent Service
|   VMware Physical Disk Helper Service
|   VMware Tools
|   WinHTTP Web Proxy Auto-Discovery Service
|   Windows Audio
|   Windows Audio Endpoint Builder
|   Windows Connection Manager
|   Windows Defender Antivirus Network Inspection Service
|   Windows Defender Antivirus Service
|   Windows Defender Security Centre Service
|   Windows Driver Foundation - User-mode Driver Framework
|   Windows Event Log
|   Windows Firewall
|   Windows Font Cache Service
|   Windows Management Instrumentation
|   Windows Process Activation Service
|   Windows Push Notifications System Service
|   Windows Search
|   Windows Time
|   Windows Update
|   Workstation
|_  World Wide Web Publishing Service
| snmp-win32-software: 
|   Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161; 2018-10-12T20:10:30
|   Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161; 2018-10-12T20:10:22
|_  VMware Tools; 2018-10-12T20:11:02
| snmp-win32-users: 
|   Administrator
|   DefaultAccount
|   Destitute
|_  Guest
Service Info: Host: Conceal

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  3 15:38:32 2020 -- 1 IP address (1 host up) scanned in 58.42 seconds
```

Crackeando a hash encontrada referente ao password da VPN

9C8B1A372B1878851BE2C097031B6E43:Dudecake1!

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/6.jpg)

voltmamos, depois de passar horas lendo a documentacao consegui estabelecer a conexao corretamente..

***resource***

https://wiki.strongswan.org/projects/strongswan/wiki/ConnSection

https://wiki.strongswan.org/issues/778

https://ubuntuforums.org/archive/index.php/t-2387199.html

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/7.jpg)


minha config  

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-conceal/8.jpg)

ipsec.conf
```
# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

config setup
	# strictcrlpolicy=yes
	# uniqueids = no

# Add connections here.

# Sample VPN connections

#conn sample-self-signed
#      leftsubnet=10.1.0.0/16
#      leftcert=selfCert.der
#      leftsendcert=never
#      right=192.168.0.2
#      rightsubnet=10.2.0.0/16
#      rightcert=peerCert.der
#      auto=start

#conn sample-with-ca-cert
#      leftsubnet=10.1.0.0/16
#      leftcert=myCert.pem
#      right=192.168.0.2
#      rightsubnet=10.2.0.0/16
#      rightid="C=CH, O=Linux strongSwan CN=peer name"
#      auto=start
#

conn Conceal
	authby=psk
	keyexchange=ikev1
	auto=route
	type=transport
	ike=3des-sha1-modp1024!
	left=10.10.14.37
        right=10.10.10.116
	rightsubnet=10.10.10.116[tcp]
	esp=3des-sha1!
 
```

ipsec.secrets

```
# This file holds shared secrets or RSA private keys for authentication.

# RSA private key for this host, authenticating it to any other host
# which knows the public part.

10.10.10.116 : PSK "Dudecake1!"

```

Depois que estabelecemos a conexao, voltamos a enumerar novamente
