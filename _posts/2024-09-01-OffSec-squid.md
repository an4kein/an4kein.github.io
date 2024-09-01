---
title:     "OffSec Proving Grounds - Squid"
tags: [Windows,easy,OffSec,phpmyadmin]
categories: OffSecProvingGrounds
---

## Enumeration

A primeira etapa do processo de exploração começou com a enumeração da máquina alvo utilizando o **Nmap**. Inicialmente, foi realizado um **scan de portas completo** para identificar todos os serviços em execução na máquina **Squid**. 

```
nmap -T4 -p- -v squid -oN nmap-all-ports.log
```

Esse comando varreu todas as portas (0-65535) com a finalidade de descobrir quais estavam abertas, salvando os resultados no arquivo `nmap-all-ports.log` para análise posterior.

Após identificar as portas em uso, foi executado um **scan mais detalhado** nas portas mais relevantes, focando na detecção de versões e nos scripts padrões do Nmap. 

```
sudo nmap -T4 -sCV -p135,139,445,3128,49666,49667 squid -oN enu/nmap-services.log
```

Este segundo scan permitiu coletar mais informações sobre os serviços específicos rodando nas portas identificadas: **135, 139, 445, 3128, 49666, 49667**. Os resultados detalhados foram armazenados em `enu/nmap-services.log`, servindo como base para as próximas etapas de exploração.

### Enumeração através do Proxy Squid

Após a enumeração inicial das portas e serviços, identifiquei que a porta **3128** estava associada ao serviço **Squid**, um proxy bastante utilizado. Para explorar mais a fundo os serviços acessíveis através desse proxy, utilizei a ferramenta **Squid Pivoting Open Port Scanner (spose.py)**, que é particularmente eficaz em cenários de **CTF** e em testes de penetração, onde o objetivo é detectar portas abertas por trás de um proxy Squid.

```
python3 spose.py --proxy http://squid:3128 --target 192.168.185.189
```

Com esse comando, a **spose.py** foi configurada para usar o proxy **Squid** (acessível via porta **3128**) para escanear as portas abertas no alvo **192.168.185.189**. Essa técnica permitiu realizar a enumeração de portas através do proxy, oferecendo uma visão mais completa das portas e serviços que poderiam ser explorados posteriormente.

A **spose.py** é uma ferramenta desenvolvida para funcionar exclusivamente com **Python 3**, e sua função principal é detectar portas abertas em sistemas remotos quando o tráfego é roteado através de um proxy HTTP, como o Squid. Essa técnica é especialmente útil quando se busca realizar pivoting, utilizando o proxy como intermediário para mapear a rede interna ou alcançar alvos que normalmente estariam inacessíveis.

Para mais detalhes e acesso ao código-fonte da ferramenta, ela pode ser encontrada no GitHub:

[Spose - Squid Pivoting Open Port Scanner](https://github.com/aancw/spose)

Além disso, consultei o [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid), um recurso valioso para testes de penetração, que forneceu insights adicionais sobre como o serviço Squid pode ser utilizado em cenários de pentest e CTF.
