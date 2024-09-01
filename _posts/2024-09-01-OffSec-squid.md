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
![image](https://github.com/user-attachments/assets/3768bfd2-578a-4f20-b596-9b8efa341d1c)

Com esse comando, a **spose.py** foi configurada para usar o proxy **Squid** (acessível via porta **3128**) para escanear as portas abertas no alvo **192.168.185.189**. Essa técnica permitiu realizar a enumeração de portas através do proxy, oferecendo uma visão mais completa das portas e serviços que poderiam ser explorados posteriormente.

A **spose.py** é uma ferramenta desenvolvida para funcionar exclusivamente com **Python 3**, e sua função principal é detectar portas abertas em sistemas remotos quando o tráfego é roteado através de um proxy HTTP, como o Squid. Essa técnica é especialmente útil quando se busca realizar pivoting, utilizando o proxy como intermediário para mapear a rede interna ou alcançar alvos que normalmente estariam inacessíveis.

Para mais detalhes e acesso ao código-fonte da ferramenta, ela pode ser encontrada no GitHub:

[Spose - Squid Pivoting Open Port Scanner](https://github.com/aancw/spose)

Além disso, consultei o [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid), um recurso valioso para testes de penetração, que forneceu insights adicionais sobre como o serviço Squid pode ser utilizado em cenários de pentest e CTF.

Depois de identificar as portas abertas por trás do proxy Squid, a próxima etapa foi acessar a porta **8080**. Para isso, foi necessário configurar o **Squid proxy** no navegador.

### Configurando o Squid Proxy no Navegador

1. **Abra as configurações de rede do seu navegador** (geralmente encontrado nas configurações avançadas).
2. **Localize a seção de proxy** e selecione a opção para configuração manual de proxy.
3. **Insira o IP da máquina Squid** seguido da porta **3128** na seção HTTP Proxy. 

   - **IP da Máquina Squid:** `192.168.185.189`
   - **Porta:** `3128`

4. **Salve as configurações** e aplique o proxy.

### Acessando a Porta 8080

Com o proxy configurado, você pode acessar a porta **8080** através do navegador digitando na barra de endereços:

```
http://192.168.185.189:8080
```

![image](https://github.com/user-attachments/assets/c0c2dcc5-9666-4fb1-bcea-8831ac40c7bd)

Isso permitirá que você visualize o serviço em execução na porta **8080** através do proxy Squid.

### Próximos Passos

Depois de acessar a porta **8080**, a análise deve continuar para identificar a natureza do serviço em execução nessa porta. Isso pode incluir a identificação de um painel de administração, uma aplicação web vulnerável ou qualquer outro tipo de serviço que possa ser explorado. Dependendo do que for encontrado, as próximas etapas podem envolver testes de penetração mais profundos, como exploração de vulnerabilidades, escalonamento de privilégios ou a captura de credenciais.


