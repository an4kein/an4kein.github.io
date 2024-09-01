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

### Continuando com a Enumeração

Após acessar a porta **8080** e explorar o serviço disponível, é crucial continuar a enumeração e procurar por elementos que possam ser explorados. Ao navegar pela página, observe cuidadosamente todos os detalhes, pois muitas vezes há pistas que podem levar a vulnerabilidades.

Se você prestar atenção, no final da página existem **aliases** que redirecionam para recursos como `phpinfo`, `phpmyadmin`, `adminer`, entre outros. Esses aliases podem fornecer informações valiosas ou ser pontos de entrada para exploração adicional.

#### Explorando o `phpinfo`

O **phpinfo** é uma página que exibe a configuração do PHP e pode revelar informações críticas, como diretórios do servidor, caminhos de arquivos e outras configurações que podem ser exploradas. É comum encontrar detalhes sobre diretórios onde podemos tentar escrever um **payload malicioso**.

#### Tentativa de Login com Senhas Padrão

Sempre que você encontrar páginas de login, como `phpmyadmin` ou `adminer`, tente acessar utilizando senhas padrão. Muitos administradores esquecem de alterar as credenciais de login, deixando o sistema vulnerável a acessos não autorizados. 

Aqui estão alguns exemplos de credenciais padrão que você pode tentar:

- **admin:admin**
- **admin:** *(sem senha)*
- **admin:password**

Se você não souber a senha padrão para um produto específico, uma simples pesquisa no Google com o nome do produto e "default password" geralmente fornece as credenciais padrão. Em muitos casos, o próprio site do fornecedor lista as senhas padrão para os produtos.

![image](https://github.com/user-attachments/assets/23f7c87e-b34f-420c-b12b-0c0ed27abf88)

### Acesso Ganhado: Login como `root` sem Senha

Durante a exploração das páginas disponíveis, tentei utilizar o login com credenciais padrão. Notavelmente, ao tentar acessar com o usuário **root** sem senha, consegui obter acesso à página de administração.

Este tipo de vulnerabilidade é comum em configurações mal protegidas, onde as credenciais padrão não foram alteradas após a instalação do sistema. O acesso como **root** sem senha geralmente concede controle total sobre o sistema ou a aplicação, permitindo a execução de comandos, upload de arquivos maliciosos, ou até mesmo a modificação de configurações críticas.

#### Próximos Passos

Com o acesso root garantido, a próxima fase envolve:

1. **Verificação de privilégios:** Confirme o nível de acesso disponível e verifique se há restrições ou se você possui controle total sobre o sistema.
   
2. **Exploração adicional:** Explore o painel de administração para identificar qualquer funcionalidade que permita upload de arquivos ou execução de comandos no servidor. Essas funcionalidades podem ser usadas para enviar um **payload** malicioso e obter um **reverse shell**.

3. **Busca por arquivos sensíveis:** Procure por arquivos de configuração, logs, ou backups que possam conter informações sensíveis, como credenciais ou configurações do sistema.

4. **Escalabilidade:** Se o acesso root não oferece controle completo, busque por formas de escalar privilégios ou explorar outros serviços no sistema.
