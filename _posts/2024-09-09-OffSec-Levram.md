---
title:     "OffSec Proving Grounds - Levram"
tags: [linux,easy,CVE-2021-43857]
categories: OffSecProvingGrounds
---


## Enumeration

### 1. **Enumeração Inicial com NmapAutomator e Nmap**

A primeira etapa de exploração da máquina **Lavram** começou com a execução de uma varredura inicial para identificar portas abertas e serviços rodando no sistema.

#### **Passo 1**: Utilizando **NmapAutomator** para agilizar a enumeração:

```bash
└─$ nmapAutomator.sh -H 192.168.199.24 -t All -o nmapautomator-all-ports
```

O **NmapAutomator** é uma ferramenta que automatiza diferentes tipos de varredura do **Nmap**, permitindo uma enumeração mais rápida e organizada. Isso inclui a varredura de todas as portas (com a flag **-t All**) para garantir que nenhuma porta importante seja deixada de fora.

#### **Passo 2**: Executando uma varredura manual com **Nmap**:

```bash
└─$ nmap -T4 -p- -v 192.168.199.24 -oN nmap-all-ports
```

Nesta etapa, foi realizada uma varredura manual usando **Nmap** com as opções:

- **-T4**: Aumenta a agressividade da varredura, acelerando o processo.
- **-p-**: Varre todas as portas, de 1 a 65535.
- **-v**: Habilita a saída verbosa, mostrando o progresso da varredura em tempo real.
- **-oN**: Salva os resultados da varredura em um arquivo de log para referência futura.

Essas etapas de enumeração são fundamentais para mapear o cenário da máquina alvo e identificar possíveis pontos de exploração, como serviços vulneráveis, portas não documentadas e possíveis vetores de ataque.

![image](https://github.com/user-attachments/assets/f937d320-61ce-45fb-af4e-984358ba1f04)

Navegando até a porta 8000, encontrei um serviço chamado Gerapy, que por sua vez é vulnerável ao CVE-2021-43857.

![image](https://github.com/user-attachments/assets/60d06174-7893-4886-8a40-76aa0ee4e2ae)

Então, pesquisei por explorações disponíveis usando o searchsploit com o objetivo de encontrar alguma vulnerabilidade para o Gerapy.

![image](https://github.com/user-attachments/assets/395904c8-9125-4d91-bf69-ddc970b7c175)

## Exploitation

Encontrei uma exploração correspondente ao nosso cenário, porém, era necessário estar autenticado para explorá-la corretamente. Utilizando as credenciais admin:admin
, que é uma senha padrão frequentemente testada, consegui fazer login na aplicação. Com isso, pude explorar a vulnerabilidade utilizando o exploit disponível.

![image](https://github.com/user-attachments/assets/4e5bf515-2352-4281-9625-7246823ccd87)

Ao tentar executar o exploit, recebi um erro de lista vazia, que estava ocorrendo porque ainda não havia sido criado nenhum projeto no dashboard.

![image](https://github.com/user-attachments/assets/6c8fa1ff-0379-445c-bbe3-f87ba5810447)

Sempre tenha em mente que é fundamental entender como a exploração funciona. Dessa forma, você aumentará suas chances de sucesso em suas tentativas de exploração.

Então, criei um projeto chamado teste, conforme vocês podem conferir na imagem abaixo.

![image](https://github.com/user-attachments/assets/c751c21f-9a39-4a42-bb55-878887d0a428)

Depois de criar o projeto, executamos novamente o exploit, e desta vez ele funcionou perfeitamente, proporcionando uma reverse shell com sucesso.

![image](https://github.com/user-attachments/assets/f7d786bc-49de-433f-8387-e3fdf07720f6)

## Privilege Escalation

Para escalar privilégios para root, e visando agilizar o processo, utilizei o linpeas.sh, uma ferramenta que costumo usar na maioria dos casos, pois ela facilita drasticamente a identificação de vetores de escalonamento de privilégios.

![image](https://github.com/user-attachments/assets/0de14c2e-e5aa-462b-9494-bf811c2ea3d8)

Encontrei o ponto-chave que estávamos procurando: **Linux capabilities**. Isso pode ser identificado de forma manual utilizando o comando:

```bash
getcap -r /
```

### O que são Linux Capabilities?

**Linux capabilities** são permissões específicas que podem ser atribuídas a processos ou binários, permitindo que eles realizem determinadas ações que normalmente seriam restritas apenas ao **root**. Ao invés de conceder privilégios completos de administrador, o sistema pode atribuir permissões granulares para ações específicas, como abrir portas de rede, mudar o ID do usuário ou acessar determinados recursos do sistema.

Isso oferece um meio mais seguro de delegar permissões sem a necessidade de elevar todo o processo ou usuário ao nível de **root**. Essas permissões granulares ajudam a reduzir os riscos de segurança ao limitar o escopo das ações permitidas por um processo.

Alguns exemplos de **Linux capabilities** incluem:
- **CAP_NET_BIND_SERVICE**: Permite que o processo abra portas de rede abaixo de 1024, sem precisar ser root.
- **CAP_SETUID**: Permite que o processo altere seu próprio ID de usuário, potencialmente escalando privilégios.

Usar o comando **getcap** ajuda a verificar quais binários ou processos possuem essas permissões, o que pode ser uma maneira de encontrar vulnerabilidades que permitam o escalonamento de privilégios no sistema.

No nosso caso, encontramos o binário **/usr/bin/python3.10** com permissões de **Linux capabilities** atribuídas.

Isso significa que o **python3.10** tem permissões específicas que podem ser exploradas para escalar privilégios no sistema. Com capacidades atribuídas, como por exemplo **CAP_SETUID**, poderíamos usar o **python3.10** para executar comandos com permissões elevadas, alterando o ID de usuário e possivelmente obtendo privilégios de **root**.

Para confirmar quais capacidades estão associadas a esse binário, você pode usar o comando:

```bash
getcap /usr/bin/python3.10
```

Dependendo das capacidades presentes, será possível explorar essas permissões para obter controle elevado sobre o sistema.

Na plataforma [GTFOBins](https://gtfobins.github.io/gtfobins/python/#capabilities), podemos verificar maneiras de explorar binários que possuem **Linux capabilities** atribuídas. No nosso caso, o **python3.10** possui a capacidade de alterar o ID de usuário, o que possibilita a elevação de privilégios.

Para escalar privilégios para **root**, podemos usar o seguinte comando:

```bash
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Esse comando faz o seguinte:
- **os.setuid(0)**: Muda o ID do usuário para 0, que é o **UID** do **root** no sistema.
- **os.system("/bin/sh")**: Abre um shell com privilégios de **root**.

Após a execução desse comando, você terá um shell com privilégios de **root**, o que permite controle total do sistema.

![image](https://github.com/user-attachments/assets/fc360026-102d-4d64-83c2-6165a6124f7c)

## Mitigation

### Medidas de Mitigação para o **CVE-2021-43857** e **Linux Capabilities**

#### 1. **Atualização do Gerapy**
   - **Atualização de Software**: O principal ponto de mitigação é garantir que o **Gerapy** esteja atualizado para a versão mais recente, que inclui patches de segurança que corrigem o **CVE-2021-43857**. Sempre acompanhe o ciclo de atualização dos softwares instalados e aplique as atualizações de segurança rapidamente.

#### 2. **Autenticação Segura**
   - **Remover Credenciais Padrão**: A exploração foi possível devido ao uso de credenciais padrão como **admin:admin**. Para mitigar esse risco, desative imediatamente as credenciais padrão após a instalação e implemente políticas de senha forte.
   - **Autenticação Multifator (MFA)**: Para evitar o uso indevido de credenciais, implemente **MFA** para proteger as contas administrativas e outras contas críticas no sistema.

#### 3. **Privilégios Mínimos e Isolamento de Aplicações**
   - **Princípio do Menor Privilégio**: Garanta que apenas usuários autorizados tenham acesso às funcionalidades administrativas do **Gerapy**. Utilize o princípio do menor privilégio, garantindo que os usuários só tenham as permissões estritamente necessárias para executar suas funções.
   - **Isolamento de Serviços**: Use contêineres ou ambientes isolados (como **Docker**) para hospedar aplicações como o Gerapy, reduzindo o impacto de uma potencial exploração.

#### 4. **Mitigação de Exploração de Linux Capabilities**
   - **Revisão e Remoção de Capabilities**: O binário **/usr/bin/python3.10** foi utilizado para escalonamento de privilégios devido às capabilities atribuídas. Para mitigar esse risco, remova capabilities desnecessárias com o comando:
     ```bash
     setcap -r /usr/bin/python3.10
     ```
     Isso impede que o binário seja utilizado para escalonamento de privilégios.
   - **Monitoramento de Modificações de Capabilities**: Configure auditorias de sistema (por exemplo, com **Auditd**) para monitorar mudanças em capabilities de binários e detectar tentativas de manipulação.

#### 5. **Monitoramento de Atividade e Logs**
   - **Monitoramento de Logs**: Use sistemas de monitoramento como **Wazuh** ou **OSSEC** para rastrear atividades incomuns, como execuções de comandos relacionados a **reverse shells** e tentativas de escalonamento de privilégios.
   - **Monitoramento de Processos e Acesso ao Sistema**: Ferramentas de monitoramento contínuo devem ser configuradas para detectar atividades que não correspondem ao comportamento normal dos usuários e alertar a equipe de segurança.
