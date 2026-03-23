# Terceiro Projeto - Análise de logs suspeitos em CSV
# Créditos do dataset -> darknight25 (Advanced_SIEM_Dataset) 100k 
# 6 milhões de linhas
# --Version 0.1


from tqdm import tqdm
import csv

def validar_ip(ip):
    valido = True
    partes = ip.split(".")
            
    if len(partes) != 4:
        valido = False
    for i in partes:
        if not i.isdigit():
            valido = False
            break
        elif int(i) > 255 or int(i) < 0:
            valido = False
            break 
    return valido

def extrair_ip():
    # Função para extrair os IPs e adicionar a um dicionário com sua respectiva contagem
    with open ("archive/logs.csv", newline="") as file:
        lista_ip_source = {
        }
        lista_ip_destination = {
        }

        reader = csv.reader(file)
        next(reader)

        for linha in tqdm(reader, total=6000001, desc="Analisando e Validando IPs..."):
            ip_source = linha[1]
            acao = linha[4]
            comportamento = linha[5]
            ferramenta = linha[8]

            source_valido = validar_ip(ip_source)
            #destination_valido = validar_ip(ip_destination)

            if source_valido == True:
                lista_ip_source[ip_source] = lista_ip_source.get(ip_source, {
                    "total": 0,
                    "blocked": 0,
                    "allowed": 0,
                    "Comportamento Suspeito": 0,
                    "Comportamento Normal": 0,
                    "Ferramenta": 0
                })
                lista_ip_source[ip_source]["total"] += 1

                if acao == "blocked":
                    lista_ip_source[ip_source]["blocked"] += 1
                elif acao == "allowed":
                    lista_ip_source[ip_source]["allowed"] += 1
                
                if comportamento == "suspicious":
                    lista_ip_source[ip_source]["Comportamento Suspeito"] += 1
                elif comportamento == "benign":
                    lista_ip_source[ip_source]["Comportamento Normal"] += 1
                
                if "mozilla" in ferramenta.lower() or "safari" in ferramenta.lower() or "windows" in ferramenta.lower():
                    continue
                else: 
                    lista_ip_source[ip_source]["Ferramenta"] += 1
            
        return lista_ip_source
            
# Função para filtrar dados com base da entrada do usuário
def filtrar_dado():
    count = 0
    entrada = input("Digite o que deseja filtrar: ").lower()
    total_linha = 6000001
    with open("archive/logs.csv", "r") as file:
        with open("rep.txt", "w") as dir:
            
            for linha in tqdm(file, total=total_linha, desc="Processando..."):
                if entrada in linha.lower():
                    count += 1
                    dir.write(linha)
    print(f"análise concluída\nA palavra {entrada}, apareceu {count} vezes")
    print("Verifique o arquivo rep.txt para ver os logs filtrados")

# A estatística geral basicamente retorna quantidade de blocked/allowed, Ranking IP, Ranking Protocolos, Ferramentas utilizadas
# Ranking fonte de logs, e estatística temporal


# Função que irá rankear os IPs e retornar uma estatística
def estatistica_ip():
    dicionario = extrair_ip()
    print("Escolha como quer filtrar (ordem decrescente):\n[1] IPs que mais aparecem\n[2] IPs mais negados\n[3] IPs mais permitidos\n[4] Comportamento normal\n[5] Comportamento suspeito\n[6] Vezes em que usou ferramenta")
    try:
        entrada_comando = int(input("Digite aqui: "))
    except ValueError:
        print("Entrada inválida, digite um número")
        return

    if 7 >= entrada_comando < 1:
        return print("Fora de escopo, digite um número válido")
    elif entrada_comando == 1:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["total"], reverse=True))
    elif entrada_comando == 2:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["blocked"], reverse=True))
    elif entrada_comando == 3:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["allowed"], reverse=True))
    elif entrada_comando == 4:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["Comportamento Normal"], reverse=True))
    elif entrada_comando == 5:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["Comportamento Suspeito"], reverse=True))
    elif entrada_comando == 6:
        saida_organizada = dict(sorted(dicionario.items(), key=lambda item: item[1]["Ferramenta"], reverse=True))

    entrada_filtro = input("Qual o número de IPs que deseja visualizar (ordem decrescente): ")
    try:
        quantidade = int(entrada_filtro)
        contador = 1
        for chave, valor in saida_organizada.items():
            print(f"{contador}° | IP: {chave} | Apareceu: {valor['total']} vezes | Blocked: {valor['blocked']} | Allowed: {valor['allowed']} | Comportamento Normal: {valor['Comportamento Normal']} | Comportamento Suspeito {valor['Comportamento Suspeito']} | Vezes que utilizou ferramenta {valor['Ferramenta']}")
            contador += 1
            if contador == quantidade+1:
                break
    except ValueError:
        print("Digite um número válido")
    

# Função para retornar um determinado tip de informação (protocolo/porta/ferramenta/?) e retornar uma estatística 
def extrair_infos(x):
    with open("archive/logs.csv", newline="") as file:
        reader = csv.reader(file)
        next(reader)
        total_linhas = 6000001
        num = 1
        
        dicionario = {

        }

        if x == 1:
            nome = "Protocolo"
            index = 3
        elif x == 2:
            nome = "Porta"
            index = 7
        elif x == 3:
            nome = "Origem lógica do evento"
            index = 6
        elif x == 4:
            nome = "Ferramenta"
            index = 8
        elif x == 5:
            nome = "User Agent"
            index = 8


        for linha in tqdm(reader, total=total_linhas, desc="Extraindo informações necessárias"):
            if nome == "Ferramenta":
                info = linha[index]
                if "mozilla" in info.lower() or "safari" in info.lower() or "windows" in info.lower():
                    continue
                else: 
                    dicionario[info] = dicionario.get(info, 0) + 1
            elif nome == "User Agent":
                info = linha[index]
                if "mozilla" in info.lower() or "safari" in info.lower() or "windows" in info.lower():
                    dicionario[info] = dicionario.get(info, 0) + 1
            else:
                info = linha[index]
                dicionario[info] = dicionario.get(info, 0) + 1
        print("Análise concluída")
        
        # Organizando em ordem decrescente no dicionário ORGANIZANDO
        organizando = dict(sorted(dicionario.items(), key=lambda item: item[1], reverse=True))  

        # Formatando a saída com base no tipo de informação que o usuário escolheu
        print(f"Informações sobre {nome}")
        if nome == "Protocolo" or nome == "Origem lógica do evento" or nome == "Ferramenta":
            for chave, valor in organizando.items():
                print(f"{num}° | {chave} apareceu {valor} | {round((valor/6000001*100), 2)}%")
                num += 1

        elif nome == "Porta" or nome == "User Agent":
            total_chaves = len(organizando)
            print(f"Existem {total_chaves} valores, digite a quantidade que deseja ver (ordem decrescente) ou digite qualquer coisa para ver todos")
            entrada = input("Digite: ")
            try:
                validando = int(entrada)
                if validando > total_chaves:
                    print("Número fora de escopo")
                else:
                    contador = 0
                    for chave, valor in organizando.items():
                        print(f"{num}° | Porta '{chave}' apareceu {valor} | {round((valor/6000001*100), 5)}%")
                        num += 1
                        contador += 1
                        if contador == validando:
                            break
            except ValueError:
                for chave, valor in organizando.items():
                    print(f"{num}° | {chave} apareceu {valor} | {round((valor/6000001*100), 2)}%")
                    num += 1
                
# Função principal
def main():
    print("Digite:\n[1] Filtro de busca\n[2] IPs mais utilizados \n[3] Análise de informações")
    
    try:
        entrada = int(input("Que tipo de inspeção deseja fazer: "))
    except ValueError:
        print("Entrada inválida")
        return
        
    if entrada == 1:
        filtrar_dado() # OK
    elif entrada == 2:
        estatistica_ip() # OK
    elif entrada == 3: # OK
        print("[1] - Protocolos\n[2] - Portas\n[3] - Origem lógica do evento\n[4] - Ferramenta\n[5] - User Agent")

        try:
            comando = int(input("Que tipo de informação deseja extrair?"))
        except ValueError:
            print("Entrada inválida")
            return

        if 0 < comando <= 5:
            extrair_infos(comando)
        else:
            print("Comando inválido")

main()