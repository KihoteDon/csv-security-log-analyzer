# Terceiro Projeto - Análise de logs suspeitos em CSV
# Créditos do dataset -> darknight25 (Advanced_SIEM_Dataset) 100k 
# 6 milhões de linhas
# --Version 0.1


from tqdm import tqdm
import csv

def extrair_ip():
    # Função para extrair os IPs e adicionar a um dicionário com sua respectiva contagem
    with open ("archive/logs.csv", newline="") as file:
        lista_ip = {

        }
        reader = csv.reader(file)
        next(reader)

        for linha in tqdm(reader, total=6000001, desc="Analisando e Validando IPs..."):
            saida = linha[1]
            partes = saida.split(".")
            valido = True
            
            if len(partes) != 4:
                continue
            for i in partes:
                if not i.isdigit():
                    valido = False
                    break
                elif int(i) > 255 or int(i) < 0:
                    valido = False
                    break 
            if valido == True:
                lista_ip[saida] = lista_ip.get(saida, 0) + 1

        # Retornando dicionário de IPs Válidos
        return lista_ip
            
            

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

# A estatística geral basicamente retorna quantidade de blocked/allowed, Ranking IP, Ranking Protocolos, Ferramentas utilizadas
# Ranking fonte de logs, e estatística temporal

def estatistica_geral():
    total_linha = 6000001 # Quantidade de linhas que o log possui
    count = 0
    with open("archive/logs.csv", "r") as file:
        with open("rep.txt", "w") as dir:

            # Analisando quantas linhas existem no CSV
            quantos_dados = sum(1 for linhas in file)
            dir.write(f"A quantidade de dados analisados {quantos_dados}")
            file.seek(0)

            # Analisando quantos ALLOWED e BLOCKED existem
            for linha in tqdm(file, total=total_linha, desc="Analisando quantidade de allowed..."):
                if "allowed" in linha.lower():
                    count += 1
                    dir.write(linha)
            print(f"A quantidade de allowed dentro do dataset é de {count} e a porcentagem em relação ao mesmo é de {round(count/total_linha*100, 2)}%")
            
            file.seek(0)
            count = 0

            for linha in tqdm(file, total=total_linha, desc="Analisando quantidade de blocked..."):
                if "blocked" in linha.lower():
                    count += 1
                    dir.write(linha)
            print(f"A quantidade de blocked dentro do dataset é de {count} e a porcentagem em relação ao mesmo é de {round(count/total_linha*100, 2)}%")

            file.seek(0)
            count = 0

def estatistica_ip():
    with open ("rep.txt", "w") as repositorio:
        dicionario = extrair_ip()
        
        rankear = sorted(dicionario.items(), key=lambda item: item[1], reverse=True)
        print(rankear[:5])
        


        

                
                
                




# Função principal
def main():
    print("Digite:\n Filtrar dado - 1\n Estatística Geral - 2\n Estatística IP - 3\n Análise de temporal - 4\n Análise de comportamento suspeito - 5\n Gerar relatório - 6")
    
    try:
        entrada = int(input("Que tipo de inspeção deseja fazer: "))
    except ValueError:
        print("Entrada inválida")
        
    if entrada == 1:
        filtrar_dado()
    if entrada == 2:
        estatistica_geral()
    if entrada == 3:
        estatistica_ip()
    else:
        print("wip")

main()