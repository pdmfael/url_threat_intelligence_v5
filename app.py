from flask import Flask, render_template, request
import requests
import base64

app = Flask(__name__)

# Suas chaves da API
API_KEY = ''  # VirusTotal
WHOIS_API_KEY = ''  # WhoisXML
ABUSEIPDB_API_KEY = ''  # AbuseIPDB

def get_ip_info(url):
    try:
        ip_response = requests.get(f"https://dns.google/resolve?name={url}").json()
        return ip_response.get("Answer", [{}])[0].get("data", "IP não encontrado")
    except Exception as e:
        return f"Erro ao obter IP: {e}"

def get_whois_info(url):
    domain = url.split("//")[-1].split("/")[0]  # Extrai o domínio
    try:
        response = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON")
        
        if response.status_code == 200:
            data = response.json()
            whois_record = data.get('WhoisRecord', {})
            
            if whois_record:
                domain_info = {
                    "Domain": whois_record.get('domainName', 'Não disponível'),
                    "Data de Criação": whois_record.get('createdDate', 'Não disponível'),
                    "Data de Expiração": whois_record.get('expiresDate', 'Não disponível'),
                    "Servidor DNS": [ns for ns in whois_record.get('registryData', {}).get('nameServers', {}).get('hostNames', [])],
                    "Registrador": whois_record.get('registrarName', 'Não disponível'),
                    "Estado": whois_record.get('registryData', {}).get('status', 'Não disponível'),
                    "Informações Adicionais": whois_record.get('rawText', 'Não disponíveis')
                }
                return domain_info
            else:
                return "Nenhuma informação WHOIS disponível"
        else:
            return f"Erro ao consultar WHOIS: {response.status_code}"
    except Exception as e:
        return f"Erro ao consultar WHOIS: {e}"

def check_url_reputation(url, api_key):
    try:
        headers = {
            "x-apikey": api_key
        }
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            data = json_response.get("data", {}).get("attributes", {})
            last_analysis_stats = data.get("last_analysis_stats", {})
            total_engines = sum(last_analysis_stats.values())

            reputation_details = {
                "Positivos (maliciosos)": last_analysis_stats.get("malicious", 0),
                "Inofensivos": last_analysis_stats.get("harmless", 0),
                "Suspeitos": last_analysis_stats.get("suspicious", 0),
                "Não Detectados": last_analysis_stats.get("undetected", 0),
                "Timeout": last_analysis_stats.get("timeout", 0),
                "Última Análise": data.get("last_analysis_date", "Não disponível"),
                "Total de Engines que Analisaram": total_engines
            }

            engines_analysis = data.get("last_analysis_results", {})
            engines_details = {engine: result["result"] for engine, result in engines_analysis.items()}

            return reputation_details, engines_details
        else:
            return f"Erro ao consultar a reputação: {response.status_code}", {}
    except Exception as e:
        return f"Erro ao consultar VirusTotal: {e}", {}

# Nova função para verificar o IP no AbuseIPDB
def check_abuseipdb(ip):
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90  # Verifica por registros nos últimos 90 dias
        }
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            abuse_info = {
                "IP": data.get('data', {}).get('ipAddress', 'Não disponível'),
                "Score de Abuso": data.get('data', {}).get('abuseConfidenceScore', 'Não disponível'),
                "Total de Relatos": data.get('data', {}).get('totalReports', 0),
                "Último Relato": data.get('data', {}).get('lastReportedAt', 'Não disponível'),
            }
            return abuse_info
        else:
            return f"Erro ao consultar AbuseIPDB: {response.status_code}"
    except Exception as e:
        return f"Erro ao consultar AbuseIPDB: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        url = request.form['url'].strip()  # Remove espaços em branco

        ip_info = get_ip_info(url)
        whois_info = get_whois_info(url)
        reputation, engines = check_url_reputation(url, API_KEY)
        abuse_info = check_abuseipdb(ip_info)  # Chama a função do AbuseIPDB

        report = {
            "URL": url,
            "IP": ip_info,
            "Domain Info": whois_info,
            "Reputation": reputation,
            "Engines": engines,
            "AbuseIPDB": abuse_info  # Inclui as informações do AbuseIPDB no relatório
        }

        return render_template('report.html', report=report)

if __name__ == '__main__':
    app.run(debug=True)
