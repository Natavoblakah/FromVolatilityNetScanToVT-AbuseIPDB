import requests
import csv
import ipaddress
from rich import print
import customtkinter as ctk
import tkinter.filedialog as fd
from tkinter import messagebox


API_KEY_AbuseIPDB = 'My_Token'
API_KEY_VirusTotal = 'My_Token'



def fetch_check_for_external_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY_VirusTotal
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Ошибка VirusTotal: {response.status_code} - {response.text}")
        return None

    data = response.json()
    attributes = data['data']['attributes']
    stats = attributes.get('last_analysis_stats', {})
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)

    total_engines = malicious + suspicious + harmless + undetected
    detection_ratio = f"{malicious + suspicious}/{total_engines}"

    return {
        "country": attributes.get('country', 'N/A'),
        "reputation": attributes.get('reputation', 0),
        "last_analysis_stats": stats,
        "detection_ratio": detection_ratio
    }



def fetch_check_for_external_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeDays': 90
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY_AbuseIPDB
    }

    response = requests.get(url, headers=headers, params = querystring)
    data = response.json()

    return data

def fetch_categories_for_external_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/reports'
    querystring = {
        'ipAddress': ip,
        'maxAgeDays': 90
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY_AbuseIPDB
    }

    response = requests.get(url, headers=headers, params = querystring)

    if response.status_code != 200:
        print(f"[red]❌ Ошибка API (status {response.status_code}) для {ip}: {response.url}[/red]")
        print(f"[yellow]Ответ сервера:[/yellow] {response.text}")
        return []
    try:
        data = response.json()

    except ValueError:
        print(f"[red]❌ Невозможно декодировать JSON-ответ для {ip}[/red]")
        print(response.text)
        return []

    if 'data' not in data or 'results' not in data['data']:
        print(f"[red]⚠️ Неожиданная структура ответа от API для {ip}[/red]")
        print(data)
        return []


    categories = set()
    results = data['data']['results']
    for result in results:
        result_categories = result['categories']
        categories.update(result_categories)
    categorie_names = []
    
    for cat in categories:
        categorie_name = CATEGORY_MAPPING.get(cat,f"Неизвестная ошибка, такой категории нет {cat}")
        categorie_names.append(categorie_name)

    return categorie_names


CATEGORY_MAPPING = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


class IPCheckApp:
    def __init__(self,root):
        print("🌀 GUI инициализируется...")
        self.root = root
        self.root.title("IP-Check Tool")
        self.root.geometry("600x500")

        self.root.grid_rowconfigure(0, weight=0) 
        self.root.grid_rowconfigure(1, weight=0) 
        self.root.grid_rowconfigure(2, weight=1)  
        self.root.grid_columnconfigure(0, weight=1) 

        button_frame = ctk.CTkFrame(self.root)
        button_frame.grid(row=1, column=0, padx=20, pady=10, sticky="w")

        self.label = ctk.CTkLabel(self.root, text="Выберите файл для обработки", font=("Arial", 14))
        self.label.grid(row=0, column=0, padx=20, pady=20, sticky="w")

        self.button = ctk.CTkButton(button_frame, text="Открыть файл", command=self.load_file)
        self.button.grid(row=0, column=0, padx=(0, 10))  

        self.process_button = ctk.CTkButton(button_frame, text="Запуск анализа", command=self.file_processing)
        self.process_button.grid(row=0, column=1)

        self.text_result = ctk.CTkTextbox(self.root, width=500, height=700)
        self.text_result.grid(row=2, column=0, padx=20, pady=20)

    def load_file(self):
        file_path = fd.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            self.label.configure(text=f"✅ Выбран файл: {file_path}")
            self.file_path = file_path

    def file_processing(self):
        print("➡️ Запущен метод file_processing()") 
        if not hasattr(self, 'file_path'):
            messagebox.showwarning("Предупреждение", "Сначала выберите файл!")
            return
        
        with open(self.file_path, 'r', encoding='utf-8') as csvfile:
            lines = csvfile.readlines()

        lines = lines[2:]
        reader = csv.DictReader(lines, delimiter='\t')

        external_ips = set()

        for row in reader:
            foreign_address = row['ForeignAddr'].strip()
            if foreign_address not in ('*', '0.0.0.0', '::'):
                try:
                    ip = ipaddress.ip_address(foreign_address)
                    if ip.is_global:
                        external_ips.add(foreign_address)
                except ValueError:
                    continue
        print(f"Найдено IP: {external_ips}") 
        self.text_result.delete(1.0, ctk.END)  

        for ip in external_ips:
            data_check = fetch_check_for_external_ip(ip)
            categories = fetch_categories_for_external_ip(ip)
            vt_data = fetch_check_for_external_ip_virustotal(ip)

            print(f"Ответ AbuseIPDB (check) для {ip}: {data_check}")
            print(f"Ответ AbuseIPDB (reports) для {ip}: {categories}")
            print(f"Ответ VirusTotal для {ip}: {vt_data}")


            abuse_score = data_check['data']['abuseConfidenceScore']
            is_clean_abuse = abuse_score == 0
            is_clean_categories = len(categories) == 0
            is_clean_virustotal = vt_data['detection_ratio'].startswith("0/")

            if is_clean_abuse and is_clean_categories and is_clean_virustotal:
                self.text_result.insert(ctk.END, f"✅IP-адрес {ip} считается чистым по данным AbuseIPDB и VirusTotal.\n")
            else:
                
                self.text_result.insert(ctk.END, f'''
-------------------------------------------------
⚠️IP-адрес: {ip}
-------------------------------------------------

============ AbuseIPDB ============
Страна: {data_check['data']['countryCode']}
Рейтинг AbusseIPDB: {abuse_score} %
Данный адрес является тор-нодой: {data_check['data']['isTor']}
Данный адрес является хостингом: {data_check['data']['usageType']}
Категории вредоносной активности: {categories}

============ VirusTotal ============
Страна: {vt_data['country']}
Репутация: {vt_data['reputation']}
Показатель выявления вредоносов вендорами АВПО: {vt_data['detection_ratio']}
Harmless: {vt_data['last_analysis_stats'].get('harmless', 'N/A')}
Malicious: {vt_data['last_analysis_stats'].get('malicious', 'N/A')}
Suspicious: {vt_data['last_analysis_stats'].get('suspicious', 'N/A')}
Undetected: {vt_data['last_analysis_stats'].get('undetected', 'N/A')}
''')

        messagebox.showinfo("Готово", "Анализ завершён!")

if __name__ == "__main__":
    root = ctk.CTk()
    app = IPCheckApp(root)
    root.mainloop()
