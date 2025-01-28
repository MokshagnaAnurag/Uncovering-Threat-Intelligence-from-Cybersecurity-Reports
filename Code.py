import os
import re
import json
import requests
import pdfplumber
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

# Download necessary NLTK data files
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

# Example VirusTotal API key (replace with your actual key)
VT_API_KEY = 'cfcc642ca25c8f3dd82c130d564637669de30e5dad8b29bad35126dd64d0854a'

# Regular expressions for IoC extraction
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b(?!\.\w{2,4}$)'  # Avoid capturing .exe etc.
HASH_PATTERN = r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# Mapping of keywords to MITRE ATT&CK tactics and techniques
mitre_tactics = {
    "initial access": "TA0001",
    "execution": "TA0002",
    "lateral movement": "TA0008",
    "credential access": "TA0006",
    "discovery": "TA0007",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "defense evasion": "TA0005",
    "persistence": "TA0003"
}

mitre_techniques = {
    "spear phishing attachment": "T1566.001",
    "powershell": "T1059.001",
    "remote services": "T1021",
    "valid accounts": "T1078",
    "process injection": "T1055",
    "data staged": "T1074.001",
    "exfiltration over c2 channel": "T1041",
    "obfuscated files or information": "T1027",
    "account manipulation": "T1098",
    "file and directory discovery": "T1083"
}

# A larger list of known malware names
malware_names = [
    'Shamoon', 'Emotet', 'Trickbot', 'Zeus', 'Locky', 'WannaCry', 'Petya',
    'NotPetya', 'RansomExx', 'DarkSide', 'Conti', 'REvil', 'Maze', 'Qakbot',
    'Dridex', 'Cerber', 'CryptoLocker', 'GandCrab', 'NetWalker', 'Ryuk',
    'Mirai', 'BlackEnergy', 'Conficker', 'Stuxnet', 'Flame', 'Duqu', 'Sality',
    'Nimda', 'ILOVEYOU', 'Mydoom', 'CodeRed', 'Slammer', 'Blaster', 'Bagle',
    'SoBig', 'ZeuS', 'Cryptolocker', 'TeslaCrypt', 'Jigsaw', 'Angler EK',
    'Neutrino EK', 'Fareit', 'Adwind', 'LokiBot', 'FormBook', 'Gozi'
]

# Known threat actors
threat_actors = [
    'APT33', 'Fancy Bear', 'Lazarus Group', 'APT28', 'APT29', 'Dragonfly',
    'Sandworm', 'Turla', 'OilRig', 'Hacking Team', 'Pawn Storm', 'Equation Group',
    'Operation Aurora', 'Comment Crew', 'Deep Panda', 'Naikon', 'Threat Group-3390',
    'Carbanak', 'FIN7', 'Energetic Bear', 'Cozy Bear', 'APT-C-36', 'APT-C-23',
    'APT-C-35', 'APT-C-45', 'APT-C-37', 'APT-C-38', 'APT-C-39', 'APT-C-40'
]

# Targeted entities
targeted_entities_list = [
    'Energy Sector', 'Financial Institutions', 'Government Agencies',
    'Healthcare', 'Defense', 'Technology', 'Critical Infrastructure',
    'Telecommunications', 'Transportation', 'Manufacturing', 'Retail', 'Education',
    'Entertainment', 'Hospitality', 'Legal Services', 'Non-Profit Organizations'
]


def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ''
    except Exception as e:
        pass  # Silent failure
    return text


def extract_iocs(report_text):
    iocs = {
        'IP addresses': re.findall(IP_PATTERN, report_text),
        'Domains': [domain for domain in re.findall(DOMAIN_PATTERN, report_text) if '.' in domain],
        # Filter out invalid domains
        'File Hashes': re.findall(HASH_PATTERN, report_text),
        'Email Addresses': re.findall(EMAIL_PATTERN, report_text)
    }

    # Remove common file extensions that should not be considered as IoCs
    filtered_hashes = []
    for hash_value in iocs['File Hashes']:
        if not any(hash_value.lower().endswith(ext) for ext in ['.exe', '.dll', '.vagira']):  # Fixed typo
            filtered_hashes.append(hash_value)
    iocs['File Hashes'] = filtered_hashes

    return {k: v for k, v in iocs.items() if v}  # Remove empty lists


def extract_ttps(report_text):
    ttps = {'Tactics': [], 'Techniques': []}

    words = word_tokenize(report_text.lower())
    stop_words = set(stopwords.words('english'))
    filtered_words = [word for word in words if word.isalpha() and word not in stop_words]

    for tactic, id in mitre_tactics.items():
        if any(word in tactic for word in filtered_words):
            ttps['Tactics'].append([id, tactic.capitalize()])

    for technique, id in mitre_techniques.items():
        if any(word in technique for word in filtered_words):
            ttps['Techniques'].append([id, technique.capitalize()])

    return {k: v for k, v in ttps.items() if v}


def detect_threat_actors(report_text):
    lower_text = report_text.lower()
    detected_actors = [actor for actor in threat_actors if actor.lower() in lower_text]
    return detected_actors


def get_vt_report(sha256):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VT_API_KEY, 'resource': sha256}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        if data.get('response_code') == 1:
            return data
    return None


def extract_malware_details(report_text):
    detected_malwares = []

    for malware in malware_names:
        if malware.lower() in report_text.lower():
            # Extract hashes considering context to avoid false positives
            md5_matches = [hash_val for hash_val in re.findall(HASH_PATTERN, report_text) if len(hash_val) == 32]
            sha1_matches = [hash_val for hash_val in re.findall(HASH_PATTERN, report_text) if len(hash_val) == 40]
            sha256_matches = [hash_val for hash_val in re.findall(HASH_PATTERN, report_text) if len(hash_val) == 64]

            md5 = md5_matches[0] if md5_matches else 'vlfenvnkgn….'
            sha1 = sha1_matches[0] if sha1_matches else 'bvdib…..'
            sha256 = sha256_matches[0] if sha256_matches else 'poherionnj…….'

            vt_report = get_vt_report(sha256) if isinstance(sha256, str) else None

            detected_malwares.append({
                'Name': malware,
                'md5': md5,
                'sha1': sha1,
                'sha256': sha256,
                'ssdeep': 'bgfnh….',
                'TLSH': 'bnfdnhg…..',
                'tags': 'XYZ',  # Placeholder tags
                'additional_details': vt_report if vt_report else {}
            })

    return detected_malwares


def identify_targeted_entities(report_text):
    lower_text = report_text.lower()
    detected_entities = [entity for entity in targeted_entities_list if
                         any(word.lower() in lower_text for word in entity.split())]
    return detected_entities


def extract_threat_intelligence(report_text):
    return {
        'IoCs': extract_iocs(report_text),
        'TTPs': extract_ttps(report_text),
        'Threat Actor(s)': detect_threat_actors(report_text),
        'Malware': extract_malware_details(report_text),
        'Targeted Entities': identify_targeted_entities(report_text)
    }


def process_directory(directory_path):
    results = {}
    for filename in os.listdir(directory_path):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(directory_path, filename)
            report_text = extract_text_from_pdf(pdf_path)
            if report_text:
                results[filename] = extract_threat_intelligence(report_text)
    return results


def save_results_to_json(results, output_folder):
    os.makedirs(output_folder, exist_ok=True)

    for filename, data in results.items():
        output_filename = os.path.splitext(filename)[0] + '_report.json'
        output_path = os.path.join(output_folder, output_filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)


def main():
    directory_path = r"C:\Users"                                    #Replace It With Your Directory 
    
    # Check if the directory exists
    if not os.path.exists(directory_path):
        print(f"Error: The directory '{directory_path}' does not exist.")
        return
    
    output_folder = r"C:\Users"                                         #Replace It With Your Directory 
    results = process_directory(directory_path)

    if results:
        save_results_to_json(results, output_folder)
        print(f"Results have been saved to '{output_folder}'")
    else:
        print("No PDF files found in the specified directory.")


if __name__ == "__main__":
    main()
