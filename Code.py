import os
import re
import json
import spacy
import pdfplumber

# Load spaCy model
nlp = spacy.load("en_core_web_sm")

# Configurations
MALWARE_SIGNATURES = {
    'Shamoon': {
        'keywords': ['disk wiping', 'destructive', 'saudi aramco', 'energy sector'],
        'targets': ['energy', 'oil', 'saudi arabia', 'middle east']
    },
    'Emotet': {
        'keywords': ['banking trojan', 'credential theft', 'modular malware'],
        'targets': ['financial', 'bank', 'enterprise']
    },
    'Trickbot': {
        'keywords': ['banking malware', 'credential stealer', 'ransomware'],
        'targets': ['financial institutions', 'enterprises']
    }
}

TARGETED_ENTITIES = [
    'Energy Sector', 'Financial Institutions', 'Government Agencies',
    'Healthcare', 'Defense', 'Technology', 'Critical Infrastructure'
]

THREAT_ACTORS = [
    'APT33', 'Fancy Bear', 'Lazarus Group', 'Cozy Bear'
]

# Regular Expressions for IoC Extraction
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b'
HASH_PATTERN = r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file."""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            text = ' '.join(page.extract_text() or '' for page in pdf.pages)
            return ' '.join(text.split())  # Clean up extra spaces/newlines
    except Exception as e:
        print(f"Error extracting text from {pdf_path}: {e}")
        return ''

def extract_iocs(report_text):
    """Extract indicators of compromise (IoCs) from text."""
    return {
        'IP_addresses': re.findall(IP_PATTERN, report_text),
        'Domains': re.findall(DOMAIN_PATTERN, report_text),
        'File_Hashes': re.findall(HASH_PATTERN, report_text),
        'Email_Addresses': re.findall(EMAIL_PATTERN, report_text)
    }

def detect_malware(report_text):
    """Detect malware signatures in the report text."""
    lower_text = report_text.lower()
    detected_malwares = []
    
    for malware, signature in MALWARE_SIGNATURES.items():
        if any(keyword.lower() in lower_text for keyword in signature['keywords']):
            detected_malwares.append({
                'Name': malware,
                'Keywords': signature['keywords'],
                'Potential_Targets': signature['targets']
            })
    
    return detected_malwares

def detect_threat_actors(report_text):
    """Identify known threat actors in the report text."""
    detected_actors = []
    for actor in THREAT_ACTORS:
        if actor.lower() in report_text.lower():
            detected_actors.append(actor)
    return detected_actors

def identify_targeted_entities(report_text):
    """Identify targeted entities from the text using spaCy."""
    doc = nlp(report_text)
    detected_entities = [ent.text for ent in doc.ents if ent.label_ in {"ORG", "GPE"}]
    # Match with predefined entities
    matched_entities = list(set(entity for entity in TARGETED_ENTITIES if entity.lower() in report_text.lower()))
    return list(set(detected_entities + matched_entities))

def process_directory(directory_path):
    """Process all PDF files in the given directory."""
    results = {}
    for filename in os.listdir(directory_path):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(directory_path, filename)
            report_text = extract_text_from_pdf(pdf_path)
            if report_text:
                results[filename] = {
                    'IoCs': extract_iocs(report_text),
                    'Malware': detect_malware(report_text),
                    'Threat_Actors': detect_threat_actors(report_text),
                    'Targeted_Entities': identify_targeted_entities(report_text)
                }
    return results

def save_results_to_json(results, output_folder):
    """Save results to JSON files in the output folder."""
    os.makedirs(output_folder, exist_ok=True)
    
    for filename, data in results.items():
        output_filename = os.path.splitext(filename)[0] + '_report.json'
        output_path = os.path.join(output_folder, output_filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

def main():
    directory_path = r"C:\Users\kanka\Downloads\C3i_HACKATHON_FINAL_ROUND_Q1_DATA"
    output_folder = os.path.join(directory_path, "JSON_Results")
    
    if not os.path.exists(directory_path):
        print(f"[ERROR] Directory path does not exist: {directory_path}")
        return
    
    print("[INFO] Starting PDF processing...")
    results = process_directory(directory_path)
    save_results_to_json(results, output_folder)
    
    # Optional: Print results to console
    for filename, data in results.items():
        print(f"\nResults for {filename}:")
        print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
