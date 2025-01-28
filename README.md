# Uncovering-Threat-Intelligence-from-Cybersecurity-Reports
# Threat Intelligence Extractor

A Python-based tool for extracting threat intelligence data from cybersecurity reports in PDF format. The tool identifies Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), known malware, threat actors, and targeted entities. Additionally, it integrates with VirusTotal to fetch additional details for detected hashes.

## Features

- **IoC Extraction:** Extracts IP addresses, domains, file hashes, and email addresses.
- **TTP Identification:** Maps keywords to MITRE ATT&CK tactics and techniques.
- **Threat Actor Detection:** Identifies well-known threat actors mentioned in the report.
- **Malware Identification:** Detects known malware and fetches associated details, including VirusTotal reports.
- **Targeted Entity Identification:** Identifies organizations or sectors targeted by the threat.
- **PDF Parsing:** Processes PDF files to extract text.

## Prerequisites

### Python Libraries
Ensure the following libraries are installed:

- `os`
- `re`
- `json`
- `requests`
- `pdfplumber`
- `nltk`

Install the dependencies using:
```bash
pip install pdfplumber requests nltk
```

### NLTK Data
The script downloads necessary NLTK data files automatically:
- `punkt`
- `stopwords`

### VirusTotal API Key
Replace the placeholder `VT_API_KEY` in the script with your actual VirusTotal API key.

## Usage

1. Clone the repository:
    ```bash
    git https://github.com/MokshagnaAnurag/Uncovering-Threat-Intelligence-from-Cybersecurity-Reports.git
    ```
2. Navigate to the project directory:
    ```bash
    cd <repository_directory>
    ```
3. Update the following paths in the `main()` function:
    - `directory_path`: Path to the folder containing PDF reports.
    - `output_folder`: Path to save the JSON output files.

4. Run the script:
    ```bash
    python <script_name>.py
    ```

## File Structure

```plaintext
.
├── script.py                 # Main script
├── README.md                 # Documentation
├── sample_reports/           # Folder for PDF reports
├── output_reports/           # Folder for JSON output
└── requirements.txt          # Dependency list
```

## Output

- The script generates a JSON file for each processed PDF report.
- The JSON files are saved in the specified `output_folder`.

### Example JSON Output
```json
{
    "IoCs": {
        "IP addresses": ["192.168.1.1"],
        "Domains": ["example.com"],
        "File Hashes": ["abcdef1234567890"],
        "Email Addresses": ["malicious@example.com"]
    },
    "TTPs": {
        "Tactics": [
            ["TA0001", "Initial Access"]
        ],
        "Techniques": [
            ["T1059.001", "Powershell"]
        ]
    },
    "Threat Actor(s)": ["Fancy Bear"],
    "Malware": [
        {
            "Name": "Emotet",
            "md5": "abcdef1234567890",
            "sha1": "1234567890abcdef",
            "sha256": "abcdef1234567890abcdef1234567890",
            "ssdeep": "bgfnh....",
            "TLSH": "bnfdnhg....",
            "tags": "XYZ",
            "additional_details": {}
        }
    ],
    "Targeted Entities": ["Financial Institutions"]
}
```

## Customization

- **Add Additional IoCs**: Update regular expressions for IoC extraction.
- **Extend MITRE ATT&CK Mapping**: Add new tactics or techniques to the `mitre_tactics` and `mitre_techniques` dictionaries.
- **Expand Malware List**: Add more malware names to the `malware_names` list.
- **Add New Threat Actors**: Extend the `threat_actors` list.
- **Include Targeted Entities**: Update the `targeted_entities_list`.

## Known Limitations

- The PDF parsing depends on the quality of the report; poorly formatted PDFs might lead to missing text.
- VirusTotal API key usage is rate-limited; ensure you have sufficient quota.
- The script may not handle all edge cases for IoC filtering.

## Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request. Ensure your code adheres to Python best practices.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [VirusTotal API](https://www.virustotal.com/)
- [pdfplumber Documentation](https://github.com/jsvine/pdfplumber)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

Feel free to report any issues or suggest improvements via the Issues tab on GitHub.

