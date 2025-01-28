# Uncovering-Threat-Intelligence-from-Cybersecurity-Reports

This project processes PDF reports to extract threat intelligence, including Indicators of Compromise (IoCs), known malware signatures, threat actors, and targeted entities. It uses Python libraries like `pdfplumber`, `re`, and `spaCy` for text extraction, pattern matching, and Named Entity Recognition (NER).

## Features

- **IoC Extraction**: Extracts IP addresses, domains, file hashes, and email addresses using regular expressions.
- **Malware Detection**: Matches report content against predefined malware signatures.
- **Threat Actor Identification**: Identifies mentions of known threat actors.
- **Targeted Entities Detection**: Uses spaCy's Named Entity Recognition (NER) and predefined entity lists.
- **Batch Processing**: Processes all PDF files in a given directory.
- **JSON Output**: Saves results for each processed file in a structured JSON format.

## Requirements

- Python 3.8+
- Required Python Libraries:
  - `os`
  - `re`
  - `json`
  - `spacy`
  - `pdfplumber`

Install the required libraries using:
```bash
pip install spacy pdfplumber
```

- Download the spaCy model:
```bash
python -m spacy download en_core_web_sm
```

## Configuration

### Malware Signatures
The `MALWARE_SIGNATURES` dictionary defines malware names, associated keywords, and potential targets. Example:
```python
MALWARE_SIGNATURES = {
    'Shamoon': {
        'keywords': ['disk wiping', 'destructive', 'saudi aramco', 'energy sector'],
        'targets': ['energy', 'oil', 'saudi arabia', 'middle east']
    }
}
```
### Threat Actors
List known threat actors in the `THREAT_ACTORS` variable:
```python
THREAT_ACTORS = ['APT33', 'Fancy Bear', 'Lazarus Group', 'Cozy Bear']
```
### Targeted Entities
Predefine the entities of interest in the `TARGETED_ENTITIES` list:
```python
TARGETED_ENTITIES = ['Energy Sector', 'Financial Institutions', 'Government Agencies']
```

## Usage

1. Place all the PDF files you want to process in a directory.
2. Update the `directory_path` variable in the `main` function with the path to your directory.
3. Run the script:
```bash
python Code.py
```
4. Extracted results are saved as JSON files in a `JSON_Results` subdirectory within the specified directory.

## Example Output
For a PDF file `example.pdf`, the output JSON structure will look like:
```json
{
    "IoCs": {
        "IP_addresses": ["192.168.1.1"],
        "Domains": ["example.com"],
        "File_Hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "Email_Addresses": ["example@example.com"]
    },
    "Malware": [
        {
            "Name": "Shamoon",
            "Keywords": ["disk wiping", "destructive"],
            "Potential_Targets": ["energy"]
        }
    ],
    "Threat_Actors": ["APT33"],
    "Targeted_Entities": ["Energy Sector"]
}
```

## Directory Structure
```
project/
│
├── script.py         # Main script
├── JSON_Results/     # Output folder for JSON files
├── example.pdf       # Sample PDF for testing
```

## Troubleshooting

- Ensure the `directory_path` points to an existing directory.
- Verify that the spaCy model is downloaded:
  ```bash
  python -m spacy download en_core_web_sm
  ```
- Check for missing libraries and install them as needed.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Feel free to submit issues or pull requests for improvements or additional features!

