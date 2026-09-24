import re
import csv
from pathlib import Path
import logging
import requests

logging.basicConfig(level=logging.INFO)

def extract_indicators(file):

    unique_set_hashes = set()

    log_path = Path(file)
    
    if not log_path.exists():
        logging.error("File Not Found In Local Drive!")

    else:
        with log_path.open(mode='r', encoding='utf-8') as file:
            for line in file:

                sha256_hash_sequence = re.findall(r"\b[a-fA-F0-9]{64}\b", line)
                md5_hash_sequence = re.findall(r"\b[a-fA-F0-9]{32}\b", line)
                
                if sha256_hash_sequence:
                    for match in sha256_hash_sequence:
                           unique_set_hashes.add(match)

                if md5_hash_sequence:
                    for match_md5 in md5_hash_sequence:
                        unique_set_hashes.add(match_md5)

            return (unique_set_hashes)

def enrich_threat_data(unique_set_hashes):

    Threat_list = []
    headers = {"x-apikey": "bae293816ad20e036bd20996e0ead3e087df929305a50206a4b6a2c3064b994e"}

    for hash in unique_set_hashes:
        virustotal_url = f"https://www.virustotal.com/api/v3/files/{hash}"

        try:
            response = requests.get(virustotal_url, headers=headers, timeout=15)

        except Exception as error:
            logging.error(f"Unexpected error occured: {error}")

        else:
            
            if response.status_code == 404:
                logging.info("Hash is unknown to current validation threat intelligence database.")
        
            elif response.status_code == 200: 
                
                logging.info("Request Successfully Completed!")

                response_dictionary = response.json()

                malicious_score = response_dictionary.get("data").get("attributes").get("last_analysis_stats").get("malicious")

                Threat_Dictionary = {"target_hash": hash, 
                                    "malicious_score": malicious_score}

                if len(hash) == 32:
                    Threat_Dictionary["hash_type"] = "MD5"

                else:
                    Threat_Dictionary["hash_type"] = "SHA-256"

                Threat_list.append(Threat_Dictionary)

            else:
                logging.warning(f"API Lookup failed with status code: {response.status_code}")

    return Threat_list

def export_threat_csv(threat_list):
    log_path = Path("data/enriched_threats.csv")

    with log_path.open(mode='w', encoding='utf-8', newline="") as file:

        writer = csv.DictWriter(file, fieldnames=["target_hash", "hash_type", "malicious_score"])

        writer.writeheader()
        writer.writerows(threat_list)

    file_path = Path("data/enriched_threats.csv")

    if file_path.exists():
        logging.info("CSV Report File Found!")

        with file_path.open(mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)

            logging.info("File accessed for reading.")

            return list(reader)

if __name__ == "__main__":
    hashes = extract_indicators("data/raw_endpoint_logs.txt")
    list_ = enrich_threat_data(hashes)
    export_threat_csv(list_)
