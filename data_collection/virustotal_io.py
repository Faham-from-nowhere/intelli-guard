import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

def get_virustotal_ip_report(ip_address: str) -> dict | None:
    """
    Fetches a report for an IP address from VirusTotal.
    Args:
        ip_address (str): The IP address to query.
    Returns:
        dict: A dictionary containing the VirusTotal report, otherwise None.
    """
    if not VIRUSTOTAL_API_KEY:
        print("VIRUSTOTAL_API_KEY not set in .env")
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VirusTotal IP report for {ip_address}: {e}")
        if response and response.status_code == 401:
            print("VirusTotal API key might be invalid or expired.")
        elif response and response.status_code == 429:
            print("Rate limit exceeded for VirusTotal API. Please wait.")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON response from VirusTotal for {ip_address}")
        return None

def get_virustotal_file_report(file_hash: str) -> dict | None:
    """
    Fetches a report for a file hash (MD5, SHA1, SHA256) from VirusTotal.
    Args:
        file_hash (str): The hash of the file to query.
    Returns:
        dict: A dictionary containing the VirusTotal report, otherwise None.
    """
    if not VIRUSTOTAL_API_KEY:
        print("VIRUSTOTAL_API_KEY not set in .env")
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VirusTotal file report for {file_hash}: {e}")
        if response and response.status_code == 401:
            print("VirusTotal API key might be invalid or expired.")
        elif response and response.status_code == 429:
            print("Rate limit exceeded for VirusTotal API. Please wait.")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON response from VirusTotal for {file_hash}")
        return None

if __name__ == "__main__":
    # Example Usage:
    # --- IP Address ---
    test_ip = "8.8.8.8" # Google DNS - should be harmless
    ip_report = get_virustotal_ip_report(test_ip)
    if ip_report and 'data' in ip_report and 'attributes' in ip_report['data']:
        print(f"\n--- VirusTotal IP Report for {test_ip} ---")
        last_analysis_stats = ip_report['data']['attributes'].get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)
        undetected_count = last_analysis_stats.get('undetected', 0)
        print(f"Malicious detections: {malicious_count}")
        print(f"Undetected: {undetected_count}")
        if malicious_count > 0:
            print("This IP has malicious detections!")
    else:
        print(f"Could not retrieve VirusTotal IP report for {test_ip}")

    # --- File Hash ---
    # Example of a known harmless file (notepad.exe on Windows, SHA256) - might vary
    # Use a real hash for testing if you have one, or look up a known good hash.
    # For demonstration, let's use a dummy hash or a known malicious one if safe to do so.
    # A known malicious hash (example for demonstration - DO NOT DOWNLOAD OR EXECUTE!)
    # This is a sample SHA256 for a common malware family, use with caution for API query only.
    malicious_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" # Example malware hash (WannaCry related)
    file_report = get_virustotal_file_report(malicious_hash)
    if file_report and 'data' in file_report and 'attributes' in file_report['data']:
        print(f"\n--- VirusTotal File Report for {malicious_hash} ---")
        last_analysis_stats = file_report['data']['attributes'].get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)
        undetected_count = last_analysis_stats.get('undetected', 0)
        print(f"Malicious detections: {malicious_count}")
        print(f"Undetected: {undetected_count}")
        if malicious_count > 0:
            print("This file hash has malicious detections!")
            # You might want to print specific vendor detections
            # print(file_report['data']['attributes']['last_analysis_results'])
    else:
        print(f"Could not retrieve VirusTotal file report for {malicious_hash}")