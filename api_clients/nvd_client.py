# D:\The intelligent guardian\api_clients\nvd_client.py

import os
import requests
from dotenv import load_dotenv
from utils.logger import logger # Assuming you have a logger setup

load_dotenv() # Load environment variables from .env file

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cve_details(cve_id: str) -> dict | None:
    """
    Fetches details for a specific CVE ID from the NVD API.
    Requires NVD_API_KEY to be set in the .env file for full access.
    """
    if not NVD_API_KEY:
        logger.warning("NVD_API_KEY is not set. Proceeding without API key, which might result in rate limiting or limited data.")
        headers = {}
    else:
        headers = {"apiKey": NVD_API_KEY}

    params = {"cveId": cve_id}

    try:
        logger.info(f"Fetching CVE details for {cve_id} from NVD...")
        response = requests.get(NVD_API_BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        if data and data.get("vulnerabilities"):
            # NVD API returns a list of vulnerabilities, take the first one matching the ID
            for vuln_entry in data["vulnerabilities"]:
                if vuln_entry["cve"]["id"] == cve_id:
                    logger.info(f"Successfully fetched CVE data for {cve_id}.")
                    return vuln_entry["cve"]

        logger.warning(f"CVE ID {cve_id} not found or no vulnerabilities returned by NVD.")
        return None

    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            logger.error(f"NVD API Error: 403 Forbidden. Check your NVD_API_KEY or rate limits. {e}")
        elif response.status_code == 404:
            logger.error(f"NVD API Error: 404 Not Found for {cve_id}. {e}")
        else:
            logger.error(f"HTTP error fetching CVE {cve_id}: {e} - Response: {response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error fetching CVE {cve_id}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout error fetching CVE {cve_id}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"An unexpected error occurred while fetching CVE {cve_id}: {e}")
        return None
    except ValueError as e: # For JSON decoding errors
        logger.error(f"Error decoding JSON response from NVD for CVE {cve_id}: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    test_cve_id = "CVE-2023-38831" # A recent example CVE
    cve_info = get_cve_details(test_cve_id)
    if cve_info:
        print(f"\n--- Details for {test_cve_id} ---")
        print(f"Description: {cve_info['descriptions'][0]['value']}")
        if 'metrics' in cve_info and 'cvssMetricV31' in cve_info['metrics']:
            print(f"CVSS v3.1 Base Score: {cve_info['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']}")
        else:
            print("CVSS v3.1 metrics not available.")
        print("-" * 30)
    else:
        print(f"Failed to retrieve or parse CVE details for {test_cve_id}.")