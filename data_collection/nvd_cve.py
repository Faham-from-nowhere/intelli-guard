import requests
import json
import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cve_details(cve_id: str) -> dict | None:
    """
    Fetches details for a given CVE ID from the NVD API.
    Args:
        cve_id (str): The CVE ID (e.g., "CVE-2023-1234").
    Returns:
        dict: A dictionary containing CVE details if found, otherwise None.
    """
    params = {"cveId": cve_id}
    try:
        response = requests.get(NVD_API_BASE_URL, params=params)
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json()

        # NVD API returns 'vulnerabilities' array
        if data and 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            # Return the first (and usually only) vulnerability matching the ID
            return data['vulnerabilities'][0]['cve']
        else:
            print(f"CVE details not found for {cve_id}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON response from NVD for {cve_id}")
        return None

if __name__ == "__main__":
    # Example Usage:
    test_cve_id = "CVE-2023-38831" # A real, relatively recent CVE
    cve_data = get_cve_details(test_cve_id)

    if cve_data:
        print(f"--- Details for {test_cve_id} ---")
        print(f"Description: {cve_data['descriptions'][0]['value']}")
        # You can explore more fields like metrics, references, etc.
        # print(f"CVSSv3 Score: {cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']}")
    else:
        print(f"Could not retrieve details for {test_cve_id}")

    test_non_existent_cve = "CVE-9999-0000"
    get_cve_details(test_non_existent_cve)