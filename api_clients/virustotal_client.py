# D:\The intelligent guardian\api_clients\virustotal_client.py

import os
import requests
from dotenv import load_dotenv
from utils.logger import logger # Assuming you have a logger setup

load_dotenv() # Load environment variables from .env file

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_API_BASE_URL = "https://www.virustotal.com/api/v3"

def _make_vt_request(endpoint: str, identifier: str) -> dict | None:
    """
    Helper function to make requests to the VirusTotal API.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.error("VIRUSTOTAL_API_KEY is not set in .env file. Cannot make VirusTotal API calls.")
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    url = f"{VIRUSTOTAL_API_BASE_URL}/{endpoint}/{identifier}"

    try:
        logger.info(f"Fetching VirusTotal report from: {url}")
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()
        if "data" in data:
            logger.info("Successfully fetched VirusTotal report.")
            return data
        else:
            logger.warning(f"VirusTotal API returned no 'data' for {identifier}: {data.get('error', 'Unknown error')}")
            return None

    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            logger.error(f"VirusTotal API Error: 401 Unauthorized. Check your VIRUSTOTAL_API_KEY. {e}")
        elif response.status_code == 404:
            logger.warning(f"VirusTotal API Error: 404 Not Found for {identifier}. {e}")
        elif response.status_code == 429:
            logger.error(f"VirusTotal API Error: 429 Too Many Requests. Rate limit exceeded. {e}")
        else:
            logger.error(f"HTTP error fetching VirusTotal report for {identifier}: {e} - Response: {response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error fetching VirusTotal report for {identifier}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout error fetching VirusTotal report for {identifier}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"An unexpected error occurred while fetching VirusTotal report for {identifier}: {e}")
        return None
    except ValueError as e: # For JSON decoding errors
        logger.error(f"Error decoding JSON response from VirusTotal for {identifier}: {e}")
        return None

def get_file_report(file_hash: str) -> dict | None:
    """Fetches a file report by its hash (MD5, SHA1, or SHA256)."""
    return _make_vt_request("files", file_hash)

def get_ip_report(ip_address: str) -> dict | None:
    """Fetches an IP address report."""
    return _make_vt_request("ip_addresses", ip_address)

def get_domain_report(domain: str) -> dict | None:
    """Fetches a domain report."""
    return _make_vt_request("domains", domain)

def get_url_report(url: str) -> dict | None:
    """
    Fetches a URL report. Note: URLs need to be URL-safe base64 encoded for VT API.
    This function will handle the encoding.
    """
    import base64
    # Encode URL to URL-safe base64 and remove padding '=' characters
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _make_vt_request("urls", encoded_url)

if __name__ == "__main__":
    # Example usage (replace with actual test data if you have API key set up)
    print("Testing VirusTotal API Client...")

    # Requires a valid VIRUSTOTAL_API_KEY in your .env
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        print("VIRUSTOTAL_API_KEY not set in .env. Skipping live API tests.")
    else:
        # Test File Hash (e.g., EICAR test file hash)
        test_file_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0c"
        file_report = get_file_report(test_file_hash)
        if file_report:
            print(f"\nFile Report for {test_file_hash}:")
            # print(json.dumps(file_report, indent=2)) # Uncomment to see full JSON
            stats = file_report['data']['attributes']['last_analysis_stats']
            print(f"  Malicious: {stats.get('malicious', 0)}")
            print(f"  Undetected: {stats.get('undetected', 0)}")
        else:
            print(f"Failed to get file report for {test_file_hash}.")

        # Test IP Address
        test_ip = "8.8.8.8" # Google DNS (should be harmless)
        ip_report = get_ip_report(test_ip)
        if ip_report:
            print(f"\nIP Report for {test_ip}:")
            # print(json.dumps(ip_report, indent=2))
            country = ip_report['data']['attributes'].get('country', 'N/A')
            print(f"  Country: {country}")
            stats = ip_report['data']['attributes']['last_analysis_stats']
            print(f"  Malicious: {stats.get('malicious', 0)}")
        else:
            print(f"Failed to get IP report for {test_ip}.")

        # Test URL
        test_url = "http://www.google.com"
        url_report = get_url_report(test_url)
        if url_report:
            print(f"\nURL Report for {test_url}:")
            # print(json.dumps(url_report, indent=2))
            stats = url_report['data']['attributes']['last_analysis_stats']
            print(f"  Malicious: {stats.get('malicious', 0)}")
        else:
            print(f"Failed to get URL report for {test_url}.")