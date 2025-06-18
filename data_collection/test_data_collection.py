import unittest
import os
from unittest.mock import patch, MagicMock
from data_collection.nvd_cve import get_cve_details
from data_collection.virustotal_io import get_virustotal_ip_report, get_virustotal_file_report

# Ensure .env is loaded for tests
from dotenv import load_dotenv
load_dotenv()

class TestDataCollection(unittest.TestCase):

    @patch('requests.get')
    def test_get_cve_details_success(self, mock_get):
        # Mock a successful NVD API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2023-1234", "descriptions": [{"value": "Test CVE Description"}]}}
            ]
        }
        mock_get.return_value = mock_response

        cve_data = get_cve_details("CVE-2023-1234")
        self.assertIsNotNone(cve_data)
        self.assertEqual(cve_data['id'], "CVE-2023-1234")
        self.assertEqual(cve_data['descriptions'][0]['value'], "Test CVE Description")
        mock_get.assert_called_once_with(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": "CVE-2023-1234"}
        )

    @patch('requests.get')
    def test_get_cve_details_not_found(self, mock_get):
        # Mock NVD API response for a non-existent CVE
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []} # Empty vulnerabilities array
        mock_get.return_value = mock_response

        cve_data = get_cve_details("CVE-9999-0000")
        self.assertIsNone(cve_data)

    @patch('requests.get')
    def test_get_cve_details_api_error(self, mock_get):
        # Mock an HTTP error from NVD API
        mock_get.side_effect = requests.exceptions.RequestException("API Error")

        cve_data = get_cve_details("CVE-2023-1234")
        self.assertIsNone(cve_data)

    @patch('requests.get')
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_key'})
    def test_get_virustotal_ip_report_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 80}}}
        }
        mock_get.return_value = mock_response

        report = get_virustotal_ip_report("8.8.8.8")
        self.assertIsNotNone(report)
        self.assertEqual(report['data']['attributes']['last_analysis_stats']['malicious'], 0)
        mock_get.assert_called_once_with(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": "test_key", "Accept": "application/json"}
        )

    @patch('requests.get')
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_key'})
    def test_get_virustotal_file_report_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 50, "undetected": 1}}}
        }
        mock_get.return_value = mock_response

        hash_value = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        report = get_virustotal_file_report(hash_value)
        self.assertIsNotNone(report)
        self.assertEqual(report['data']['attributes']['last_analysis_stats']['malicious'], 50)
        mock_get.assert_called_once_with(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": "test_key", "Accept": "application/json"}
        )

    @patch.dict(os.environ, {}, clear=True) # Ensure API key is not set for this test
    def test_virustotal_no_api_key(self):
        report_ip = get_virustotal_ip_report("1.1.1.1")
        self.assertIsNone(report_ip)

        report_file = get_virustotal_file_report("somehash")
        self.assertIsNone(report_file)


if __name__ == '__main__':
    unittest.main()