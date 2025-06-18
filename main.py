# main.py
import sys
import json
from data_collection.nvd_cve import get_cve_details
from data_collection.virustotal_io import get_virustotal_ip_report, get_virustotal_file_report
# Update import for LLM functions - remove map_to_mitre_attack_with_llm, add answer_mitre_query_with_rag
from llm_processing.llm_summarizer import summarize_cve_with_llm, explain_virustotal_report_with_llm, answer_mitre_query_with_rag
from pii_detection.text_ingestion import extract_text_from_file, extract_text_from_pdf
from pii_detection.pii_analyzer import analyze_pii, format_pii_results
import os
from utils.logger import setup_logging, logger, set_log_level

logger.info("Intelligent Guardian application started.")


def process_cve_request(cve_id: str):
    logger.info(f"Processing CVE: {cve_id}")
    try:
        from data_processing.cve_data_manager import get_cve_details
        from llm_processing.llm_summarizer import summarize_cve_with_llm

        cve_data = get_cve_details(cve_id)
        if not cve_data:
            logger.warning(f"No details found for CVE ID: {cve_id}")
            return

        logger.info("--- CVE Summary (LLM Generated) ---")
        summary = summarize_cve_with_llm(cve_data)
        logger.info(summary)

    except Exception as e:
        logger.error(f"An unexpected error occurred during CVE processing for {cve_id}: {e}", exc_info=True)


def process_virustotal_request(file_hash: str):
    logger.info(f"Processing VirusTotal report for hash: {file_hash}")
    try:
        from data_processing.virustotal_data_manager import get_virustotal_report
        from llm_processing.llm_summarizer import explain_virustotal_report_with_llm

        report_data = get_virustotal_report(file_hash)
        if not report_data:
            logger.warning(f"No report found for hash: {file_hash}")
            return

        logger.info("--- VirusTotal Report Explanation (LLM Generated) ---")
        explanation = explain_virustotal_report_with_llm(report_data)
        logger.info(explanation)

    except Exception as e:
        logger.error(f"An unexpected error occurred during VirusTotal processing for {file_hash}: {e}", exc_info=True)


def process_mitre_request(query: str):
    logger.info(f"Answering MITRE ATT&CK query with RAG: '{query}'")
    try:
        from llm_processing.llm_summarizer import answer_mitre_query_with_rag

        logger.info(f"Retrieving relevant MITRE context for query: '{query}'...")
        rag_response = answer_mitre_query_with_rag(query)

        logger.info("\n--- MITRE ATT&CK RAG Response (LLM Generated) ---")
        logger.info(rag_response)

    except Exception as e:
        logger.error(f"An unexpected error occurred during MITRE RAG processing for query '{query}': {e}", exc_info=True)


def process_pii_scan_request(file_path: str):
    logger.info(f"Scanning '{file_path}' for PII...")
    try:
        from pii_detection.text_ingestion import extract_text_from_file
        from pii_detection.pii_analyzer import analyze_pii, format_pii_results

        extracted_text = extract_text_from_file(file_path)
        if not extracted_text:
            logger.warning("No text extracted from the file. Cannot perform PII scan.")
            return

        pii_results = analyze_pii(extracted_text)
        formatted_output = format_pii_results(pii_results, extracted_text)

        logger.info("\n--- PII Scan Results ---")
        if formatted_output["pii_found"]:
            logger.info(f"PII found: Yes ({formatted_output['total_pii_entities']} entities)")
            for entity in formatted_output["detected_entities"]:
                logger.info(f"  - Type: {entity['entity_type']}")
                logger.info(f"    Text: '{entity['text']}'")
                logger.info(f"    Score: {entity['score']:.2f}")
                logger.info(f"    Context: '...{entity['context_snippet']}...'")
            logger.info("\nConsider reviewing this document for sensitive information.")
        else:
            logger.info("PII found: No")
            logger.info("No significant PII entities detected based on the configured threshold.")

    except FileNotFoundError as e:
        logger.error(f"Error: {e}")
    except ValueError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during PII scan: {e}", exc_info=True)


def main():
    if len(sys.argv) < 2:
        logger.info("Usage: python main.py <command> [args]")
        logger.info("Commands:")
        logger.info("  cve <cve_id>                       - Summarize a CVE (e.g., CVE-2023-1234)")
        logger.info("  virustotal <file_hash>             - Explain a VirusTotal report (e.g., 990145c265...)")
        logger.info("  mitre <query>                      - Answer a MITRE ATT&CK query with RAG (e.g., 'techniques for persistence')")
        logger.info("  scan-pii <file_path>               - Scan a document for PII (e.g., 'document.txt')")
        logger.info("  populate-db                        - Populate the local ChromaDB with MITRE ATT&CK data")
        return

    command = sys.argv[1].lower()

    if command == "cve":
        if len(sys.argv) != 3:
            logger.warning("Usage: python main.py cve <cve_id>")
            return
        cve_id = sys.argv[2]
        process_cve_request(cve_id)

    elif command == "virustotal":
        if len(sys.argv) != 3:
            logger.warning("Usage: python main.py virustotal <file_hash>")
            return
        file_hash = sys.argv[2]
        process_virustotal_request(file_hash)

    elif command == "mitre":
        if len(sys.argv) < 3:
            logger.warning("Usage: python main.py mitre \"<query>\"")
            return
        query = " ".join(sys.argv[2:]) # Join all parts of the query
        process_mitre_request(query)

    elif command == "scan-pii":
        if len(sys.argv) != 3:
            logger.warning("Usage: python main.py scan-pii <file_path>")
            return
        file_path = sys.argv[2]
        if not os.path.exists(file_path):
            logger.error(f"Error: File not found at '{file_path}'. Please check the path and try again.")
            return
        if not os.path.isfile(file_path):
            logger.error(f"Error: '{file_path}' is not a file. Please provide a valid file path.")
            return
        process_pii_scan_request(file_path)

    elif command == "populate-db":
        if len(sys.argv) != 2:
            logger.warning("Usage: python main.py populate-db")
            return
        logger.info("Starting database population. This may take a while...")
        from data_processing.vector_db_manager import populate_vector_db
        populate_vector_db()
    else:
        logger.warning(f"Unknown command: {command}")
    
    logger.info("Intelligent Guardian application finished.")


if __name__ == "__main__":
    main()
