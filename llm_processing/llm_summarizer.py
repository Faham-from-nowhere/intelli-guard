# llm_processing/llm_summarizer.py

import os
import json
import requests
from dotenv import load_dotenv

# --- Core Imports for Logging and DB Manager ---
from utils.logger import logger # Import the logger instance
from data_processing.vector_db_manager import MITREDbManager # Import the DB manager class
# --- End Core Imports ---

from llm_processing.prompt_templates import CVE_SUMMARY_PROMPT, VIRUSTOTAL_REPORT_PROMPT, MITRE_ATTACK_PROMPT, MITRE_ATTACK_RAG_PROMPT


load_dotenv()

# Initialize mitre_db_manager globally in this module, after loading dotenv
mitre_db_manager = MITREDbManager()

# --- Configuration for Hugging Face Inference API ---
HF_API_TOKEN = os.getenv("HF_API_TOKEN")
HF_MODEL_ID = os.getenv("HF_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.2") # Default model if not in .env
HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL_ID}"
HEADERS = {"Authorization": f"Bearer {HF_API_TOKEN}"}

def get_llm_response(prompt: str, model: str = HF_MODEL_ID, temperature: float = 0.7) -> str | None:
    """
    Sends a prompt to the Hugging Face Inference API and returns the response.
    Args:
        prompt (str): The prompt for the LLM.
        model (str): The Hugging Face model ID (defaults to HF_MODEL_ID).
        temperature (float): Controls creativity.
    Returns:
        str: The LLM's generated response, or None if an error occurs.
    """
    if not HF_API_TOKEN:
        logger.warning("HF_API_TOKEN not set in .env. Cannot use Hugging Face LLM.")
        return None

    # Hugging Face Inference API expects inputs in a specific way for text generation
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 500, # Limit the length of the generated response
            "temperature": temperature,
            "return_full_text": False, # We only want the generated text, not the prompt repeated
            "do_sample": True # Enable sampling for more creative output
        }
    }

    try:
        response = requests.post(HF_API_URL, headers=HEADERS, json=payload)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        result = response.json()

        if isinstance(result, list) and len(result) > 0 and 'generated_text' in result[0]:
            return result[0]['generated_text'].strip()
        else:
            logger.error(f"Unexpected Hugging Face response format: {result}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error calling Hugging Face API for model {model}: {e}", exc_info=True)
        if response is not None:
            if response.status_code == 401:
                logger.error("Hugging Face API token might be invalid.")
            elif response.status_code == 429:
                logger.warning("Hugging Face Inference API rate limit exceeded. Please wait and try again.")
            elif response.status_code == 503:
                logger.warning(f"Hugging Face model '{model}' is currently loading or unavailable. Please try again in a moment.")
            else:
                logger.error(f"Server response: {response.text}")
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON response from Hugging Face for {model}")
        return None

def summarize_cve_with_llm(cve_data: dict) -> str | None:
    """
    Uses LLM to summarize CVE details.
    Args:
        cve_data (dict): The raw CVE data from NVD.
    Returns:
        str: A human-readable summary, or None.
    """
    if not cve_data:
        return "No CVE data provided for summarization."

    prompt = CVE_SUMMARY_PROMPT.format(cve_json_data=json.dumps(cve_data, separators=(',', ':')))
    return get_llm_response(prompt)

def explain_virustotal_report_with_llm(report_data: dict) -> str | None:
    """
    Uses LLM to explain a VirusTotal report.
    Args:
        report_data (dict): The raw VirusTotal report.
    Returns:
        str: A human-readable explanation, or None.
    """
    if not report_data:
        return "No VirusTotal report provided for explanation."

    prompt = VIRUSTOTAL_REPORT_PROMPT.format(report_json_data=json.dumps(report_data, separators=(',', ':')))
    return get_llm_response(prompt)


def map_to_mitre_attack_with_llm(threat_description: str) -> str | None:
    """
    Uses LLM to map a threat description to MITRE ATT&CK tactics and techniques.
    Args:
        threat_description (str): A description of threat behavior or an incident.
    Returns:
        str: A human-readable mapping to MITRE ATT&CK, or None.
    """
    if not threat_description:
        return "No threat description provided for MITRE ATT&CK mapping."

    prompt = MITRE_ATTACK_PROMPT.format(threat_description=threat_description)
    return get_llm_response(prompt)


def retrieve_mitre_context(query: str) -> str:
    """
    Retrieves relevant MITRE ATT&CK techniques and their associated mitigations
    from the local ChromaDB based on the query.
    """
    try:
        techniques_collection = mitre_db_manager.get_or_create_collection("techniques")
        mitigations_collection = mitre_db_manager.get_or_create_collection("mitigations")

        logger.debug(f"Techniques collection contains {techniques_collection.count()} documents.")
        logger.debug(f"Mitigations collection contains {mitigations_collection.count()} documents.")

        # --- MODIFICATION HERE: Increased n_results ---
        query_results = techniques_collection.query(
            query_texts=[query],
            n_results=20, # Fetch more results to increase the chance of catching all concepts
            include=['documents', 'metadatas', 'distances']
        )
        # --- END MODIFICATION ---

        logger.debug(f"Raw technique query results for '{query}':\n{json.dumps(query_results, indent=2)}")

        retrieved_techniques = []
        if query_results and query_results['metadatas'] and query_results['documents']:
            for i in range(len(query_results['ids'][0])):
                metadata = query_results['metadatas'][0][i]
                # doc = query_results['documents'][0][i] # 'doc' is not used directly in current formatting
                similarity_score = 1 - query_results['distances'][0][i] # Convert distance to similarity (0 to 1)

                associated_mitigations = []
                if 'associated_mitigations' in metadata and metadata['associated_mitigations']:
                    mitigation_ids = [m_id.strip() for m_id in metadata['associated_mitigations'].split(';') if m_id.strip()]
                    
                    unique_mitigation_ids = []
                    for mid in mitigation_ids:
                        if mid.startswith("ID: "):
                            actual_id = mid.replace("ID: ", "").strip()
                            if actual_id and actual_id not in unique_mitigation_ids:
                                unique_mitigation_ids.append(actual_id)
                        else:
                             if mid and mid not in unique_mitigation_ids:
                                unique_mitigation_ids.append(mid)

                    for m_id in unique_mitigation_ids:
                        mitigation_query_results = mitigations_collection.query(
                            query_texts=[m_id],
                            n_results=1,
                            include=['metadatas']
                        )
                        
                        if mitigation_query_results and mitigation_query_results['metadatas'] and len(mitigation_query_results['metadatas'][0]) > 0:
                            m_metadata = mitigation_query_results['metadatas'][0][0]
                            associated_mitigations.append(f"{m_metadata.get('name', m_id)} (ID: {m_metadata.get('id', m_id)})")
                        else:
                            associated_mitigations.append(f"Unknown Mitigation (ID: {m_id})")

                tech_details = {
                    "Technique ID": metadata.get('id', 'N/A'),
                    "Name": metadata.get('name', 'N/A'),
                    "Tactic(s)": metadata.get('tactic', 'N/A'),
                    "Description": metadata.get('description', 'N/A'),
                    "URL": metadata.get('url', 'N/A'),
                    "Similarity Score": f"{similarity_score:.2f} (closer to 1 is more similar)",
                    "Associated Mitigations": ", ".join(associated_mitigations) if associated_mitigations else "None found in database."
                }
                retrieved_techniques.append(tech_details)

        if not retrieved_techniques:
            return "No relevant techniques found in the MITRE ATT&CK database for your query."

        context_string = "### Relevant MITRE ATT&CK Techniques:\n\n"
        for tech in retrieved_techniques:
            context_string += (
                f"**Technique ID:** {tech['Technique ID']}\n"
                f"**Name:** {tech['Name']}\n"
                f"**Tactic(s):** {tech['Tactic(s)']}\n"
                f"**Description:** {tech['Description']}\n"
                f"**URL:** {tech['URL']}\n"
                f"**Similarity Score:** {tech['Similarity Score']}\n"
                f"**Associated Mitigations:** {tech['Associated Mitigations']}\n"
                f"---\n\n"
            )
        return context_string
    except Exception as e:
        logger.error(f"Error during MITRE context retrieval: {e}", exc_info=True)
        return "Error: Could not retrieve MITRE ATT&CK context."


def answer_mitre_query_with_rag(user_query: str) -> str | None:
    """
    Uses RAG to answer a MITRE ATT&CK related query by first retrieving context
    from the local database and then augmenting the LLM prompt.
    """
    if not user_query:
        return "No query provided for MITRE ATT&CK RAG."

    logger.info(f"Retrieving relevant MITRE context for query: '{user_query}'...")
    # Removed the 'n_results=5' from this call, as it's now handled inside retrieve_mitre_context
    retrieved_context = retrieve_mitre_context(user_query)

    logger.info("\n--- Retrieved Context for LLM ---")
    logger.info(retrieved_context)
    logger.info("---------------------------------\n") # Keeping this for consistent console formatting

    prompt = MITRE_ATTACK_RAG_PROMPT.format(
        mitre_context=retrieved_context,
        user_query=user_query
    )
    return get_llm_response(prompt)


if __name__ == "__main__":
    # Example usage (dummy data)
    dummy_cve_data = {
        "id": "CVE-2023-12345",
        "descriptions": [{"value": "A critical buffer overflow vulnerability found in ExampleSoftware version 1.0 allows remote attackers to execute arbitrary code via specially crafted network packets."}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "impactScore": 5.9, "exploitabilityScore": 3.9}]
        },
        "configurations": [
            {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:example:examplesoftware:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "ABCDEF12345"}]}]}
        ]
    }

    logger.info("Testing CVE summary with Hugging Face LLM...")
    cve_summary = summarize_cve_with_llm(dummy_cve_data)
    if cve_summary:
        logger.info("\n--- LLM Summary of CVE-2023-12345 (HF Generated) ---")
        logger.info(cve_summary)
    else:
        logger.warning("Failed to get CVE summary from LLM.")


    dummy_ip_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 70, "suspicious": 5, "harmless": 2, "undetected": 10},
                "as_owner": "MALWARE_HOSTING_PROVIDER_INC",
                "country": "RU",
                "tags": ["malware-distribution", "phishing-c2"]
            },
            "type": "ip_address",
            "id": "1.2.3.4"
        }
    }

    logger.info("\nTesting VirusTotal explanation with Hugging Face LLM...")
    vt_explanation = explain_virustotal_report_with_llm(dummy_ip_report)
    if vt_explanation:
        logger.info("\n--- LLM Explanation of VirusTotal IP Report (HF Generated) ---")
        logger.info(vt_explanation)
    else:
        logger.warning("Failed to get VirusTotal report explanation from LLM.")

    # Re-assign HF_API_TOKEN etc. if this __main__ block is separate and needs its own config
    # HF_API_TOKEN = os.getenv("HF_API_TOKEN") # This might be redundant if defined globally above
    # HF_MODEL_ID = os.getenv("HF_MODEL_ID", "google/gemma-2b-it") # Ensure this is your working model
    # HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL_ID}"
    # HEADERS = {"Authorization": f"Bearer {HF_API_TOKEN}"}


    # Add example for MITRE ATT&CK (LLM-only)
    logger.info("\n" + "="*50)
    logger.info("Testing MITRE ATT&CK Mapping (LLM-only)...")
    example_threat_behavior = "An attacker sent a spear-phishing email with a malicious attachment, then used PowerShell to execute commands and establish persistence via a scheduled task."
    mitre_mapping = map_to_mitre_attack_with_llm(example_threat_behavior)
    if mitre_mapping:
        logger.info("\n--- MITRE ATT&CK Mapping (LLM Generated) ---")
        logger.info(mitre_mapping)
    else:
        logger.warning("Failed to get MITRE ATT&CK mapping from LLM.")

    # Add example for MITRE ATT&CK RAG (new version)
    logger.info("\n" + "="*50)
    logger.info("Testing MITRE ATT&CK RAG with LLM...")
    rag_query = "What are common techniques for initial access and how can they be mitigated?"
    rag_response = answer_mitre_query_with_rag(rag_query)
    if rag_response:
        logger.info("\n--- MITRE ATT&CK RAG Response (LLM Generated) ---")
        logger.info(rag_response)
    else:
        logger.warning("Failed to get MITRE ATT&CK RAG response from LLM.")

    rag_query_specific = "Tell me about PowerShell execution and its defenses."
    rag_response_specific = answer_mitre_query_with_rag(rag_query_specific)
    if rag_response_specific:
        logger.info("\n--- MITRE ATT&CK RAG Response (Specific Query, LLM Generated) ---")
        logger.info(rag_response_specific)
    else:
        logger.warning("Failed to get MITRE ATT&CK RAG response from LLM for specific query.")