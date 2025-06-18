# app.py
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import pandas as pd
import streamlit as st
import os
import sys

# Add the project root to the sys.path to allow absolute imports
# This ensures that imports like 'llm_processing.llm_summarizer' work correctly
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

# Import functions from your existing modules
from llm_processing.llm_summarizer import summarize_cve_with_llm, explain_virustotal_report_with_llm, map_to_mitre_attack_with_llm, answer_mitre_query_with_rag
from api_clients.nvd_client import get_cve_details
from api_clients.virustotal_client import get_file_report, get_ip_report, get_domain_report, get_url_report

from pii_detection.text_ingestion import extract_text_from_file # Kept for .txt files
from pii_detection.pii_analyzer import analyze_pii_with_llm, format_pii_results_llm # Updated imports

# Configure Streamlit page
st.set_page_config(
    page_title="Intelligent Guardian",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Intelligent Guardian")
st.markdown("Your AI-powered assistant for threat intelligence.")

# Sidebar for API Keys and info
st.sidebar.header("Configuration")
with st.sidebar.expander("API Key Setup"):
    st.markdown("Enter your API keys here. They will not be saved.(Only if you encounter No API KEY error))")
    hf_api_token = st.text_input("Hugging Face API Token", type="password", key="hf_token_sidebar")
    vt_api_key = st.text_input("VirusTotal API Key", type="password", key="vt_token_sidebar")
    nvd_api_key = st.text_input("NVD API Key (Optional)", type="password", key="nvd_token_sidebar")

    if hf_api_token:
        os.environ["HF_API_TOKEN"] = hf_api_token
    if vt_api_key:
        os.environ["VIRUSTOTAL_API_KEY"] = vt_api_key
    if nvd_api_key:
        os.environ["NVD_API_KEY"] = nvd_api_key

st.sidebar.markdown("---")
st.sidebar.info("Select a tab to analyze threats using AI and various intel sources.")


# Tabbed interface for different functionalities
tab_cve, tab_virustotal, tab_mitre_map, tab_mitre_rag, tab_PII_Detector = st.tabs([
    "CVE Analysis",
    "VirusTotal Scan",
    "MITRE ATT&CK Mapping (LLM)",
    "MITRE ATT&CK RAG",
    "PII Detector"
])

with tab_cve:
    st.header("CVE Vulnerability Analysis")
    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2023-1234)", key="cve_input")
    if st.button("Analyze CVE"):
        if cve_id:
            with st.spinner(f"Fetching and analyzing {cve_id}..."):
                cve_data = get_cve_details(cve_id)
                if cve_data:
                    st.subheader(f"Raw CVE Data for {cve_id}")
                    st.json(cve_data) # Display raw JSON for debugging/transparency
                    
                    st.subheader(f"AI Summary for {cve_id}")
                    cve_summary = summarize_cve_with_llm(cve_data)
                    if cve_summary:
                        st.write(cve_summary)
                    else:
                        st.error("Failed to get AI summary for CVE.")
                else:
                    st.error(f"Could not retrieve details for CVE ID: {cve_id}. Please check the ID.")
        else:
            st.warning("Please enter a CVE ID.")

with tab_virustotal:
    st.header("VirusTotal Report Explanation")
    vt_type = st.radio("Select type of indicator:", ["File Hash", "IP Address", "Domain", "URL"], key="vt_type")
    vt_indicator = st.text_input(f"Enter {vt_type}:", key="vt_indicator")

    if st.button("Get VirusTotal Report"):
        if vt_indicator:
            report_data = None
            with st.spinner(f"Fetching VirusTotal report for {vt_indicator}..."):
                if vt_type == "File Hash":
                    report_data = get_file_report(vt_indicator)
                elif vt_type == "IP Address":
                    report_data = get_ip_report(vt_indicator)
                elif vt_type == "Domain":
                    report_data = get_domain_report(vt_indicator)
                elif vt_type == "URL":
                    report_data = get_url_report(vt_indicator)

                if report_data:
                    st.subheader(f"Raw VirusTotal Report for {vt_indicator}")
                    st.json(report_data)

                    st.subheader(f"AI Explanation for {vt_indicator}")
                    explanation = explain_virustotal_report_with_llm(report_data)
                    if explanation:
                        st.write(explanation)
                    else:
                        st.error("Failed to get AI explanation for VirusTotal report.")
                else:
                    st.error(f"Could not retrieve VirusTotal report for {vt_indicator}. Check indicator and API key.")
        else:
            st.warning(f"Please enter a {vt_type}.")

with tab_mitre_map:
    st.header("MITRE ATT&CK Mapping (LLM-only)")
    threat_description_map = st.text_area(
        "Describe the threat behavior:",
        "An attacker sent a spear-phishing email with a malicious attachment, then used PowerShell to execute commands and establish persistence via a scheduled task.",
        height=150,
        key="mitre_map_input"
    )
    if st.button("Map to MITRE ATT&CK"):
        if threat_description_map:
            with st.spinner("Mapping threat to MITRE ATT&CK..."):
                mitre_mapping = map_to_mitre_attack_with_llm(threat_description_map)
                if mitre_mapping:
                    st.subheader("LLM-Generated MITRE ATT&CK Mapping")
                    st.markdown(mitre_mapping) # Use markdown to render bolding, lists etc.
                else:
                    st.error("Failed to map threat to MITRE ATT&CK.")
        else:
            st.warning("Please provide a threat description.")

with tab_mitre_rag:
    st.header("MITRE ATT&CK RAG Query")
    mitre_rag_query = st.text_area(
        "Ask a question about MITRE ATT&CK (e.g., 'What are common techniques for initial access and how can they be mitigated?')",
        "An attacker sent a spear-phishing email with a malicious attachment, then used PowerShell to execute commands and establish persistence via a scheduled task.",
        height=150,
        key="mitre_rag_input"
    )
    if st.button("Get RAG Answer"):
        if mitre_rag_query:
            # You might want to temporarily redirect logging for Streamlit or clean it up.
            # For now, let's assume default logging to console is fine, and Streamlit will display the final answer.
            with st.spinner("Retrieving context and generating RAG answer..."):
                rag_response = answer_mitre_query_with_rag(mitre_rag_query)
                if rag_response:
                    st.subheader("LLM-Generated RAG Answer")
                    st.markdown(rag_response) # Use markdown to render bolding, lists etc.
                else:
                    st.error("Failed to get RAG answer for MITRE ATT&CK query.")
        else:
            st.warning("Please enter a query.")

with tab_PII_Detector:
    st.header("Personally Identifiable Information (PII) Detector (LLM-based)")
    st.markdown("Upload a text document or paste text to scan for PII. Note: PDF extraction is simplified for direct text content and might not preserve complex formatting.")

    pii_input_method = st.radio(
        "Choose input method:",
        ("Paste Text", "Upload File"),
        key="pii_input_method"
    )

    extracted_text = ""
    if pii_input_method == "Paste Text":
        text_to_analyze = st.text_area("Paste text here:", height=200, key="pii_text_input")
        extracted_text = text_to_analyze
    else: # Upload File
        uploaded_file = st.file_uploader("Upload a document (.txt, .pdf)", type=["txt", "pdf"], key="pii_file_uploader")
        if uploaded_file is not None:
            file_extension = uploaded_file.name.split('.')[-1].lower()
            if file_extension == "txt":
                try:
                    # Streamlit uploaded files are BytesIO objects
                    extracted_text = uploaded_file.getvalue().decode("utf-8")
                except Exception as e:
                    st.error(f"Error decoding text file: {e}")
                    extracted_text = ""
            elif file_extension == "pdf":
                with st.spinner("Extracting text from PDF..."):
                    from io import BytesIO
                    from pypdf import PdfReader # Ensure pypdf is imported here for direct use
                    try:
                        pdf_bytes = BytesIO(uploaded_file.getvalue())
                        reader = PdfReader(pdf_bytes)
                        text_content = ""
                        for page in reader.pages:
                            text_content += page.extract_text() or ""
                        extracted_text = text_content.strip()
                    except Exception as e:
                        st.error(f"Error extracting text from PDF: {e}")
                        extracted_text = ""
            if not extracted_text:
                st.warning("Could not extract text from the uploaded file.")


    if st.button("Detect PII"):
        if extracted_text:
            with st.spinner("Analyzing text for PII using LLM..."):
                # Call the new LLM-based PII analysis function
                llm_pii_output = analyze_pii_with_llm(extracted_text)
                
                if llm_pii_output:
                    formatted_results = format_pii_results_llm(llm_pii_output)
                    
                    if formatted_results:
                        st.subheader("Detected PII (LLM-Generated)")
                        st.write("The LLM identified the following potential PII entities:")
                        
                        # Display results in a table
                        st.dataframe(pd.DataFrame(formatted_results))

                        st.subheader("LLM's Raw Output (for verification)")
                        st.code(llm_pii_output)
                        
                        # Optional: Highlight text based on LLM output (more complex, might not be precise)
                        # For simple display, just showing the raw output is fine with LLM-based PII
                        st.info("Note: LLM-based PII detection might not always provide exact character positions for highlighting like rule-based systems. Review the 'Detected PII' table and 'LLM's Raw Output' for details.")

                    else:
                        st.info("No PII detected by the LLM in the provided text.")
                        st.subheader("LLM's Raw Output")
                        st.code(llm_pii_output) # Show why it didn't find any, if LLM output gives clue
                else:
                    st.error("Failed to get PII analysis from the LLM. Check API token and LLM availability.")
        else:
            st.warning("Please provide text or upload a file for PII detection.")
