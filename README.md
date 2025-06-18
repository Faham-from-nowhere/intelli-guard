# 🛡️ Intelligent Guardian: AI-Powered Threat & Privacy Intelligence

## Project Title: Intelligent Guardian: AI-Powered Threat & Privacy Intelligence

## Brief Tagline/One-Liner
An AI-driven cybersecurity assistant integrating real-time threat intelligence, MITRE ATT&CK insights, and sensitive data (PII) detection for comprehensive digital defense.

## Primary Categories
AI/ML, Cybersecurity, Full-Stack, Data Science

## Overview
The Intelligent Guardian is a powerful Streamlit-based web application designed to assist cybersecurity professionals, researchers, and anyone concerned with data privacy. It unifies several critical security analysis capabilities into a single, intuitive interface: fetching and summarizing CVE vulnerabilities, explaining VirusTotal reports, mapping threat behaviors to MITRE ATT&CK, providing contextual answers via RAG from the MITRE framework, and detecting Personally Identifiable Information (PII) in documents.

By leveraging Large Language Models (LLMs) and local vector databases, the project demonstrates how AI can streamline complex security analysis and enhance decision-making.

## Key Features

* **CVE Analysis:** Obtain detailed Common Vulnerabilities and Exposures (CVE) information from the NVD API, with an AI-generated summary highlighting severity and impact.
* **VirusTotal Scan & Explanation:** Query file hashes, IP addresses, domains, or URLs via the VirusTotal API, and receive an LLM-powered explanation of the threat intelligence report.
* **MITRE ATT&CK Mapping:** Input a natural language description of observed threat behavior, and the LLM will identify and map it to relevant MITRE ATT&CK techniques and tactics.
* **MITRE ATT&CK RAG (Retrieval Augmented Generation):** Ask specific questions about MITRE ATT&CK techniques, tactics, or mitigations. The system retrieves relevant context from a local ChromaDB vector store and generates an informed answer using the LLM.
* **PII Detector:** Scan text directly or upload `.txt` or `.pdf` files to identify and list Personally Identifiable Information (PII) using an LLM-based detection approach.
* **Command-Line Interface (CLI):** A `main.py` script provides direct command-line access for specific functionalities like populating the MITRE database or performing quick analyses.

## How It Works (High-Level Architecture)
The Intelligent Guardian operates through several interconnected modules:

1.  **Frontend (Streamlit):** Provides the interactive web interface, allowing users to input data and visualize analysis results.
2.  **API Clients:** Dedicated modules (`nvd_client.py`, `virustotal_client.py`) handle secure communication with external threat intelligence APIs.
3.  **LLM Processing:** The `llm_summarizer.py` module orchestrates all interactions with the Hugging Face LLM (Mistral-7B-Instruct-v0.3), including prompt engineering for summarization, mapping, Q&A, and PII detection.
4.  **Vector Database (ChromaDB):** `vector_db_manager.py` handles the local ChromaDB instance (`mitre_attack.db`), which stores MITRE ATT&CK data. `Sentence-Transformers` are used to create embeddings for efficient semantic search within this database for RAG queries.
5.  **Data Processing:** `text_ingestion.py` handles parsing text from various document formats for PII analysis. `pii_analyzer.py` contains the LLM-based logic for identifying PII.
6.  **CLI Utilities:** `main.py` provides a command-line interface for tasks like initializing the MITRE database or performing quick, scriptable analyses.

## Technologies Used

* **Languages:** Python 3.9+
* **Web Framework:** Streamlit
* **Machine Learning/NLP:**
    * Hugging Face Transformers (for LLM inference)
    * Hugging Face `InferenceClient`
    * Sentence-Transformers
    * `torch` (PyTorch)
* **Vector Database:** ChromaDB
* **API Clients:** `requests`
* **Data Handling:** `pandas`, `json`
* **PDF Processing:** `pypdf`
* **Environment Management:** `python-dotenv`
* **Logging:** `logging` module (with a `utils/logger.py` if present)
* **Testing:** `unittest` (for `test_data_collection.py`)

## Setup (Local Development)

Follow these steps to set up and run the Intelligent Guardian on your local machine.

### Prerequisites

* Python 3.9 or higher
* Git

### 1. Clone the Repository

```bash
git clone [https://github.com/Faham-from-nowhere/Intelligent-Guardian.git](https://github.com/your-username/Intelligent-Guardian.git)
cd Intelligent-Guardian