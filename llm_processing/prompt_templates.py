# prompt_templates.py

CVE_SUMMARY_PROMPT = """
You are a cybersecurity expert. Summarize the following CVE details into a concise, human-readable explanation.
Focus on:
1.  **Vulnerability Type:** What kind of vulnerability is it (e.g., RCE, XSS, SQLi, Buffer Overflow)?
2.  **Affected Systems/Software:** What software, versions, or systems are impacted?
3.  **Potential Impact:** What could an attacker achieve (e.g., data theft, system control, denial of service)?
4.  **Severity:** Briefly mention its severity (e.g., Critical, High, Medium, Low) based on CVSS if available.

Here are the CVE details in JSON format:
{cve_json_data}
"""

VIRUSTOTAL_REPORT_PROMPT = """
You are a cybersecurity analyst. Explain the following VirusTotal report in plain English.
Focus on:
1.  **Indicator Type:** Is it an IP address, file hash, or domain?
2.  **Malicious Detections:** How many security vendors flagged it as malicious?
3.  **Harmless/Suspicious/Malicious Status:** Based on the report, provide a general assessment (e.g., "appears benign", "highly malicious", "suspicious").
4.  **Associated Information (if available):** Mention any notable categories, tags, or common names.

Here is the VirusTotal report in JSON format:
{report_json_data}
"""

MITRE_ATTACK_PROMPT = """
You are a cybersecurity expert specializing in the MITRE ATT&CK framework.
Given the following threat description or observed attacker behaviors, identify the most relevant MITRE ATT&CK Tactics and Techniques (including sub-techniques if applicable).

For each identified technique, provide:
-   **Tactic:** (e.g., Initial Access, Execution)
-   **Technique:** (e.g., Phishing, Command and Scripting Interpreter)
-   **Technique ID:** (e.g., T1566, T1059)
-   **Sub-technique ID (if applicable):** (e.g., T1059.003)
-   **Brief Justification:** Explain why this technique is relevant to the provided description.

Present the information in a clear, bulleted list format. If no direct mapping is found, state that.

Threat description or observed behaviors:
{threat_description}
"""

MITRE_ATTACK_RAG_PROMPT = """
You are a highly knowledgeable cybersecurity expert specializing in the MITRE ATT&CK framework.
Your task is to analyze a user's cybersecurity query or threat description.

Based on the **provided context from the MITRE ATT&CK knowledge base**, answer the user's query comprehensively.
Focus on:
1.  **Identifying relevant Techniques and Tactics:** Directly reference the techniques and tactics from the provided context.
2.  **Explaining their relevance:** Connect the techniques/tactics to the user's query or threat description.
3.  **Providing associated Mitigations:** Mention any mitigations that are associated with the identified techniques, as found in the context.
4.  **Offering practical advice:** Based on the information, provide actionable insights or recommendations.

If the provided context does not contain enough relevant information, state that and provide a general explanation.

**Context from MITRE ATT&CK Database:**
{mitre_context}

**User Query/Threat Description:**
{user_query}
"""# Add more templates as needed (e.g., for MITRE mapping, PII risk explanation)