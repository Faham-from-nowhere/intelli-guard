# pii_detection/pii_analyzer.py

import json
from typing import List, Dict, Union

# Import the LLM function from your llm_summarizer module
# Assuming llm_summarizer.py is in llm_processing/
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)
from llm_processing.llm_summarizer import get_llm_response # We need a generic LLM call here

# Function to analyze PII using the LLM
def analyze_pii_with_llm(text: str) -> str | None:
    """
    Analyzes text for PII using an LLM.
    The LLM is prompted to identify and list PII entities.
    """
    if not text:
        return None

    prompt = f"""
    Analyze the following text and identify any Personally Identifiable Information (PII).
    List each detected PII entity, its type (e.g., Name, Email, Phone Number, Address, SSN, Credit Card Number), and the actual value found.
    If no PII is found, state 'No PII detected.'.

    Text:
    "{text}"

    Output in a structured format, for example:
    - Type: Name, Value: John Doe
    - Type: Email, Value: john.doe@example.com
    - Type: Phone Number, Value: (123) 456-7890
    """
    
    # Use your generic LLM response function
    response = get_llm_response(prompt) # Assuming get_llm_response exists and works
    return response

# This function might not be as detailed as Presidio's but provides a structured output
def format_pii_results_llm(llm_output: str) -> List[Dict[str, Union[str, str]]]:
    """
    Parses LLM output into a list of dictionaries.
    Assumes LLM output is in a simple "- Type: X, Value: Y" format,
    but is more robust to leading/trailing whitespace.
    """
    formatted_data = []
    if not llm_output or "No PII detected" in llm_output:
        # If the LLM explicitly states no PII or output is empty, return empty list
        return formatted_data

    # Split lines and clean them up
    lines = llm_output.strip().split('\n')
    for line in lines:
        cleaned_line = line.strip()
        if cleaned_line.startswith('- Type:'):
            try:
                # Use find to locate the first comma, then split
                # This handles cases where 'Type' or 'Value' itself might contain commas
                type_end_index = cleaned_line.find(', Value:')
                if type_end_index != -1:
                    entity_type = cleaned_line[len('- Type:'):type_end_index].strip()
                    value = cleaned_line[type_end_index + len(', Value:'):].strip()
                    
                    if entity_type and value: # Ensure both parts are non-empty
                        formatted_data.append({
                            "entity_type": entity_type,
                            "value": value
                        })
            except Exception as e:
                print(f"Warning: Could not parse LLM output line '{line}'. Error: {e}")
                # Optionally add unparsed lines for debugging:
                # formatted_data.append({"entity_type": "Parse Error", "value": line.strip()})
    return formatted_data



if __name__ == "__main__":
    # This __main__ block is for testing this module independently.
    # It will require your LLM API token to be set as an environment variable.
    import os
    from dotenv import load_dotenv
    load_dotenv() # Load .env variables for local testing

    test_text_1 = "My name is John Doe, and my email is john.doe@example.com. My phone number is (123) 456-7890. I live at 123 Main St, Anytown, CA 90210. My Social Security number is 987-65-4321. My credit card is 1234-5678-9012-3456."
    print("--- Analyzing Test Text 1 with LLM ---")
    llm_pii_output_1 = analyze_pii_with_llm(test_text_1)
    print("LLM Raw Output:")
    print(llm_pii_output_1)
    
    formatted_1 = format_pii_results_llm(llm_pii_output_1)
    print("\nFormatted PII Results:")
    for pii_item in formatted_1:
        print(json.dumps(pii_item, indent=2))

    test_text_2 = "This document contains no PII."
    print("\n--- Analyzing Test Text 2 with LLM ---")
    llm_pii_output_2 = analyze_pii_with_llm(test_text_2)
    print("LLM Raw Output:")
    print(llm_pii_output_2)
    formatted_2 = format_pii_results_llm(llm_pii_output_2)
    if not formatted_2:
        print("No PII detected.")