# pii_detection/text_ingestion.py

import io
from pypdf import PdfReader # PyPDF2 is often easier to install and use than pdfminer.six directly for simple text extraction. Let's use this.
import pandas as pd
import json

def extract_text_from_pdf(file_path: str) -> str | None:
    """
    Extracts text from a PDF file.
    Args:
        file_path (str): Path to the PDF file.
    Returns:
        str: Extracted text, or None if an error occurs.
    """
    try:
        with open(file_path, "rb") as f:
            reader = PdfReader(f)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or "" # extract_text might return None
            return text.strip()
    except FileNotFoundError:
        print(f"Error: PDF file not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error extracting text from PDF {file_path}: {e}")
        return None

def extract_text_from_file(file_path: str) -> str | None:
    """
    Extracts text from a plain text file.
    Args:
        file_path (str): Path to the text file.
    Returns:
        str: Extracted text, or None if an error occurs.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Text file not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error extracting text from file {file_path}: {e}")
        return None

# Placeholder for other ingestion methods (e.g., JSON, CSV, API)
def extract_text_from_json(json_data: dict) -> str:
    """Extracts relevant text from a JSON object (simplified for now)."""
    # This is a basic approach; a real implementation would traverse and filter.
    return json.dumps(json_data, indent=2)

def extract_text_from_csv(csv_data: pd.DataFrame) -> str:
    """Extracts text from a Pandas DataFrame (simplified for now)."""
    # This is a basic approach; a real implementation would join relevant columns.
    return csv_data.to_string()


if __name__ == "__main__":
    # Create dummy files for testing
    dummy_text_file = "dummy_text.txt"
    with open(dummy_text_file, "w", encoding="utf-8") as f:
        f.write("This is a test document.\nMy email is example@test.com.\nMy phone number is 123-456-7890.\nJohn Doe lives at 123 Main St, Anytown, CA.")

    dummy_pdf_file = "dummy.pdf"
    # To create a dummy PDF, you'd typically use a library like reportlab or fpdf
    # or manually create a simple one. For now, assume it exists for testing the function call.
    # We will provide guidance on creating a test PDF if needed.
    # For testing, you might need to manually create a simple PDF with some text.
    # If you can't, you can skip the PDF test for now and focus on text file.

    print(f"--- Testing text file ingestion: {dummy_text_file} ---")
    text_content = extract_text_from_file(dummy_text_file)
    if text_content:
        print(text_content)

    # Example: how to generate a simple PDF if you have fpdf installed:
    # from fpdf import FPDF
    # pdf = FPDF()
    # pdf.add_page()
    # pdf.set_font("Arial", size=12)
    # pdf.multi_cell(0, 10, "This is a test PDF document.\nMy email is test_pdf@example.com.\nMy address is 456 Oak Ave, Somewhere, TX 77777.")
    # pdf.output(dummy_pdf_file)
    # print(f"\n--- Testing PDF file ingestion: {dummy_pdf_file} ---")
    # pdf_content = extract_text_from_pdf(dummy_pdf_file)
    # if pdf_content:
    #    print(pdf_content)
    # else:
    #    print(f"Failed to read from {dummy_pdf_file}. Make sure it exists and has text.")

    import os
    if os.path.exists(dummy_text_file):
        os.remove(dummy_text_file)
    # if os.path.exists(dummy_pdf_file): # Uncomment if you generate the PDF
    #     os.remove(dummy_pdf_file)