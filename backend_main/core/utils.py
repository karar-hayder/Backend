import re


def extract_markdown_text(ai_output: str) -> str:
    """
    Extracts and returns only the text surrounded by '```markdown ... ```' from a string.

    Args:
        ai_output (str): The AI output string.

    Returns:
        str: The text found inside the first ```markdown ... ``` block, or an empty string if not found.
    """
    pattern = r"```markdown\s*(.*?)\s*```"
    match = re.search(pattern, ai_output, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""
