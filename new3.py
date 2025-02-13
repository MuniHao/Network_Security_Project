import requests
from bs4 import BeautifulSoup
import re
from transformers import pipeline
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
from tabulate import tabulate
from colorama import Fore, Style, init
import json

# Initialize colorama
init(autoreset=True)

# Create a pipeline for natural language processing using Hugging Face Transformers
nlp_pipeline = pipeline("text2text-generation", model="google/flan-t5-base")

def fetch_url_content(url):
    """
    Fetch HTML content from a URL.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the webpage: {e}")
        return None

def check_security_headers(response):
    headers = response.headers
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "X-Content-Type-Options"
    ]
    issues = []
    for header in security_headers:
        if header not in headers:
            issues.append(f"Missing security header: {header}")
    return issues

def extract_potential_issues(html_content):
    """
    Analyze HTML content to identify basic security vulnerabilities.
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    issues = []

    # Check for suspicious scripts
    scripts = soup.find_all("script", src=True)
    for script in scripts:
        if "eval" in script.get("src", "").lower():
            issues.append("Detected 'eval()' in JavaScript source, which may lead to XSS vulnerabilities.")

    # Look for outdated libraries
    for script in scripts:
        if "jquery" in script["src"] and re.search(r"jquery-(1\.[0-9]|2\.[0-9])", script["src"]):
            issues.append("Outdated jQuery version detected, which is vulnerable to XSS.")

    # Check for unsecured links (http://)
    links = soup.find_all("a", href=True)
    for link in links:
        if link['href'].startswith("http://"):
            issues.append(f"Insecure link found: {link['href']}")

    # Detect forms missing HTTPS or CSRF tokens
    forms = soup.find_all("form")
    for form in forms:
        if form.get("action", "").startswith("http://"):
            issues.append(f"Form with insecure action (HTTP): {form['action']}")
        if not form.find("input", {"name": re.compile("csrf", re.IGNORECASE)}):
            issues.append("Form missing CSRF token, which may lead to CSRF attacks.")

    # Detect input fields missing validation attributes
    inputs = soup.find_all("input")
    for input_field in inputs:
        if input_field.get("type") in ["text", "password", "email"] and not input_field.get("required"):
            issues.append(f"Input field '{input_field.get('name', 'unknown')}' is missing 'required' attribute for validation.")

    # Look for inline styles that may have XSS risks
    inline_styles = soup.find_all(style=True)
    for style in inline_styles:
        if "expression(" in style.get("style", "").lower():
            issues.append("Possible XSS vulnerability in inline CSS (use of 'expression()').")

    # Detect unprotected admin panels
    if soup.find(string=re.compile(r"admin login", re.IGNORECASE)):
        issues.append("Unprotected admin login page detected.")

    return issues

def detect_sql_injection(form_elements):
    issues = []
    for form in form_elements:
        if form.get("method", "").lower() == "get":
            issues.append("Potential SQL injection risk in GET-based form.")
    return issues

def detect_file_upload_vulnerabilities(soup):
    issues = []
    file_inputs = soup.find_all("input", {"type": "file"})
    for file_input in file_inputs:
        issues.append("File upload input detected; ensure proper validation for file uploads.")
    return issues

def detect_sensitive_keywords(html_content):
    sensitive_keywords = ["admin", "password", "login", "config"]
    issues = []
    for keyword in sensitive_keywords:
        if keyword in html_content.lower():
            issues.append(f"Sensitive keyword '{keyword}' found in HTML source.")
    return issues

def detect_open_api_endpoints(links):
    issues = []
    for link in links:
        if re.search(r"/api/|/v1/", link.get("href", "").lower()):
            issues.append(f"Potentially exposed API endpoint: {link['href']}")
    return issues

def detect_js_leaks(scripts):
    issues = []
    for script in scripts:
        if script.get("src"):
            try:
                js_content = requests.get(script["src"]).text
                if js_content and re.search(r"(key=|token=|password=)", js_content, re.IGNORECASE):
                    issues.append(f"Sensitive data found in JavaScript file: {script['src']}")
            except Exception as e:
                issues.append(f"Error loading JavaScript file {script['src']}: {str(e)}")
    return issues

def analyze_with_huggingface_custom(issues_list):
    """
    Use Hugging Face Transformers to analyze security issues.
    """
    model_name = "google/flan-t5-base"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    # Create a prompt from the list of security issues
    prompt = "Here are the potential security issues found on the website:\n"
    prompt += "\n".join([f"- {issue}" for issue in issues_list])
    prompt += "\n\nPlease analyze these issues and provide actionable recommendations."

    # Encode input and generate output from the model
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
    outputs = model.generate(**inputs, max_length=300, num_beams=4, early_stopping=True)
    result = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return result

def display_results(results):
    print(Fore.CYAN + "=" * 50)
    print(Fore.GREEN + "\u2728 Security Analysis Report".center(50))
    print(Fore.CYAN + "=" * 50)

    # Group results by category
    grouped_results = {
        "Missing Security Headers": [],
        "Insecure Links": [],
        "Form Issues": [],
        "JavaScript Errors": [],
        "Sensitive Data": []
    }

    for issue in results:
        if "Missing security header" in issue:
            grouped_results["Missing Security Headers"].append(issue)
        elif "Insecure link" in issue:
            grouped_results["Insecure Links"].append(issue)
        elif "Form" in issue:
            grouped_results["Form Issues"].append(issue)
        elif "JavaScript" in issue or "Error loading JavaScript" in issue:
            grouped_results["JavaScript Errors"].append(issue)
        elif "Sensitive" in issue:
            grouped_results["Sensitive Data"].append(issue)

    # Display results by category
    for category, issues in grouped_results.items():
        if issues:
            print(f"\n{Fore.YELLOW}\u25BA {category}:")
            table = [[idx + 1, issue] for idx, issue in enumerate(issues)]
            print(tabulate(table, headers=["#", "Issue"], tablefmt="grid"))

    print(Fore.CYAN + "\n\u2728 End of Report \u2728")
    print(Fore.CYAN + "=" * 50)

if __name__ == "__main__":
    url = "https://en.ctu.edu.vn/"
    print(Fore.BLUE + f"Analyzing URL: {url}")

    # Step 1: Fetch website content
    response = fetch_url_content(url)
    if response is None:
        print(Fore.RED + "Unable to analyze the URL.")
    else:
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")

        # Step 2: Detect basic security issues
        issues = []
        issues.extend(check_security_headers(response))
        issues.extend(extract_potential_issues(html_content))
        issues.extend(detect_sql_injection(soup.find_all("form")))
        issues.extend(detect_file_upload_vulnerabilities(soup))
        issues.extend(detect_sensitive_keywords(html_content))
        issues.extend(detect_open_api_endpoints(soup.find_all("a", href=True)))
        issues.extend(detect_js_leaks(soup.find_all("script")))

        if issues:
            print(Fore.YELLOW + "\nPotential security issues found:")
            display_results(issues)
        else:
            print(Fore.GREEN + "No obvious security issues detected.")

        # Step 3: Use Hugging Face to analyze further
        print(Fore.MAGENTA + "\nUsing Hugging Face for further analysis...")
        ai_analysis = analyze_with_huggingface_custom(issues)
        if ai_analysis:
            print(Fore.GREEN + "\nAI Analysis:")
            print(Fore.WHITE + ai_analysis)
        else:
            print(Fore.RED + "Unable to perform AI analysis.")
