# 🔐 Web Security Analyzer with Hugging Face AI

This project is a Python-based tool that analyzes a given website URL for potential security vulnerabilities. It performs both static HTML analysis and header inspection, and then utilizes a Hugging Face Transformer model (`google/flan-t5-base`) to generate AI-powered recommendations.

## 🚀 Features

- Fetch and parse webpage content
- Check for missing security headers
- Analyze HTML for:
  - Insecure links (`http://`)
  - Unprotected forms (e.g., missing CSRF tokens)
  - Inline scripts with potential XSS vulnerabilities
  - Outdated JavaScript libraries (e.g., jQuery)
  - File upload fields
  - Sensitive keywords (`admin`, `password`, etc.)
  - Open API endpoints
- Use Hugging Face Transformers to summarize and analyze issues
- Display results in a clear tabulated and colorized report using `tabulate` and `colorama`

## 🛠️ Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`
- `transformers`
- `tabulate`
- `colorama`
- `torch` (for running the Transformer model)

Install dependencies using:

```bash
'pip install -r requirements.txt'
```

## 🧪 Usage
Edit the URL in the __main__ section of new3.py

`url = "https://en.ctu.edu.vn/"`

Then run the script: Use virtual environment if you want

```bash
python new3.py
```
