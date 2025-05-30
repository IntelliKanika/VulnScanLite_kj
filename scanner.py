import re

RISKY_PATTERNS = {
    "XSS": [
        r"eval\(",    # Using eval() is risky
        r"document\.write\(",    # document.write() can cause XSS
        r"innerHTML\s*=",    # Setting innerHTML directly can be unsafe
        r"<script.*>"    # Inline <script> tags may cause XSS
    ],
    "CORS_Misconfiguration": [
        r"Access-Control-Allow-Origin:\s*\*"  # Wildcard CORS policy
    ],
    "Hardcoded_Secrets": [
        r"password\s*=\s*[\"']+?['\"]",  # Hardcoded passwords
        r"api_key\s*=\s*[\"']+?['\"]"    # Hardcoded API keys
    ]
}

def scan_code(code):
    results = {}  # To store found issues
    for vuln_type, patterns in RISKY_PATTERNS.items():
        matched_patterns = []
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                matched_patterns.append(pattern)
        if matched_patterns:
            results[vuln_type] = matched_patterns

    # If no issues found, return this message
    if not results:
        return "No major issues found!"
    
    messages = []
    for vuln, patterns_found in results.items():
        messages.append(f"A {vuln} issues detected:")
        for p in patterns_found:
            messages.append(f" - Matched pattern: {p}")
    return "\n".join(messages)