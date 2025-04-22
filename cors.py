import requests
import pandas as pd
import os
from colorama import Fore, Style

# Define the HTTP methods we will test for CORS vulnerabilities
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

def scan_cors(target_url):
    """Scans the given URL for CORS misconfigurations and logs issues found."""
    print(f"\n{Fore.CYAN}Scanning CORS settings for: {target_url}{Style.RESET_ALL}")
    detected_issues = []  # List to store any found issues

    # Testing each HTTP method
    for method in METHODS_TO_TEST:
        headers = {
            "Origin": "https://malicious.com",  # Simulating a potentially harmful external domain
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://malicious.com"
        }
        
        try:
            response = requests.request(method, target_url, headers=headers, timeout=5)
            issues = analyze_response(target_url, method, response)
            if issues:
                detected_issues.extend(issues)
        except requests.exceptions.RequestException as error:
            print(f"{Fore.RED}Error reaching {target_url}: {error}{Style.RESET_ALL}")
    
    # Save results if any vulnerabilities are found
    if detected_issues:
        save_results(detected_issues)

def analyze_response(url, method, response):
    """Analyzes the response headers for possible CORS misconfigurations."""
    print(f"\n{Fore.YELLOW}[{method}] Response Analysis:{Style.RESET_ALL}")

    # Extract CORS-related headers from the response
    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    allow_credentials = response.headers.get("Access-Control-Allow-Credentials")
    allow_methods = response.headers.get("Access-Control-Allow-Methods")

    # If no CORS headers exist, we assume CORS isn't enabled
    if not allow_origin:
        print(f"{Fore.RED}No CORS headers found for {method} request.{Style.RESET_ALL}")
        return []

    issues = []  # List to store found issues

    # Check for wildcard * origin, which is a serious security risk
    if allow_origin == "*":
        issue = "HIGH RISK: Any website can access this API."
        print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        issues.append([url, method, allow_origin, allow_credentials, "High", issue])

    # Allowing credentials with a wildcard origin is extremely dangerous
    if allow_credentials == "true":
        issue = "CRITICAL: Credentials are allowed with wildcard origin!"
        print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        issues.append([url, method, allow_origin, allow_credentials, "High", issue])

    # If dangerous HTTP methods (PUT, DELETE) are exposed, it's a problem
    if allow_methods and ("PUT" in allow_methods or "DELETE" in allow_methods):
        issue = "HIGH RISK: PUT/DELETE methods are accessible via CORS."
        print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        issues.append([url, method, allow_origin, allow_credentials, "High", issue])

    return issues

def save_results(vulnerabilities):
    """Saves CORS security issues to a CSV file."""
    output_file = "cors_scan_results.csv"
    df = pd.DataFrame(vulnerabilities, columns=["URL", "Method", "Allow-Origin", "Allow-Credentials", "Severity", "Issue"])

    # Append to file if it already exists; otherwise, create a new one
    if os.path.exists(output_file):
        df.to_csv(output_file, mode="a", header=False, index=False)
    else:
        df.to_csv(output_file, mode="w", index=False)

    print(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    # Ask the user for a URL to scan
    user_url = input("Enter the API endpoint to scan: ").strip()
    
    if user_url:
        scan_cors(user_url)
    else:
        print(f"{Fore.RED}Invalid input. Please provide a valid URL.{Style.RESET_ALL}")
