import requests
from bs4 import BeautifulSoup
import time
import winsound
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import re

def test_cve_details_token():
    # Token from CVE Details
    token = "8ca742a51e6b1d25a5b2108bd33f244a034e71d6.eyJzdWIiOjEwODI1LCJpYXQiOjE3NDI4NjcwOTYsImV4cCI6MTc0NTUzOTIwMCwia2lkIjoxLCJjIjoicDhRZEJMNTluYlZjXC9paVpQaWFJUmtldlZ3SUR2ZzIxS3BIS0ZzZ3JsY3hhdzhxajNMaENyaUNtUFBzNTBjamtGXC9WS2xVQWg5Zz09In0="
    
    # CVE ID to test with
    test_cve_id = "CVE-2021-44228"  # Log4j vulnerability - should definitely exist
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    # User agent to look like a legitimate browser
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    print("\n=== Testing CVE Details access token ===\n")
    
    # First, try visiting the homepage to get cookies
    print("1. Visiting homepage to get initial cookies...")
    home_response = session.get("https://www.cvedetails.com/", headers=headers)
    print(f"   Status code: {home_response.status_code}")
    
    # Test Method 1: Bearer token in Authorization header
    print("\n2. Testing Method 1: Bearer token in Authorization header...")
    auth_headers = headers.copy()
    auth_headers["Authorization"] = f"Bearer {token}"
    
    url = f"https://www.cvedetails.com/cve-details.php?cve_id={test_cve_id}"
    response = session.get(url, headers=auth_headers)
    
    print(f"   Status code: {response.status_code}")
    
    # Check response content
    soup = BeautifulSoup(response.text, 'html.parser')
    h1_tag = soup.find('h1')
    
    if h1_tag and test_cve_id in h1_tag.get_text():
        print("   ✓ Success! Found CVE details page with correct h1 tag")
        print(f"   H1 tag text: {h1_tag.get_text().strip()}")
        winsound.Beep(1000, 100)  # Success beep
    else:
        print("   ✗ Failed with Method 1 - Bearer token in header")
        
        # Test Method 2: Token as a cookie
        print("\n3. Testing Method 2: Token as a cookie...")
        session.cookies.set('access_token', token)
        session.cookies.set('api_key', token)
        response = session.get(url, headers=headers)
        
        print(f"   Status code: {response.status_code}")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        h1_tag = soup.find('h1')
        
        if h1_tag and test_cve_id in h1_tag.get_text():
            print("   ✓ Success! Found CVE details page with correct h1 tag")
            print(f"   H1 tag text: {h1_tag.get_text().strip()}")
            winsound.Beep(1000, 100)  # Success beep
        else:
            print("   ✗ Failed with Method 2 - Token as cookie")
            
            # Test Method 3: Token as URL parameter
            print("\n4. Testing Method 3: Token as URL parameter...")
            url_with_token = f"{url}&token={token}"
            response = session.get(url_with_token, headers=headers)
            
            print(f"   Status code: {response.status_code}")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            h1_tag = soup.find('h1')
            
            if h1_tag and test_cve_id in h1_tag.get_text():
                print("   ✓ Success! Found CVE details page with correct h1 tag")
                print(f"   H1 tag text: {h1_tag.get_text().strip()}")
                winsound.Beep(1000, 100)  # Success beep
            else:
                print("   ✗ Failed with Method 3 - Token as URL parameter")
                print("\nAll methods failed. Possible issues:")
                print("- The token may not be active yet")
                print("- The token may need to be used differently")
                print("- CVE Details might be using a different authentication method")
                winsound.Beep(1500, 300)  # Failure beep
    
    # Check if we got a cloudflare challenge
    if "Just a moment" in response.text and "cf-" in response.text:
        print("\n⚠️ Cloudflare protection detected! The token doesn't seem to bypass this.")
        winsound.Beep(1500, 300)  # Warning beep
    
    # Look for login messages or token-related text
    login_text = soup.find(text=lambda t: t and ("login" in t.lower() or "token" in t.lower() or "access" in t.lower()))
    if login_text:
        print(f"\nFound potentially relevant text: {login_text.strip()}")
    
    # Save the response for inspection
    with open("cve_details_test_response.html", "w", encoding="utf-8") as f:
        f.write(response.text)
    print("\nResponse saved to cve_details_test_response.html for inspection")

def get_cve_with_selenium(cve_id):
    # Setup Chrome driver
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    
    try:
        # Visit the page with your token
        token = "8ca742a51e6b1d25a5b2108bd33f244a034e71d6"
        url = f"https://www.cvedetails.com/cve-details.php?cve_id={cve_id}&token={token}"
        
        print(f"Accessing {url}")
        driver.get(url)
        
        # Wait for Cloudflare challenge to complete
        print("Waiting for Cloudflare challenge...")
        time.sleep(10)
        
        # Check if we got past Cloudflare
        if "Just a moment" in driver.page_source:
            print("Still on Cloudflare challenge page, waiting longer...")
            time.sleep(20)
        
        print(f"Page title: {driver.title}")
        
        # Get the page content
        html = driver.page_source
        return html
    finally:
        driver.quit()

if __name__ == "__main__":
    test_cve_details_token()

# Test with the Log4j vulnerability
html = get_cve_with_selenium("CVE-2021-44228")

# Check if we got the actual CVE page
if re.search(r'<h1>.*CVE-2021-44228.*</h1>', html):
    print("Success! Found CVE details page")
    # Save the successful HTML for analysis
    with open("cve_success.html", "w", encoding="utf-8") as f:
        f.write(html)
else:
    print("Failed to bypass Cloudflare protection")