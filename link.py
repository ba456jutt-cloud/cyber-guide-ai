import whois
from urllib.parse import urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import os
import base64
import re
import concurrent.futures

def check_ip_details(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    "ip": ip,
                    "country": data.get('country', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "asn": data.get('as', 'Unknown'),
                    "status": "Success"
                }
        return {"status": "Failed to get IP info"}
    except Exception as e:
        return {"status": "Error", "error": str(e)}

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.now()).days
                
                issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                
                # Check for free or sketchy issuers often used by scams
                risk = "Low Risk"
                if days_left < 30:
                    risk = "High Risk (Expires Soon)"
                elif any(free_ca in issuer_name.lower() for free_ca in ["let's encrypt", "zerossl", "cpanel"]):
                    risk = "Medium Risk (Free SSL)"
                
                return {
                    "valid": True,
                    "issuer": issuer_name,
                    "days_left": days_left,
                    "risk": risk
                }
    except Exception as e:
        return {"valid": False, "error": str(e), "risk": "High Risk (No valid SSL)"}

def check_virustotal(url):
    vt_api_key = os.environ.get("VT_API_KEY", "ab9e3cab0ed9005dda320771722679ff1884b2a2b379b97c724ece4053e89462")
    if not vt_api_key:
        return {"status": "Skipped (No API Key)"}
        
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(api_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_flags = malicious + suspicious
            return {
                "status": "Checked",
                "malicious_flags": malicious,
                "suspicious_flags": suspicious,
                "risk": "High Risk (Scam/Malware Reported!)" if total_flags > 0 else "Low Risk (Clean)"
            }
        else:
            return {"status": f"API Error {response.status_code}"}
    except Exception as e:
         return {"status": f"Failed: {str(e)}"}

def scrape_website(url):
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        
        text_content = soup.get_text()
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content)))
        
        wa_links = []
        for a in soup.find_all('a', href=True):
            if 'wa.me/' in a['href'] or 'api.whatsapp.com' in a['href']:
                wa_links.append(a['href'])

        return {
            "title": title.strip(),
            "status": "Success",
            "redirected_url": response.url,
            "was_redirected": response.url != url,
            "emails": emails[:3],
            "whatsapp_links": list(set(wa_links))[:3]
        }
    except Exception as e:
        return {"title": "Failed to scrape", "status": "Failed", "error": str(e), "was_redirected": False}

def check_domain_forensics(url):
    print(f"[*] Advanced Analysis shuru ho raha hai URL par: {url}")
    
    if not url.startswith("http"):
        url = "https://" + url
        
    try:
        domain = urlparse(url).netloc
    except Exception:
        domain = url.split('/')[0]
        
    results = {
        "original_url": url,
        "domain": domain,
        "status": "Success",
        "age_days": "Unknown",
        "domain_risk": "Unknown",
        "state_impersonation": False
    }
    
    # 1. Scraping & Redirects Check
    print("[*] Checking Redirects & Content...")
    scrape_data = scrape_website(url)
    results["web_content"] = scrape_data
    
    if scrape_data.get("was_redirected"):
        domain = urlparse(scrape_data["redirected_url"]).netloc
        results["final_domain"] = domain
        print(f"[*] Redirected to: {domain}")
        
    # State Impersonation Logic
    title = scrape_data.get('title', '').lower()
    url_lower = url.lower()
    gov_keywords = ['bisp', 'ehsaas', 'challan', 'psca', 'nser', 'gov', 'pass.gov', '8171']
    
    is_impersonating = False
    for kw in gov_keywords:
        # Check if keyword is in title or URL but it's NOT a .gov.pk site
        if (kw in title or kw in url_lower) and not domain.endswith('.gov.pk'):
            is_impersonating = True
            break
            
    results['state_impersonation'] = is_impersonating
        
    # 2. Whois Database Check
    print("[*] Fetching WHOIS data...")
    import socket
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3.0)
    
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]

        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_in_days = (datetime.now() - creation_date).days
            results["age_days"] = age_in_days
            
            if is_impersonating:
                results["domain_risk"] = "Critical Risk (State Impersonation!)"
            else:
                results["domain_risk"] = "High Risk (Scam)" if age_in_days < 30 else "Low Risk"
        else:
            if is_impersonating:
                results["domain_risk"] = "Critical Risk (State Impersonation!)"
            else:
                results["domain_risk"] = "Unknown (No date found)"
    except socket.timeout:
        print("[!] WHOIS Socket Timeout!")
        results["whois_error"] = "Timeout"
        results["age_days"] = "Unknown"
        results["domain_risk"] = "Critical Risk (State Impersonation!)" if is_impersonating else "Unknown"
    except Exception as e:
        results["whois_error"] = str(e)
        results["age_days"] = "Unknown"
        if is_impersonating:
            results["domain_risk"] = "Critical Risk (State Impersonation!)"
        else:
            results["domain_risk"] = "Unknown"
    finally:
        socket.setdefaulttimeout(old_timeout)

    # 3. SSL Certificate Check
    print("[*] Checking SSL Certificate...")
    ssl_data = check_ssl(domain)
    results["ssl_info"] = ssl_data
    
    # 4. VirusTotal Global Scam Report Check
    print("[*] Checking VirusTotal...")
    vt_data = check_virustotal(url)
    results["virustotal"] = vt_data
    
    # 5. Geolocation & ASN
    print("[*] Checking IP Geolocation...")
    ip_data = check_ip_details(domain)
    results["geolocation"] = ip_data
    
    return results

if __name__ == "__main__":
    print("\n--- TEST: Scam check ---")
    fake_site = "https://ecodsdfu-pa.cc/pk" 
    print(check_domain_forensics(fake_site))