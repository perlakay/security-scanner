import requests
import json
import dns.resolver
import whois
import socket
import ssl
import re
import argparse
import sys
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
from time import sleep
from datetime import datetime  # Added for SSL fix

# Suppress only the specific warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def find_subdomains(domain):
    """Discover subdomains using passive methods with enhanced robustness"""
    subdomains = set()
    
    print(f"  Querying certificate transparency logs for {domain}...")
    for attempt in range(3):
        try:
            response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(f'.{domain}') or subdomain == domain:
                                clean_subdomain = re.sub(r'^\*\.', '', subdomain)
                                subdomains.add(clean_subdomain)
                except json.JSONDecodeError:
                    print(f"  Warning: Could not parse crt.sh response as JSON")
                break
            else:
                print(f"  Warning: crt.sh returned status code {response.status_code}")
        except Exception as e:
            print(f"  Warning: Attempt {attempt+1} failed querying crt.sh: {str(e)}")
            sleep(2)
    else:
        print(f"  Warning: All attempts to query crt.sh for {domain} failed.")

    try:
        print(f"  Checking TXT records for subdomain hints...")
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            txt = record.to_text().strip('"')
            domain_pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+' + re.escape(domain))
            matches = domain_pattern.findall(txt)
            for match in matches:
                if match.endswith(f'.{domain}'):
                    subdomains.add(match)
    except Exception as e:
        print(f"  Warning: Error checking TXT records: {str(e)}")

    try:
        print(f"  Checking MX records for subdomains...")
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in mx_records:
            mx = record.exchange.to_text().rstrip('.')
            if mx.endswith(f'.{domain}'):
                subdomains.add(mx)
    except Exception as e:
        print(f"  Warning: Error checking MX records: {str(e)}")

    try:
        print(f"  Checking NS records for subdomains...")
        ns_records = dns.resolver.resolve(domain, 'NS')
        for record in ns_records:
            ns = record.to_text().rstrip('.')
            if ns.endswith(f'.{domain}'):
                subdomains.add(ns)
    except Exception as e:
        print(f"  Warning: Error checking NS records: {str(e)}")

    common_prefixes = ['www', 'mail', 'webmail', 'api', 'dev', 'stage', 'blog', 'shop', 'support']
    for prefix in common_prefixes:
        common_subdomain = f"{prefix}.{domain}"
        try:
            dns.resolver.resolve(common_subdomain, 'A')
            subdomains.add(common_subdomain)
        except Exception:
            pass

    subdomains.add(domain)
    return sorted(list(subdomains))

def get_security_headers(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, timeout=5, allow_redirects=True, headers=headers, verify=False)
        headers = response.headers
        final_url = response.url
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not present'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not present'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not present'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not present'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not present'),
            'Permissions-Policy': headers.get('Permissions-Policy', headers.get('Feature-Policy', 'Not present')),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not present')
        }
        return {
            'final_url': final_url,
            'headers': security_headers,
            'server': headers.get('Server', 'Not Disclosed'),
            'all_headers': dict(headers)
        }
    except requests.RequestException as e:
        return {'error': f'Error fetching headers: {str(e)}'}

def get_dns_records(domain):
    records = {}
    for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'CAA']:
        try:
            records[record_type] = [str(r) for r in dns.resolver.resolve(domain, record_type)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout) as e:
            records[record_type] = f'Not Found ({str(e)})'
        except Exception as e:
            records[record_type] = f'Error: {str(e)}'
    try:
        spf_records = [r for r in records.get('TXT', []) if isinstance(r, str) and 'v=spf1' in r]
        records['SPF'] = spf_records if spf_records else 'Not Found'
    except Exception as e:
        records['SPF'] = f'Error: {str(e)}'
    try:
        dmarc_domain = f'_dmarc.{domain}'
        dmarc_records = [str(r) for r in dns.resolver.resolve(dmarc_domain, 'TXT')]
        records['DMARC'] = dmarc_records
    except Exception as e:
        records['DMARC'] = f'Not Found or Error: {str(e)}'
    return records

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
            'updated_date': str(w.updated_date),
            'name_servers': w.name_servers,
            'status': w.status,
            'dnssec': getattr(w, 'dnssec', 'Not specified')
        }
    except Exception as e:
        return f'Error fetching WHOIS info: {str(e)}'

def get_robots_txt(url):
    try:
        domain = urlparse(url).netloc
        scheme = urlparse(url).scheme
        robots_url = f"{scheme}://{domain}/robots.txt"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(robots_url, timeout=5, headers=headers, verify=False)
        return response.text if response.status_code == 200 else f"No robots.txt found (Status code: {response.status_code})"
    except Exception as e:
        return f"Error fetching robots.txt: {str(e)}"

def get_cookie_info(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, timeout=5, allow_redirects=True, headers=headers, verify=False)
        cookies = response.cookies
        cookie_info = []
        for cookie in cookies:
            http_only = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in [attr.lower() for attr in cookie._rest.keys()]
            cookie_data = {
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': http_only,
                'samesite': cookie.get_nonstandard_attr('SameSite', 'Not Set')
            }
            cookie_info.append(cookie_data)
        return cookie_info if cookie_info else "No cookies found"
    except requests.RequestException as e:
        return f'Error fetching cookies: {str(e)}'

def check_ssl_tls(url):
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                cert_valid_until = datetime.strptime(cert.get('notAfter'), "%b %d %H:%M:%S %Y %Z")
                cert_has_expired = cert_valid_until < datetime.utcnow()
                return {
                    'ssl_version': ssl_version,
                    'cipher_suite': cipher,
                    'cert_issuer': cert.get('issuer'),
                    'cert_subject': cert.get('subject'),
                    'cert_valid_from': cert.get('notBefore'),
                    'cert_valid_until': cert.get('notAfter'),
                    'cert_has_expired': cert_has_expired,
                    'cert_san': cert.get('subjectAltName', [])
                }
    except (socket.gaierror, socket.error, ssl.SSLError, ssl.CertificateError) as e:
        return f'SSL/TLS Error: {str(e)}'
    except Exception as e:
        return f'Error checking SSL/TLS: {str(e)}'

def get_tech_stack(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        tech_stack = {
            'javascript_libraries': [],
            'meta_tags': {},
            'server': response.headers.get('Server', 'Not disclosed'),
            'powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
            'cms': []
        }
        scripts = soup.find_all('script', src=True)
        js_patterns = {
            'jQuery': r'jquery[.-]', 'React': r'react[.-]', 'Angular': r'angular[.-]', 'Vue': r'vue[.-]',
            'Bootstrap': r'bootstrap[.-]', 'Modernizr': r'modernizr', 'Google Analytics': r'google-analytics.com|ga.js',
            'Google Tag Manager': r'googletagmanager.com'
        }
        for script in scripts:
            src = script['src']
            for tech, pattern in js_patterns.items():
                if re.search(pattern, src, re.I):
                    tech_stack['javascript_libraries'].append(tech)
        tech_stack['javascript_libraries'] = list(set(tech_stack['javascript_libraries']))
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            name = tag.get('name', tag.get('property', ''))
            if name:
                tech_stack['meta_tags'][name] = tag.get('content', '')
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'/themes/', 'WordPress'],
            'Drupal': [r'drupal.js', r'Drupal.settings', 'Drupal'],
            'Joomla': [r'joomla', r'/components/', 'Joomla'],
            'Shopify': [r'shopify', 'Shopify'],
            'Magento': [r'magento', 'Magento'],
            'Wix': [r'wix.com'],
            'Squarespace': [r'squarespace']
        }
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.I):
                    tech_stack['cms'].append(cms)
                    break
        tech_stack['cms'] = list(set(tech_stack['cms']))
        return tech_stack
    except Exception as e:
        return f'Error detecting tech stack: {str(e)}'

def extract_subdomains_from_certificates(url):
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subdomains = [san for type_, san in cert.get('subjectAltName', []) if type_ == 'DNS']
                return list(set(subdomains))
    except Exception as e:
        return f'Error extracting subdomains from certificate: {str(e)}'

def check_security_txt(url):
    try:
        domain = urlparse(url).netloc
        scheme = urlparse(url).scheme
        security_txt_url = f"{scheme}://{domain}/.well-known/security.txt"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(security_txt_url, timeout=5, headers=headers, verify=False)
        if response.status_code == 200:
            return response.text
        security_txt_url_alt = f"{scheme}://{domain}/security.txt"
        response = requests.get(security_txt_url_alt, timeout=5, headers=headers, verify=False)
        return response.text if response.status_code == 200 else "No security.txt found"
    except Exception as e:
        return f"Error fetching security.txt: {str(e)}"

def analyze_security_posture(report):
    for company, data in report.items():
        if 'subdomains' in data and 'domain_results' not in data:
            continue
        domain_results = data.get('domain_results', {})
        if not domain_results:
            continue
        for domain_key, domain_data in domain_results.items():
            if 'error' in domain_data:
                continue
            analysis = {
                'security_score': 0,
                'findings': [],
                'strengths': [],
                'recommendations': []
            }
            headers_data = domain_data.get('security_headers', {})
            if isinstance(headers_data, dict):
                missing_headers = [h for h, v in headers_data.items() if v == 'Not present']
                if missing_headers:
                    analysis['findings'].append(f"Missing {len(missing_headers)} security headers: {', '.join(missing_headers)}")
                    analysis['recommendations'].append("Implement missing security headers")
                else:
                    analysis['strengths'].append("All recommended security headers implemented")
            ssl_tls = domain_data.get('ssl_tls', {})
            if isinstance(ssl_tls, str) and 'Error' in ssl_tls:
                analysis['findings'].append(f"SSL/TLS issues: {ssl_tls}")
                analysis['recommendations'].append("Fix SSL/TLS configuration")
            elif isinstance(ssl_tls, dict):
                if ssl_tls.get('cert_has_expired', False):
                    analysis['findings'].append("SSL certificate expired")
                    analysis['recommendations'].append("Renew SSL certificate")
            cookies = domain_data.get('cookie_info', [])
            if isinstance(cookies, list) and cookies and cookies != "No cookies found":
                insecure_cookies = [c['name'] for c in cookies if not c.get('secure', False) or not c.get('httponly', False)]
                if insecure_cookies:
                    analysis['findings'].append(f"Insecure cookies: {', '.join(insecure_cookies)}")
                    analysis['recommendations'].append("Set Secure and HttpOnly flags on cookies")
                else:
                    analysis['strengths'].append("Cookies secured with Secure and HttpOnly flags")
            dns = domain_data.get('dns_records', {})
            if isinstance(dns, dict):
                if dns.get('DMARC', 'Not Found') == 'Not Found' or 'Error' in str(dns.get('DMARC', '')):
                    analysis['findings'].append("DMARC record not found")
                    analysis['recommendations'].append("Implement DMARC")
                else:
                    analysis['strengths'].append("DMARC record implemented")
                if dns.get('SPF', 'Not Found') == 'Not Found' or 'Error' in str(dns.get('SPF', '')):
                    analysis['findings'].append("SPF record not found")
                    analysis['recommendations'].append("Implement SPF")
                else:
                    analysis['strengths'].append("SPF record implemented")
            security_txt = domain_data.get('security_txt', '')
            if security_txt == "No security.txt found":
                analysis['findings'].append("No security.txt file found")
                analysis['recommendations'].append("Implement security.txt")
            else:
                analysis['strengths'].append("security.txt implemented")
            findings_count = len(analysis['findings'])
            strengths_count = len(analysis['strengths'])
            analysis['security_score'] = 10 - findings_count if findings_count <= 10 else 1
            if findings_count == 0 and strengths_count > 0:
                analysis['security_score'] = 10
            domain_data['security_analysis'] = analysis
    return report

def scan_domain(domain_info):
    domain_name, url = domain_info
    print(f"  Scanning {domain_name} ({url})...")
    try:
        security_headers_result = get_security_headers(url)
        dns_records = get_dns_records(domain_name)
        whois_info = get_whois_info(domain_name)
        ssl_tls = check_ssl_tls(url)
        cookie_info = get_cookie_info(url)
        tech_stack = get_tech_stack(url)
        security_txt = check_security_txt(url)
        robots_txt = get_robots_txt(url)
        return {
            'url': url,
            'security_headers': security_headers_result.get('headers', security_headers_result),
            'dns_records': dns_records,
            'whois_info': whois_info,
            'ssl_tls': ssl_tls,
            'cookie_info': cookie_info,
            'tech_stack': tech_stack,
            'security_txt': security_txt,
            'robots_txt': robots_txt
        }
    except Exception as e:
        return {'error': f'Failed to scan {domain_name}: {str(e)}'}

def scan_tech_company_security(companies):
    results = {}
    for company, url in companies.items():
        print(f"\n===== Scanning {company} ({url}) =====")
        try:
            main_domain = urlparse(url).netloc
            print(f"Discovering subdomains for {main_domain}...")
            subdomains = find_subdomains(main_domain)
            print(f"Found {len(subdomains)} domains/subdomains for {main_domain}")
            results[company] = {
                'main_url': url,
                'main_domain': main_domain,
                'subdomains': subdomains,
                'domain_results': {}
            }
            scan_tasks = [(subdomain, f"https://{subdomain}") for subdomain in subdomains]
            print(f"Beginning parallel scan of all {len(scan_tasks)} domains/subdomains...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_domain = {executor.submit(scan_domain, task): task[0] for task in scan_tasks}
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        domain_result = future.result()
                        results[company]['domain_results'][domain] = domain_result
                        print(f"  ✓ Completed scan of {domain}")
                    except Exception as e:
                        results[company]['domain_results'][domain] = {'error': str(e)}
                        print(f"  ✗ Error scanning {domain}: {str(e)}")
        except Exception as e:
            results[company] = {'error': f'Failed to scan {company}: {str(e)}'}
    return results

def generate_summary_report(report):
    summary = {}
    for company, data in report.items():
        if 'error' in data:
            summary[company] = {'status': 'ERROR', 'error': data['error']}
            continue
        company_summary = {
            'main_domain': data.get('main_domain', ''),
            'total_subdomains': len(data.get('subdomains', [])),
            'successful_scans': 0,
            'failed_scans': 0,
            'average_security_score': 0,
            'common_findings': {},
            'common_strengths': {},
            'vulnerable_subdomains': []
        }
        total_score = 0
        score_count = 0
        all_findings = []
        all_strengths = []
        domain_results = data.get('domain_results', {})
        for domain, domain_data in domain_results.items():
            if 'error' in domain_data:
                company_summary['failed_scans'] += 1
                continue
            company_summary['successful_scans'] += 1
            analysis = domain_data.get('security_analysis', {})
            if 'security_score' in analysis:
                total_score += analysis['security_score']
                score_count += 1
                if analysis['security_score'] < 5:
                    company_summary['vulnerable_subdomains'].append({
                        'domain': domain,
                        'score': analysis['security_score'],
                        'key_findings': analysis.get('findings', [])[:3]
                    })
                all_findings.extend(analysis.get('findings', []))
                all_strengths.extend(analysis.get('strengths', []))
        if score_count > 0:
            company_summary['average_security_score'] = round(total_score / score_count, 1)
        for finding in all_findings:
            company_summary['common_findings'][finding] = company_summary['common_findings'].get(finding, 0) + 1
        for strength in all_strengths:
            company_summary['common_strengths'][strength] = company_summary['common_strengths'].get(strength, 0) + 1
        company_summary['common_findings'] = dict(sorted(company_summary['common_findings'].items(), key=lambda x: x[1], reverse=True)[:5])
        company_summary['common_strengths'] = dict(sorted(company_summary['common_strengths'].items(), key=lambda x: x[1], reverse=True)[:5])
        summary[company] = company_summary
    return summary

def main():
    parser = argparse.ArgumentParser(description="Passive Security Scanner - A tool for passive reconnaissance")
    parser.add_argument("--targets", nargs='+', required=True, 
                        help="List of targets in format 'CompanyName:URL', e.g., 'Google:https://www.google.com'")
    args = parser.parse_args()
    
    print("\n=============================================")
    print("  Starting passive security reconnaissance...")
    print("  This scan only collects publicly available information")
    print("  and uses non-intrusive techniques to assess security.")
    print("  IMPORTANT: This tool performs ONLY passive, legal")
    print("  information gathering and does not perform any")
    print("  active scanning or testing that requires permission.")
    print("=============================================\n")
    
    companies = {}
    for target in args.targets:
        try:
            company, url = target.split(':', 1)
            companies[company] = url
        except ValueError:
            print(f"Error: Target '{target}' not in required format 'CompanyName:URL'")
            continue
    
    report = scan_tech_company_security(companies)
    print("\nAnalyzing security posture of all domains and subdomains...")
    analyzed_report = analyze_security_posture(report)
    print("Generating summary report...")
    summary_report = generate_summary_report(analyzed_report)
    
    print("\n=============================================")
    print("  Passive reconnaissance complete!")
    print("  Results displayed below (no files saved):")
    print("=============================================\n")
    
    print("Security Posture Overview:")
    print("------------------------")
    for company, data in summary_report.items():
        if data.get('status') == 'ERROR':
            print(f"  {company}: SCAN FAILED - {data.get('error')}")
            continue
        print(f" {company}:")
        print(f"   Main Domain: {data.get('main_domain')}")
        print(f"   Total Subdomains Found: {data.get('total_subdomains')}")
        print(f"   Successful Scans: {data.get('successful_scans')}")
        print(f"   Failed Scans: {data.get('failed_scans')}")
        print(f"   Average Security Score: {data.get('average_security_score')}/10")
        
        vulnerable_domains = data.get('vulnerable_subdomains', [])
        if vulnerable_domains:
            print(f"   Potentially Vulnerable Subdomains ({len(vulnerable_domains)}):")
            for domain in vulnerable_domains[:3]:
                print(f"     - {domain['domain']} (Score: {domain['score']}/10)")
                for finding in domain.get('key_findings', []):
                    print(f"       * {finding}")
            if len(vulnerable_domains) > 3:
                print(f"     - Plus {len(vulnerable_domains) - 3} more...")
        
        print("   Top Issues:")
        for finding, count in list(data.get('common_findings', {}).items())[:3]:
            print(f"     - {finding} (Found in {count} domains)")
        
        print("   Top Strengths:")
        for strength, count in list(data.get('common_strengths', {}).items())[:3]:
            print(f"     - {strength} (Found in {count} domains)")
        
        print()

if __name__ == "__main__":
    main()