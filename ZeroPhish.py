import re
import os
import glob
import sys
import json
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SUSPICIOUS_TLDS = ('.xyz', '.top', '.club', '.info', '.site', '.online', '.ru', '.cn', '.tk', '.ml', '.gq', '.cf', '.buzz')
FREEMAIL_DOMAINS = ('gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'yandex.com', 'mail.com', 'protonmail.com', 'icloud.com')
CORPORATE_KEYWORDS = ('bank', 'banka', 'security', 'guvenlik', 'support', 'destek', 'admin', 'update', 'verify', 'onay', 'fatura', 'invoice', 'it', 'helpdesk')
URL_SHORTENERS = ('bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly')
RISKY_EXTENSIONS = ('.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.iso', '.img', '.hta', '.chm', '.jar', '.msi', '.ps1')
ARCHIVE_EXTENSIONS = ('.zip', '.rar', '.7z', '.tar', '.gz')

def defang_url(url):
   
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def extract_urls(text):
    
    url_regex = r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+'
    return list(set(re.findall(url_regex, text)))

def get_clean_domain(url):
   
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    # Port varsa temizle (orn: 192.168.1.1:8080 -> 192.168.1.1)
    return parsed.netloc.split(':')[0].lower()

def extract_email_parts(header_val):
    
    if not header_val or header_val == 'None':
        return "", "", ""
    display_name, email_addr = parseaddr(str(header_val))
    email_addr = email_addr.lower()
    domain = email_addr.split('@')[-1] if '@' in email_addr else ""
    return display_name.lower(), email_addr, domain

def is_ip_address(domain):
    
    ip_regex = r'^\d{1,3}(\.\d{1,3}){3}$'
    return bool(re.match(ip_regex, domain))

def analyze_email(eml_file_path, return_json=False):
    try:
        with open(eml_file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        print(f"[!] ERROR reading file: {e}")
        return None

    risk_score = 0
    risk_reasons = []
    extracted_iocs = {"urls": [], "attachments": [], "origin_ip": None}

    from_raw = str(msg.get('From', 'None'))
    to_raw = str(msg.get('To', 'None'))
    subject_hdr = str(msg.get('Subject', 'None'))
    date_hdr = str(msg.get('Date', 'None'))
    return_path_raw = str(msg.get('Return-Path', 'None'))
    reply_to_raw = str(msg.get('Reply-To', 'None'))

    from_name, from_email, from_domain = extract_email_parts(from_raw)
    _, reply_email, reply_domain = extract_email_parts(reply_to_raw)
    _, return_email, return_domain = extract_email_parts(return_path_raw)

   
    auth_results = str(msg.get('Authentication-Results', 'None'))
    auth_lower = auth_results.lower()

    if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
        risk_score += 35
        risk_reasons.append("SPF dogrulamasi basarisiz (Olasi Gonderici Taklidi) [+35 pts]")
    if "dkim=fail" in auth_lower:
        risk_score += 20
        risk_reasons.append("DKIM imzasi gecersiz [+20 pts]")
    if "dmarc=fail" in auth_lower:
        risk_score += 30
        risk_reasons.append("DMARC politikasi basarisiz [+30 pts]")

   
    if reply_domain and from_domain and (reply_domain != from_domain):
        risk_score += 25
        risk_reasons.append(f"Reply-To domaini ({reply_domain}) ile Gonderici domaini ({from_domain}) farkli [+25 pts]")

    if return_domain and from_domain and (return_domain != from_domain):
        risk_score += 15
        risk_reasons.append(f"Return-Path domaini ({return_domain}) ile Gonderici domaini ({from_domain}) farkli [+15 pts]")

   
    if from_domain in FREEMAIL_DOMAINS:
        if any(kw in from_name or kw in subject_hdr.lower() for kw in CORPORATE_KEYWORDS):
            risk_score += 35
            risk_reasons.append(f"Ucretsiz e-posta servisi ({from_domain}) ile kurumsal anahtar kelime kullanimi [+35 pts]")

   
    if '@' in from_name and from_domain not in from_name:
        risk_score += 45
        risk_reasons.append("Gorunen ad (Display Name) icinde yaniltici e-posta adresi tespit edildi [+45 pts]")

    received_headers = msg.get_all('Received', [])
    origin_hop = received_headers[-1].strip() if received_headers else "None"

    
    body_content = ""
    html_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try: body_content += part.get_content() + "\n"
                except Exception: pass
            elif ctype == "text/html":
                try: 
                    html_part = part.get_content()
                    body_content += html_part + "\n"
                    html_content += html_part + "\n"
                except Exception: pass
    else:
        try: body_content = msg.get_content()
        except Exception: pass

    
    anchor_matches = re.findall(r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL)
    for href_url, anchor_text in anchor_matches:
        clean_anchor = re.sub(r'<[^>]+>', '', anchor_text).strip()
        if re.match(r'^https?://|^www\.', clean_anchor, re.IGNORECASE):
            href_dom = get_clean_domain(href_url)
            anchor_dom = get_clean_domain(clean_anchor)
            if href_dom and anchor_dom and (href_dom != anchor_dom):
                risk_score += 45
                risk_reasons.append(f"Aldatici HTML Linki: Gorunen '{anchor_dom}' ancak hedef '{href_dom}' [+45 pts]")

    urls = extract_urls(body_content)
    scored_domains = set()

    for url in urls:
        parsed_domain = get_clean_domain(url)
        safe_url = defang_url(url)
        extracted_iocs["urls"].append({"domain": parsed_domain, "defanged_url": safe_url})

       
        if parsed_domain not in scored_domains and parsed_domain:
            scored_domains.add(parsed_domain)

            if is_ip_address(parsed_domain):
                risk_score += 35
                risk_reasons.append(f"URL dogrudan IP adresi kullaniyor ({parsed_domain}) [+35 pts]")
            
            if parsed_domain.endswith(SUSPICIOUS_TLDS):
                risk_score += 25
                risk_reasons.append(f"Yuksek riskli domain uzantisi/TLD ({parsed_domain}) [+25 pts]")

            if parsed_domain in URL_SHORTENERS:
                risk_score += 20
                risk_reasons.append(f"URL kisaltma servisi kullanimi ({parsed_domain}) [+20 pts]")

            if "xn--" in parsed_domain:
                risk_score += 40
                risk_reasons.append(f"Punycode (IDN Homograph) taklit domain suphesi ({parsed_domain}) [+40 pts]")

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            sha256_hash = hashlib.sha256(payload).hexdigest() if payload else "N/A"
            extracted_iocs["attachments"].append({"filename": filename, "sha256": sha256_hash})

            fname_lower = filename.lower()
           
            if len(fname_lower.split('.')) > 2 and fname_lower.endswith(RISKY_EXTENSIONS):
                risk_score += 60
                risk_reasons.append(f"Cift uzantili zararli dosya eki suphesi ({filename}) [+60 pts]")
            elif fname_lower.endswith(RISKY_EXTENSIONS):
                risk_score += 45
                risk_reasons.append(f"Yuksek riskli yurutulebilir dosya eki ({filename}) [+45 pts]")
            elif fname_lower.endswith(ARCHIVE_EXTENSIONS):
                risk_score += 15
                risk_reasons.append(f"Sifreli/Arsivlenmis dosya eki ({filename}) [+15 pts]")

    
    final_score = min(risk_score, 100)
    if final_score >= 60:
        verdict = "HIGH RISK - LIKELY PHISHING"
    elif final_score >= 30:
        verdict = "MEDIUM RISK - SUSPICIOUS (Manual Review)"
    else:
        verdict = "LOW RISK - CLEAN"

   
    if not return_json:
        print("\n" + "=" * 70)
        print(" ZEROPHISH V1 - AUTOMATED EMAIL TRIAGE & IOC EXTRACTOR")
        print("=" * 70)
        print(f" TARGET FILE : {eml_file_path}")
        print("=" * 70)
        print(f"From        : {from_raw}\nTo          : {to_raw}\nSubject     : {subject_hdr}")
        print(f"Reply-To    : {reply_to_raw}\nReturn-Path : {return_path_raw}")
        print("-" * 70)
        print(f"Origin Hop  : {origin_hop}")
        print(f"URLs Found  : {len(extracted_iocs['urls'])} | Attachments: {len(extracted_iocs['attachments'])}")
        for att in extracted_iocs["attachments"]:
            print(f" -> Attachment: {att['filename']} (SHA256: {att['sha256'][:16]}...)")
        print("=" * 70)
        print(f"RISK SCORE  : {final_score} / 100")
        print(f"VERDICT     : {verdict}\n")
        if risk_reasons:
            print("Triggered Detection Rules:")
            for r in set(risk_reasons):
                print(f" [!] {r}")
        else:
            print("Triggered Detection Rules: None")
        print("=" * 70)

    return {
        "file": eml_file_path,
        "score": final_score,
        "verdict": verdict,
        "reasons": list(set(risk_reasons)),
        "iocs": extracted_iocs
    }

if __name__ == "__main__":
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1].strip('"').strip("'")
        analyze_email(target_file)
    else:
        eml_files = glob.glob("*.eml") + glob.glob("*.eml.txt")
        if eml_files:
            for file_path in eml_files:
                analyze_email(file_path)
        else:
            user_file = input("\nDrag and drop an .eml file here and press Enter: ")
            if user_file:
                analyze_email(user_file.strip('"').strip("'"))

   
    print("Developer:Mert Duvan")
    input("\nAnalysis finished. Press Enter to exit...")
    