# Soliannikov Vladyslav. Example of a module for threat intelligence analysis in Python.

# This module provides functions for analyzing and processing threat intelligence data.
# It includes functions for parsing threat reports, extracting indicators of compromise (IOCs),
# and generating actionable insights for cybersecurity teams.

# Soliannikov Vladyslav. Example of a module for threat intelligence and forensics.

import requests
import json
import hashlib
import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# 1. Configuration
IP_TO_CHECK = "121.15.140.235" 
ABUSE_IPDB_API_KEY = "your_api_key_here"  
TG_BOT_TOKEN = "" 
TG_CHAT_ID = ""    

def send_telegram_alert(ip, score, country, usage):
    """Sends an alert to a configured Telegram chat."""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[-] Telegram credentials not configured. Skipping alert.")
        return
        
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    message = f"🚨 *SecOps Alert*\n\n*IP:* `{ip}`\n*Score:* {score}/100\n*Country:* {country}\n*Usage:* {usage}\n\n_Action Required: Block IP_"
    payload = {"chat_id": TG_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    
    try:
        requests.post(url, json=payload)
        print("[+] Telegram alert sent successfully.")
    except Exception as e:
        print(f"[-] Failed to send Telegram alert: {e}")

def check_ip_reputation(ip, api_key):
    """Analyzes IP reputation via AbuseIPDB."""
    print(f"[*] Starting IP address check: {ip}...")
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status() 
        
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        usage_type = data['data']['usageType']
        country = data['data']['countryCode']
        
        print("\n--- THREAT INTEL RESULTS ---")
        print(f"Country: {country}")
        print(f"Usage Type: {usage_type}")
        print(f"Threat Score (0-100): {score}")
        
        if score > 50:
            print("\n[!] ALERT: Highly suspicious IP address. Firewall blocking recommended.")
            send_telegram_alert(ip, score, country, usage_type)
        else:
            print("\n[V] The IP address appears safe.")
            
    except Exception as e:
        print(f"[-] Error connecting to API: {e}")


def get_decimal_from_dms(dms, ref):
    """Helper to convert DMS to decimal coordinates."""
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
        
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ['S', 'W']:
            decimal = -decimal
        return decimal
    except:
        return None

def analyze_image_metadata(file_path):
    """Extracts EXIF and GPS metadata, generating a Google Maps link if possible."""
    print(f"\n[*] Starting File Forensics for: {file_path}...")
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        
        if not exif_data:
            print("[-] No EXIF metadata found in this file.")
            return

        gps_info = {}
        print("\n--- GENERAL METADATA ---")
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_tag_id in value:
                    gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag_name] = value[gps_tag_id]
            else:
                if isinstance(value, bytes) and len(value) > 50:
                    value = f"<binary data, {len(value)} bytes>"
                print(f"{tag_name}: {value}")
        
        if gps_info:
            print("\n--- GPS LOCATION DATA ---")
            for k, v in gps_info.items():
                print(f"{k}: {v}")
                
            if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
                lat = get_decimal_from_dms(gps_info["GPSLatitude"], gps_info.get("GPSLatitudeRef", "N"))
                lon = get_decimal_from_dms(gps_info["GPSLongitude"], gps_info.get("GPSLongitudeRef", "E"))
                if lat and lon:
                    print("\n[!] TARGET LOCATED [!]")
                    print(f"Decimal Coordinates: {lat}, {lon}")
                    print(f"Google Maps Link: https://www.google.com/maps?q={lat},{lon}")
                
    except Exception as e:
        print(f"[-] Error analyzing file: {e}")

def calculate_file_hashes(file_path):
    """
    Calculates MD5, SHA-1, and SHA-256 for a file at the specified path.
    Useful for quick analysis via terminal.
    """
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} not found.")
        return

    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        print(f"\n--- HASH ANALYSIS: {os.path.basename(file_path)} ---")
        print(f"MD5:     {md5}")
        print(f"SHA-1:   {sha1}")
        print(f"SHA-256: {sha256}")
        return {"md5": md5, "sha1": sha1, "sha256": sha256}

if __name__ == "__main__":
    # Example 1: Check IP
    check_ip_reputation(IP_TO_CHECK, ABUSE_IPDB_API_KEY)
    
    # Example 2: Check Image (Uncomment and replace with a real image path to test)
    # analyze_image_metadata("sample_image.jpg")
    
    # Example 3: Calculate File Hashes
    # calculate_file_hashes("sample_file.exe")