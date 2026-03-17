import streamlit as st
import pandas as pd
import hashlib
import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# 1. PAGE CONFIGURATION (Must be only one per file!)
st.set_page_config(page_title="SecOps Dashboard (Soliannikov - example Python + CI/CD with security)", page_icon="🛡️", layout="wide")

# --- SIDEBAR (Settings) ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cyber-security.png", width=80)
    st.header("⚙️ Settings")
    abuse_api_key = st.text_input("🔑 AbuseIPDB API Key", type="password")
    vt_api_key = st.text_input("🧬 VirusTotal API Key", type="password", help="Get it at virustotal.com")
    
    st.markdown("---")
    st.header("🤖 Telegram Alerts")
    tg_token = st.text_input("Bot Token", type="password")
    tg_chat_id = st.text_input("Chat ID")

# --- HELPER FUNCTIONS ---

def send_telegram_alert(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return True
    except Exception as e:
        st.sidebar.error(f"Telegram Alert Error: {e}")
        return False

def check_virustotal(file_hash, api_key):
    """Checks file hash in VirusTotal with detailed status handling."""
    if not api_key:
        return {"error": "VT API Key missing"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"not_found": True}
        elif response.status_code == 401:
            return {"error": "Invalid API key (401 Unauthorized)"}
        elif response.status_code == 429:
            return {"error": "API request limit exceeded (Quota Exceeded)"}
        else:
            return {"error": f"API Error: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def get_file_hashes(file_bytes):
    #Generates MD5, SHA-1, and SHA-256 hashes of a file.
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),    # nosec
        "sha1": hashlib.sha1(file_bytes).hexdigest(),   # nosec
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }

def get_decimal_from_dms(dms, ref):
    """Converts coordinates from DMS format to decimal."""
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ['S', 'W']: decimal = -decimal
        return decimal
    except: 
        return None

def extract_metadata(image_file):
    """Extracts basic tags and GPS from an image, converting coordinates."""
    try:
        image = Image.open(image_file)
        exif_data = image._getexif()
        if not exif_data: return None, None, None, None
        
        metadata, gps_info = {}, {}
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_tag_id in value:
                    gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag_name] = value[gps_tag_id]
            else:
                if isinstance(value, bytes) and len(value) > 50:
                    value = f"<binary data, {len(value)} bytes>"
                metadata[tag_name] = str(value)
                
        lat, lon = None, None
        if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
            lat = get_decimal_from_dms(gps_info["GPSLatitude"], gps_info.get("GPSLatitudeRef", "N"))
            lon = get_decimal_from_dms(gps_info["GPSLongitude"], gps_info.get("GPSLongitudeRef", "E"))
        return metadata, gps_info, lat, lon
    except Exception as e:
        return {"Error": str(e)}, None, None, None

# --- MAIN INTERFACE ---
st.title("🛡️ SecOps: Threat Intel & Advanced Forensics")

# Tabs
tab1, tab2 = st.tabs(["🌐 IP Reputation", "🔬 File Forensics"])

# --- TAB 1: IP INTEL ---
with tab1:
    st.subheader("IP Intelligence (AbuseIPDB)")
    ip_to_check = st.text_input("Enter IP address to check", "121.15.140.235")

    if st.button("🚀 Launch Intel"):
        if not abuse_api_key:
            st.error("Please enter your AbuseIPDB API key in the sidebar first!")
        else:
            with st.spinner("Analyzing threat databases..."):
                url = "https://api.abuseipdb.com/api/v2/check"
                querystring = {'ipAddress': ip_to_check, 'maxAgeInDays': '90'}
                headers = {'Accept': 'application/json', 'Key': abuse_api_key}
                
                try:
                    response = requests.get(url, headers=headers, params=querystring)
                    response.raise_for_status() 
                    data = response.json()
                    
                    score = data['data']['abuseConfidenceScore']
                    country = data['data']['countryCode']
                    usage_type = data['data']['usageType']
                    isp = data['data'].get('isp', 'Unknown')
                    
                    st.markdown("---")
                    st.subheader("📊 Analysis Results")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    if score > 50:
                        col1.metric("Threat Level", f"{score}/100", "Critical", delta_color="inverse")
                    else:
                        col1.metric("Threat Level", f"{score}/100", "Normal", delta_color="normal")
                        
                    col2.metric("Country", country)
                    col3.metric("Network Type", usage_type)
                    col4.metric("ISP", isp)
                    
                    if score > 50:
                        st.error(f"🚨 ALERT: IP address {ip_to_check} is highly suspicious.")
                        if tg_token and tg_chat_id:
                            msg = f"🚨 *SecOps Alert*\n\n*IP:* `{ip_to_check}`\n*Score:* {score}/100\n*Country:* {country}\n*ISP:* {isp}\n\n_Action Required: Block IP_"
                            if send_telegram_alert(tg_token, tg_chat_id, msg):
                                st.sidebar.success("Alert forwarded to Telegram!")
                    else:
                        st.success(f"✅ IP address {ip_to_check} appears safe.")
                    
                    with st.expander("🔍 View raw server data (JSON)"):
                        st.json(data)
                        
                except Exception as e:
                    st.error(f"Error connecting to API: {e}")

# --- TAB 2: FILE FORENSICS ---
with tab2:
    st.markdown("### 🕵️ File Analysis")
    uploaded_file = st.file_uploader("Upload any file for inspection", type=None, key="main_file_uploader")
    
    if uploaded_file:
        file_bytes = uploaded_file.read()
        hashes = get_file_hashes(file_bytes)
        
        # 1. Hashes section
        st.subheader("🆔 Digital Fingerprints (Hashes)")
        c1, c2, c3 = st.columns(3)
        c1.metric("MD5", hashes['md5'][:10] + "...")
        c2.metric("SHA-1", hashes['sha1'][:10] + "...")
        c3.metric("SHA-256", hashes['sha256'][:10] + "...")
        with st.expander("Show full hashes"):
            st.write(hashes)

        # 2. VirusTotal Analysis
        st.markdown("---")
        st.subheader("🧬 Malware Analysis (VirusTotal)")
        if st.button("🔍 Check Hash on VirusTotal", key="vt_check_btn"):
            if not vt_api_key:
                st.warning("Please enter VirusTotal API Key in the sidebar!")
            else:
                with st.spinner("Checking VirusTotal database..."):
                    vt_results = check_virustotal(hashes['sha256'], vt_api_key)
                    
                    if "error" in vt_results:
                        st.error(f"⚠️ VirusTotal Error: {vt_results['error']}")
                    elif vt_results.get("not_found"):
                        st.info("ℹ️ VirusTotal has never seen this file. It is not in the threat database (normal for personal files).")
                    else:
                        # Safe parsing: using .get() to avoid KeyError
                        data_block = vt_results.get('data', {})
                        attributes = data_block.get('attributes', {})
                        stats = attributes.get('last_analysis_stats')
                        
                        if not stats:
                            st.warning("⚠️ VirusTotal returned a response, but analysis stats are missing.")
                            with st.expander("View raw API response"):
                                st.json(vt_results)
                        else:
                            malicious = stats.get('malicious', 0)
                            total = sum(stats.values())
                            
                            if malicious > 0:
                                st.error(f"🚨 DETECTED: {malicious}/{total} engines flagged this file!")
                            else:
                                st.success(f"✅ CLEAN: 0/{total} engines detected threats.")
                            
                            st.json(stats)

        # 3. Metadata (if image)
        if uploaded_file.type in ["image/jpeg", "image/png", "image/tiff"]:
            st.markdown("---")
            st.subheader("🖼️ Image Forensics (EXIF & GPS)")
            meta, gps, lat, lon = extract_metadata(uploaded_file)
            
            if lat and lon:
                st.map(pd.DataFrame({'lat': [lat], 'lon': [lon]}))
                st.info(f"📍 Location: {lat}, {lon}")
            
            c_meta, c_gps = st.columns(2)
            with c_meta:
                st.write("**EXIF Data:**")
                st.json(meta if meta else {"status": "No EXIF found"})
            with c_gps:
                st.write("**GPS Data:**")
                st.json(gps if gps else {"status": "No GPS found"})