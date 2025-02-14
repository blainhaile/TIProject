import streamlit as st
import requests
import pandas as pd

# Set Streamlit page title
st.title("Threat Intelligence Dashboard 🔍")

# Load API Key
VT_API_KEY = st.secrets["virustotal"]

# Input for IP Address
ip_address = st.text_input("Enter an IP Address:", "")

# Function to query VirusTotal
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None

# Process the response
if ip_address:
    with st.spinner("Scanning IP... 🔎"):
        result = query_virustotal(ip_address)

    if result:
        data = result.get("data", {}).get("attributes", {})

        # Display Reputation Score
        reputation_score = data.get("last_analysis_stats", {})
        st.subheader("🛡️ VirusTotal IP Analysis")
        st.metric("Malicious Detections", reputation_score.get("malicious", "N/A"))
        st.metric("Suspicious Detections", reputation_score.get("suspicious", "N/A"))

        # Show ASN & Network Info
        st.write(f"🌍 **Country:** {data.get('country', 'N/A')}")
        st.write(f"🛜 **ASN:** {data.get('asn', 'N/A')}")
        st.write(f"🏛️ **ISP:** {data.get('network', 'N/A')}")

        # Display associated domains
        st.subheader("🌐 Associated Domains")
        if "last_analysis_results" in data:
            vt_results = pd.DataFrame(data["last_analysis_results"]).T
            vt_results = vt_results[["category", "result"]]
            st.dataframe(vt_results)

        # Display last seen URL analysis
        st.subheader("🔗 Last Seen URLs")
        if "last_https_certificate" in data:
            cert_info = data["last_https_certificate"]
            st.write(f"🔑 Issuer: {cert_info['issuer']}")
            st.write(f"📅 Valid Until: {cert_info['validity']['not_after']}")

    else:
        st.error("❌ Error fetching data. Check API key or IP format.")


