import streamlit as st
import requests

# Set page title
st.title("Threat Intelligence Dashboard 🔍")

# Load API key from Streamlit Secrets
VT_API_KEY = st.secrets["api_keys"]["virustotal"]

# Input for IP Address
ip_address = st.text_input("Enter an IP Address:", "")

# Function to query VirusTotal
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY  # Correct way to use the VirusTotal API key
    }
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

# If user enters an IP, fetch VirusTotal results
if ip_address:
    st.subheader("🛡️ **VirusTotal Threat Analysis**")
    vt_result = query_virustotal(ip_address)

    if vt_result:
        # Display General IP Information
        st.write(f"🔹 **IP:** {ip_address}")
        st.write(f"🌍 **Country:** {vt_result.get('data', {}).get('attributes', {}).get('country', 'N/A')}")
        st.write(f"🏛️ **Organization:** {vt_result.get('data', {}).get('attributes', {}).get('organization', 'N/A')}")

        # Display VirusTotal analysis statistics
        attributes = vt_result.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        if last_analysis_stats:
            st.write("📊 **Malicious Analysis:**")
            st.write(f"🔴 Malicious: {last_analysis_stats.get('malicious', 0)}")
            st.write(f"🟢 Harmless: {last_analysis_stats.get('harmless', 0)}")
            st.write(f"🟡 Suspicious: {last_analysis_stats.get('suspicious', 0)}")
            st.write(f"🟢 Undetected: {last_analysis_stats.get('undetected', 0)}")
        else:
            st.write("❌ No analysis data available for this IP.")
    else:
        st.error("❌ Error fetching data from VirusTotal.")

