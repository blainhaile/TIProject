import streamlit as st
import requests
import pandas as pd
import shodan  # Import the Shodan library

# Set page title
st.title("Threat Intelligence Dashboard 🚀")

# Load API keys from Streamlit Secrets
api_keys = st.secrets["api_keys"]
ABUSEIPDB_API_KEY = api_keys["abuseipdb"]
SHODAN_API_KEY = api_keys["shodan"]

# Input for IP Address
ip_address = st.text_input("Enter an IP Address:", "")

# Function to query AbuseIPDB
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json() if response.status_code == 200 else None

# Function to query Shodan
def shodan_scan(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return result
    except shodan.APIError as e:
        return {"error": str(e)}

# If user enters an IP, fetch results
if ip_address:
    # 🛡️ AbuseIPDB Check
    st.subheader("🛡️ **AbuseIPDB Threat Analysis**")
    result = check_ip(ip_address)

    if result:
        data = result.get('data', {})
        
        # Debugging step: Display the full response data to understand its structure
        st.write(f"🔧 Full response data: {data}")

        # Display Reputation Score
        st.metric(label="IP Reputation Score", value=data.get('abuseConfidenceScore', 'N/A'))

        # Display General IP Information
        st.write(f"🔹 **IP:** {data.get('ipAddress', 'N/A')}")
        st.write(f"🌍 **Country:** {data.get('countryCode', 'N/A')}")
        st.write(f"🏛️ **ISP:** {data.get('isp', 'N/A')}")

        # Safely access 'asn' and 'domain' using .get() to avoid KeyError
        asn = data.get('asn')
        domain = data.get('domain')

        # Check if 'asn' and 'domain' are in the response
        if asn is not None and domain is not None:
            st.write(f"🛜 **ASN:** {asn} ({domain})")
        else:
            # Handle case when 'asn' or 'domain' is missing
            st.write("🛜 **ASN and Domain:** Data not available")

        st.write(f"🖥️ **Usage Type:** {data.get('usageType', 'N/A')}")
        st.write(f"📅 **Last Reported:** {data.get('lastReportedAt', 'N/A')}")

        # Display reports in a table
        if data.get('totalReports', 0) > 0:
            reports = pd.DataFrame(data['reports'])
            reports = reports[['reportedAt', 'categories', 'comment']]
            st.write("🚨 **Recent Reports:**", reports)
        else:
            st.write("✅ No reports found for this IP.")
    else:
        st.error("❌ Error fetching data. Check API key or IP format.")

    # 🔍 Shodan Scan
    st.subheader("🔍 **Shodan Open Ports & Services**")
    shodan_result = shodan_scan(ip_address)

    if "error" in shodan_result:
        st.error(f"❌ Shodan Error: {shodan_result['error']}")
    else:
        # Display Open Ports
        ports = shodan_result.get("ports", [])
        if ports:
            st.write("🛠️ **Open Ports:**", ", ".join(map(str, ports)))
        else:
            st.write("✅ No open ports detected.")

        # Display Vulnerabilities
        vulnerabilities = shodan_result.get("vulns", {})
        if vulnerabilities:
            st.write("🚨 **Known Vulnerabilities:**")
            for vuln in vulnerabilities:
                st.write(f"🔴 {vuln}")
        else:
            st.write("✅ No known vulnerabilities detected.")



