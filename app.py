import streamlit as st
import requests
import pandas as pd

# Set page title
st.title("Threat Intelligence Dashboard 🚀")

# Input for IP Address
ip_address = st.text_input("Enter an IP Address:", "")

# API Key (Replace with your own)
API_KEY = "16bb91fecf61b9a112ca286a24bc508f9493f8b5fd6e4b1fd0723c07b01ede081c7ee60c2dfd45be"  # Replace with your API key

# Function to query AbuseIPDB
def check_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json() if response.status_code == 200 else None

# If user enters an IP, fetch results
if ip_address:
    result = check_ip(ip_address)

    if result:
        data = result['data']
        
        # Display Reputation Score
        st.metric(label="IP Reputation Score", value=data['abuseConfidenceScore'])
        # Display General IP Information
        st.write(f"🔹 **IP:** {data['ipAddress']}")
        st.write(f"🌍 **Country:** {data['countryCode']}")
        st.write(f"🏛️ **ISP:** {data['isp']}")
        st.write(f"🛜 **ASN:** {data['asn']} ({data['domain']})")
        
        # Display Usage Type
        st.write(f"🖥️ **Usage Type:** {data['usageType']}")
        
        # Display Last Reported
        st.write(f"📅 **Last Reported:** {data['lastReportedAt']}")
        
        # Display reports in a table
        if data['totalReports'] > 0:
            reports = pd.DataFrame(data['reports'])
            reports = reports[['reportedAt', 'categories', 'comment']]
            st.write("🚨 **Recent Reports:**", reports)
        else:
            st.write("✅ No reports found for this IP.")
    else:
        st.error("❌ Error fetching data. Check API key or IP format.")
