import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from sklearn.cluster import KMeans

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

# Enrich data with external sources (for illustration, we are using mock data)
def enrich_with_external_data(ip_data):
    # Example: Add external threat feed or OSINT data to enrich
    ip_data['external_data'] = {"osint_source": "example.com", "risk_level": "high"}
    return ip_data

# Perform anomaly detection using KMeans clustering
def perform_anomaly_detection(ip_data):
    # For example, let's say we use risk scores to detect anomalies
    data = ip_data.get("data", {})
    if not data:
        return []
    
    # This is just a mock example of anomaly detection based on 'last_analysis_stats' (you may adapt it)
    stats = data.get("attributes", {}).get("last_analysis_stats", {})
    risk_scores = [stats.get("harmless", 0), stats.get("malicious", 0), stats.get("suspicious", 0)]
    
    # Example clustering (using KMeans to detect anomalies)
    kmeans = KMeans(n_clusters=2)
    kmeans.fit([risk_scores])
    return kmeans.labels_

# Visualize analysis with network graphs
def plot_analysis(ip_data):
    # Visualize IP relations (basic network graph)
    G = nx.Graph()
    ip = ip_data.get("data", {}).get("id", "")
    if ip:
        G.add_node(ip)
        G.add_edge(ip, "malicious_activity", weight=3)
        G.add_edge(ip, "other_ip", weight=1)
        
        plt.figure(figsize=(8, 6))
        nx.draw(G, with_labels=True, node_size=3000, node_color="skyblue", font_size=12)
        plt.title(f"Network Graph for IP: {ip}")
        st.pyplot()

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
        
        # Enrich data with external sources
        enriched_data = enrich_with_external_data(vt_result)
        st.write("🔍 **Enriched Data:**", enriched_data)
        
        # Perform anomaly detection
        anomalies = perform_anomaly_detection(enriched_data)
        st.write("🚨 **Anomaly Detection Results:**", anomalies)
        
        # Visualize data with network graph
        plot_analysis(enriched_data)

    else:
        st.error("❌ Error fetching data from VirusTotal.")


