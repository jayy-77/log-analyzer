import streamlit as st
import pandas as pd
import os, re

UPLOAD_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'log'}

def parse_log_line(line):
    fields = re.split(r' +', line.strip())
    if len(fields) < 11:
        return None

    log_data = {
        'Date': fields[0],
        'Time': fields[1],
        'Action': fields[2],
        'Protocol': fields[3],
        'Src_IP': fields[4],
        'Dst_IP': fields[5],
        'Src_Port': fields[6] if fields[6] != '-' else None,
        'Dst_Port': fields[7] if fields[7] != '-' else None,
        'Size': fields[8] if fields[8] != '-' else None,
        'TCP_Flags': fields[9] if fields[9] != '-' else None,
        'Info': " ".join(fields[10:])
    }

    return log_data

def analyze_uploaded_log(file):
    log_data_list = []
    with open(file, 'r') as f:
        next(f) 
        for line in f:
            if line.strip():
                parsed_line = parse_log_line(line)
                if parsed_line:
                    log_data_list.append(parsed_line)
    
    log_df = pd.DataFrame(log_data_list).dropna(how='all')

    if not log_df.empty:
        log_df['DateTime'] = pd.to_datetime(log_df['Date'] + ' ' + log_df['Time'], errors='coerce')
        log_df = log_df.drop(['Date', 'Time'], axis=1)
        log_df['Size'] = pd.to_numeric(log_df['Size'], errors='coerce')

        action_counts = log_df['Action'].value_counts()
        top_blocked_ports = log_df[log_df['Action'] == 'BLOCK']['Dst_Port'].value_counts().head(10)
        suspicious_ips = log_df[log_df['Action'] == 'BLOCK']['Src_IP'].value_counts().head(10)

        def identify_ddos_attempts():
            src_ip_counts = log_df.groupby(['Src_IP', pd.Grouper(key='DateTime', freq='Min')]).size()
            return src_ip_counts[src_ip_counts > 100]

        def identify_brute_force_attempts():
            failed_logins = log_df[log_df['Info'].str.contains('Failed login', case=False)]
            brute_force_attempts = failed_logins.groupby('Src_IP').size().sort_values(ascending=False)
            return brute_force_attempts[brute_force_attempts > 5]

        ddos_attempts = identify_ddos_attempts()
        brute_force_attempts = identify_brute_force_attempts()

        return log_df, action_counts, top_blocked_ports, suspicious_ips, ddos_attempts, brute_force_attempts
    else:
        return None, None, None, None, None, None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

st.title("Firewall Log Analyzer")

uploaded_file = st.file_uploader("Upload your firewall log", type="log")

if uploaded_file is not None and allowed_file(uploaded_file.name):
    with open(os.path.join(UPLOAD_FOLDER, 'uploaded.log'), 'wb') as f:
        f.write(uploaded_file.getbuffer())

    log_df, action_counts, blocked_ports, suspicious_ips, ddos_attempts, brute_force_attempts = analyze_uploaded_log(os.path.join(UPLOAD_FOLDER, 'uploaded.log'))
    
    if log_df is not None:
        st.subheader("Log Data Overview")
        st.write(log_df.head())

        st.subheader("Action Counts")
        st.bar_chart(action_counts)

        st.subheader("Top Blocked Ports")
        st.bar_chart(blocked_ports)

        st.subheader("Suspicious IPs (Blocked)")
        st.bar_chart(suspicious_ips)

        if not ddos_attempts.empty:
            st.subheader("Potential DDoS Attempts")
            st.write(ddos_attempts)
        else:
            st.write("No potential DDoS attempts detected")

        if not brute_force_attempts.empty:
            st.subheader("Brute Force Attempts")
            st.write(brute_force_attempts)
        else:
            st.write("No brute force attempts detected")
    else:
        st.error("Failed to parse log data.")
else:
    st.info("Please upload a valid .log file")