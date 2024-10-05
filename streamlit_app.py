import streamlit as st
import pandas as pd
import os, re, joblib
from sklearn.ensemble import IsolationForest

UPLOAD_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'log'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

        return log_df, action_counts, top_blocked_ports, suspicious_ips
    else:
        return None, None, None, None

def train_ai_model(log_df):
    features = log_df[['Src_Port', 'Dst_Port', 'Size']].fillna(0).astype(float)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    joblib.dump(model, 'anomaly_detection_model.pkl')

def detect_anomalies(log_df):
    model = joblib.load('anomaly_detection_model.pkl')
    features = log_df[['Src_Port', 'Dst_Port', 'Size']].fillna(0).astype(float)
    log_df['Anomaly'] = model.predict(features)
    return log_df[log_df['Anomaly'] == -1] 

st.title("AI-Powered Firewall Log Analyzer")

uploaded_file = st.file_uploader("Upload your firewall log", type="log")

if uploaded_file is not None and allowed_file(uploaded_file.name):
    with open(os.path.join(UPLOAD_FOLDER, 'uploaded.log'), 'wb') as f:
        f.write(uploaded_file.getbuffer())

    log_df, action_counts, blocked_ports, suspicious_ips = analyze_uploaded_log(os.path.join(UPLOAD_FOLDER, 'uploaded.log'))
    
    if log_df is not None:
        st.subheader("Log Data Overview")
        st.write(log_df.head())

        st.subheader("Action Counts")
        st.bar_chart(action_counts)

        st.subheader("Top Blocked Ports")
        st.bar_chart(blocked_ports)

        st.subheader("Suspicious IPs (Blocked)")
        st.bar_chart(suspicious_ips)

        train_ai_model(log_df)
        
        anomalies = detect_anomalies(log_df)

        if not anomalies.empty:
            st.subheader("Detected Anomalies (Potential Threats)")
            st.write(anomalies)
        else:
            st.write("No anomalies detected.")

    else:
        st.error("Failed to parse log data.")
else:
    st.info("Please upload a valid .log file")