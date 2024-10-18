import pandas as pd
import re
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText

# Step 1: Log Collection & Parsing
log_data = """
127.0.0.1 - - [12/Oct/2024:12:45:45 +0000] "GET /index.html HTTP/1.1" 200
192.168.1.2 - - [12/Oct/2024:12:46:10 +0000] "POST /login HTTP/1.1" 401
203.0.113.5 - - [12/Oct/2024:12:47:20 +0000] "GET /admin HTTP/1.1" 403
"""

# Parse log data into a DataFrame
log_lines = log_data.strip().split("\n")
pattern = r'(?P<ip>\S+) - - \[(?P<date_time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status_code>\d+)'
parsed_logs = [re.match(pattern, line).groupdict() for line in log_lines]
df_logs = pd.DataFrame(parsed_logs)

# Convert date_time to pandas datetime
df_logs['date_time'] = pd.to_datetime(df_logs['date_time'], format="%d/%b/%Y:%H:%M:%S %z")
print("Parsed Logs:")
print(df_logs.head())

# Step 2: Pattern Matching for Known Threats
suspicious_ips = ["203.0.113.5", "192.168.1.2"]
sql_injection_patterns = [r"(?i)(\bselect\b|\binsert\b|\bdelete\b|\bupdate\b|\bunion\b)"]

# Detect suspicious IPs and SQL injection patterns
df_logs['suspicious_ip'] = df_logs['ip'].isin(suspicious_ips)
df_logs['sql_injection'] = df_logs['endpoint'].apply(
    lambda x: any(re.search(pattern, x) for pattern in sql_injection_patterns)
)

suspicious_logs = df_logs[(df_logs['suspicious_ip']) | (df_logs['sql_injection'])]
print("\nSuspicious Logs:")
print(suspicious_logs)

# Step 3: Frequency and Anomaly Analysis
ip_frequency = df_logs['ip'].value_counts()

# Visualize request frequency
plt.figure(figsize=(10, 5))
ip_frequency.plot(kind='bar', color='steelblue')
plt.title("Request Frequency by IP")
plt.xlabel("IP Address")
plt.ylabel("Number of Requests")
plt.show()

# Anomaly detection: flag IPs with more than 10 requests as suspicious
df_logs['anomalous'] = df_logs['ip'].map(ip_frequency) > 10
print("\nAnomalous Logs:")
print(df_logs[df_logs['anomalous']])


# Step 4: Alerting System
def send_alert(subject, message):
    sender = "shirishraj57@gmail.com"
    recipient = "shirishraj57@gmail.com"
    msg = MIMEText(message)
    msg['found supecious IP'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login(sender, "yourpassword")
        server.send_message(msg)


# Example: Send an alert if more than 5 failed login attempts are detected
failed_logins = df_logs[df_logs['status_code'] == '401']
if len(failed_logins) > 5:
    send_alert("Failed Login Alert", f"{len(failed_logins)} failed login attempts detected.")

# Step 5: Report Generation
plt.figure(figsize=(8, 6))
df_logs['status_code'].value_counts().plot(kind='bar', color='orange')
plt.title("Status Code Distribution")
plt.xlabel("Status Code")
plt.ylabel("Frequency")
plt.savefig('status_code_distribution.png')
print("Report generated and saved as 'status_code_distribution.png'")

# Step 6: Incident Investigation Support
specific_ip_logs = df_logs[df_logs['ip'] == '192.168.1.2']
print("\nLogs for IP 192.168.1.2:")
print(specific_ip_logs)

login_attempts = df_logs[df_logs['endpoint'] == '/login']
print("\nLogin Attempt Logs:")
print(login_attempts)
