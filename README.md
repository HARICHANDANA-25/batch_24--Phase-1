# batche-24--phase1

#  LogFlow Portal

LogFlow Portal is a Streamlit-based automation platform for:

-  Log Collection
-  Log Validation
-  Splunk HEC Data Ingestion
-  Duplicate Detection
-  Multi-Source Log Simulation

It supports automated generation, upload, validation, and ingestion of logs into Splunk using the HTTP Event Collector (HEC).

---

#  Features

##  Log Generation
Generate realistic logs for:

- Firewall Devices
- Windows Servers
- Linux Systems
- Network Switches
- Routers
- Custom Sources

---

##  Log Validation

Uploaded logs are validated using regex-based patterns before ingestion.

Examples:

| Source | Validation |
|--------|-------------|
| Firewall | action=ALLOW src=x.x.x.x |
| Windows | EventID=4624 |
| Linux | sshd, sudo, cron, kernel |
| Switches | %SWITCH-5-NOTICE |
| Routers | %BGP-5-ADJCHANGE |

---

##  Splunk HEC Integration

Logs are ingested directly into Splunk using:

- HTTP Event Collector (HEC)
- Batch Event Ingestion
- JSON Payload Format
- Token Authentication

---

Install

pip install requirements.txt

Run

streamlit run app.py 


