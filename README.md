# HTTP-Logs-Analysis-Lab-using-Splunk-
A hands-on lab project to ingest, analyze, and visualize HTTP logs using Splunk. Detects server errors, suspicious user-agents, large file transfers, and malicious URI access, while providing a ready-to-use dashboard for monitoring web activity. Ideal for learning Splunk SPL queries, log analysis, and security monitoring.

## 🎯 Objective
This lab demonstrates how to ingest, analyze, and visualize HTTP logs in Splunk. By completing this lab, you will:
- Learn to ingest Zeek-style JSON HTTP logs into Splunk.
- Detect client errors, server errors, and suspicious web activity.
- Identify large file transfers and suspicious URI access attempts.
- Create a Splunk dashboard for monitoring HTTP anomalies.

---

## 🖥️ Lab Setup

**Requirements:**
- Splunk installed and accessible (Splunk Enterprise or Splunk Cloud).
- Zeek-style JSON HTTP logs (`http_logs.json`).

**Steps to Upload Logs:**
1. Go to **Splunk Web → Settings → Add Data**.
2. Choose **Upload** and select `http_logs.json`.
3. Set **Source type**: `json` (or create a custom `zeek:http`).
4. Set **Index**: `main` (or create a new index like `http_lab`).
5. Complete the upload and confirm indexing.

---

## 🔍 Lab Tasks and SPL Queries

### Task 1: Top 10 Endpoints Generating Web Traffic
```spl
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10
```

### Task 2: Count of Server Errors (5xx)
```spl
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count as server_errors
```

### Task 3: Suspicious User-Agents
```spl
index=http_lab sourcetype="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
```

### Task 4: Large File Transfers (>500 KB)
```spl
index=http_lab sourcetype="json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```

### Task 5: Suspicious URI Access
```spl
index=http_lab sourcetype="json" uri IN ("/admin","/shell.php","/etc/passwd")
| stats count by uri, "id.orig_h"
```

✅ Conclusion

* After completing this lab, you will have:

* Ingested and analyzed HTTP logs in Splunk.

* Detected anomalies including HTTP errors, suspicious user-agents, malicious URIs, and large file transfers.

* Created a Splunk dashboard for monitoring web activity and anomalies.
