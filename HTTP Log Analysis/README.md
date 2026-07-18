# HTTP Log Analysis

This section demonstrates the use of **Splunk Enterprise** and **SPL** to analyze HTTP logs from the **BOTS v3** dataset. The queries focus on common SOC investigation workflows, including client attribution, web error analysis, request pattern analysis, and reviewing recent events.

---

## #1 Identifying Client IPs Generating HTTP Errors (Image to refer: #1 IP with error code.png)

### Objective
Identify the source IP addresses responsible for HTTP **400 (Bad Request)** responses.

### SPL Query

```spl
index="botsv3" sourcetype="access_combined" status=400
| stats count by clientip
```

### What it does
Filters HTTP 400 responses and groups the results by client IP address. This helps identify systems repeatedly generating malformed requests, which may indicate vulnerability scanning, automated tools or potential brute-force attempts.

---

## #2 Identifying Frequently Accessed Error URIs (Image to refer: #2 URI with error codes.png)

### Objective
Identify web page frequently associated with the possibility of brute-force attempts.

### SPL Query

```spl
index="botsv3" sourcetype="stream:http" status="4*" OR status="302"
| stats count by uri_path
| sort -count
```

### What it does
Groups HTTP 4** and 302 responses by URI path to identify resources generating repeated errors. Frequently targeted endpoints may indicate broken links, directory enumeration, vulnerability scanning, or authentication pages targeted during brute-force attempts.

---

## #3 Most Used HTTP Method Between Source and Destination (Image to refer: #3 Most requested HTTP method bw src-dest.png)

### Objective
Understand communication patterns between hosts by identifying the HTTP methods used.

### SPL Query

```spl
index="botsv3" sourcetype="stream:http"
| stats count by src_ip dest_ip http_method
```

### What it does
Summarizes HTTP methods exchanged between source and destination hosts. Monitoring request methods helps establish normal web traffic and detect unusual activity such as unexpected POST, PUT, or DELETE requests.

---

## #4 Most Requested URI Between Source and Destination (Image to refer: #4 Most requested URI.png)

### Objective
Identify the most frequently requested web resources during communication between hosts.

### SPL Query

```spl
index="botsv3" sourcetype="stream:http"
| stats values(uri_path) as most_requested values(count) as counts sum(count) as total by src_ip dest_ip
```

### What it does
Correlates source and destination IP addresses with requested URI paths to understand browsing patterns and identify frequently accessed resources. This is useful for spotting repeated requests to sensitive endpoints or unusual application behaviour.

---

## #5 Reviewing the Latest HTTP Error Events (Image to refer: #5 Latest generated error.png)

### Objective
Review the most recent HTTP 400 events for investigation.

### SPL Query

```spl
index="botsv3" sourcetype="access_combined" status=400
| stats latest(*) by _raw _time
```

### What it does
Retrieves the latest HTTP 400 events while preserving request details such as timestamps, client IPs, request methods, and requested resources. Reviewing recent events helps analysts understand the context of web errors and determine whether suspicious activity is ongoing.

---

## Skills Demonstrated

- Splunk Enterprise
- Search Processing Language (SPL)
- HTTP Log Analysis
- Apache Log Investigation
- Web Traffic Analysis
- Incident Investigation
- Threat Hunting
- Security Monitoring
- Data Aggregation using `stats`
