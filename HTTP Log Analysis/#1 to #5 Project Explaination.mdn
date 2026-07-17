The following SPL queries were written using the Splunk BOTS v3 dataset to understand HTTP traffic, identify suspicious web activity and practice common SOC investigation workflows. 

##1 IDENTIFYING IP ADDRESS OF BAD REQUESTEES

OBJECTIVE: Identify the source IP addresses responsible for HTTP 400 (Bad Request) responses.
SPL: index="botsv3" sourcetype="access_combined" status=400 | stats count by clientip

USECASE: This query filters web server logs for **HTTP 400 responses** and groups the results by client IP address. It helps identify hosts repeatedly generating malformed or invalid requests, which may indicate vulnerability scanning, injection attacks, misconfigured user-agents or brute-force attempts requiring further investigation.

---

#2 DETECTING FREQUENTLY REQUESTED URIs:

OBJECTIVE: Identify web resources frequently associated with HTTP client errors.
SPL: index="botsv3" sourcetype="stream:http" status="4*" | stats count by uri_path | sort -count
```

### Description

This query groups HTTP **4xx responses** by requested URI to identify endpoints generating repeated errors. Frequently targeted URIs can reveal application misconfigurations, broken links, directory enumeration, vulnerability scanning, or authentication endpoints targeted during brute-force attempts.

---

## #3 Most Used HTTP Method Between Source and Destination

### Objective

Understand communication patterns between hosts by identifying the HTTP methods used.

### SPL

```spl
index="botsv3" sourcetype="stream:http"
| stats count by src_ip dest_ip http_method
```

### Description

This query summarizes HTTP methods exchanged between communicating hosts. Monitoring request methods helps establish normal application behaviour and can reveal unusual usage patterns such as unexpected POST, PUT, or DELETE requests during investigations.

---

## #4 Most Requested URI Between Source and Destination

### Objective

Identify the most frequently requested web resources during communication between hosts.

### SPL

```spl
index="botsv3" sourcetype="stream:http"
| stats values(uri_path) as most_requested values(count) as counts sum(count) as total by src_ip dest_ip
```

### Description

This query correlates source and destination IP addresses with the requested URI paths to understand browsing patterns and identify frequently accessed resources. Such analysis is useful for spotting repeated requests to sensitive endpoints or unusual application behaviour.

---

## #5 Reviewing the Latest HTTP Error Events

### Objective

Review the most recent HTTP 400 events for investigation.

### SPL

```spl
index="botsv3" sourcetype="access_combined" status=400
| stats latest(*) by _raw _time
```

### Description

This query retrieves the latest HTTP 400 events while preserving important request details such as timestamps, client IPs, request methods, and requested resources. Reviewing recent events helps analysts understand the context of web errors and validate whether suspicious activity is ongoing.

---

## Skills Demonstrated

- Splunk Enterprise
- SPL (Search Processing Language)
- HTTP Log Analysis
- Web Traffic Analysis
- Apache Log Investigation
- Incident Investigation
- Threat Hunting
- IOC Identification
- Data Aggregation (`stats`)
- Security Monitoring

