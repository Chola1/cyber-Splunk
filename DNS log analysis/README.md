# DNS Log Analysis

The following SPL queries were developed using DNS logs to understand domain resolution patterns, identify frequently queried domains, and correlate DNS requests with client systems for security monitoring and threat hunting.

---

## #1 Identifying Frequently Queried Domains

### Objective
Identify the most frequently resolved Fully Qualified Domain Names (FQDNs) and the client systems responsible for the requests.

### SPL Query

```spl
index="sample" sourcetype=dnslog
| stats count values(client_ip) as client_ip values(record) as record by fqdn
| sort -count
```

### What it does

This query aggregates DNS requests by **Fully Qualified Domain Name (FQDN)** and counts how many times each domain was queried. It also lists the unique client IP addresses and DNS record types associated with each domain. Reviewing frequently requested domains helps establish normal DNS behaviour, identify commonly accessed services, and detect unusual or suspicious DNS activity during investigations.

### Skills Demonstrated

- DNS Log Analysis
- Splunk SPL
- FQDN Analysis
- Field Aggregation (`stats`, `values`)
- Security Monitoring
- Threat Hunting
