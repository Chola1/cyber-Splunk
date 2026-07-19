# Windows Security Event Analysis

The following SPL queries were developed using Windows Security Event Logs collected from my Active Directory home lab. These investigations focus on authentication events, account activity, and identifying suspicious login behaviour using commonly monitored Windows Event IDs.

---

## #1 Most Generated Windows Event IDs

### Objective
Identify the Windows Security Event IDs that occur most frequently.

### SPL Query

```spl
index="main" sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
```

### What it does

This query counts the occurrence of each Windows Security Event ID and sorts the results in descending order. Reviewing frequently generated events helps establish a baseline of normal system activity and identify the authentication and account management events that require continuous monitoring.

---

## #2 Detecting Account Lockout Events

### Objective
Identify user account lockout events for security monitoring.

### SPL Query

```spl
index="main" sourcetype="WinEventLog:Security"
(EventCode="4625" OR EventCode="4740")
```

### What it does

This query filters failed logon attempts (**Event ID 4625**) and account lockout events (**Event ID 4740**). Monitoring these events helps identify repeated authentication failures that may indicate password guessing, brute-force attempts, or user accounts requiring investigation.

---

## #3 Identifying Accounts with the Highest Security Events

### Objective
Determine which user accounts generate the highest number of Windows security events.

### SPL Query

```spl
index="main" sourcetype="WinEventLog:Security"
| stats count by Account_Name EventCode
| stats count values(EventCode) as eventid by Account_Name
| sort -count
```

### What it does

This query aggregates Windows Security Event IDs for each user account and ranks them based on activity. It helps identify highly active accounts, privileged accounts, or accounts generating unusual authentication patterns that may require further investigation.

---

## #4 Investigating Possible Brute-Force Activity

### Objective
Correlate failed and successful authentication events from the same source to identify potential brute-force behaviour.

### SPL Query

```spl
index="main" sourcetype="WinEventLog:Security"
(EventCode="4625" OR EventCode="4624" OR EventCode="4740")
| transaction Source_Network_Address maxpause=30s maxevents=1000
| table _time Source_Network_Address EventCode eventcount duration
```

### What it does

This query uses the **transaction** command to group authentication events originating from the same source within a 30-second window. Correlating failed logons (**4625**), successful logons (**4624**), and account lockouts (**4740**) helps reconstruct authentication activity and identify patterns consistent with password guessing or potential brute-force attempts.

---

## Skills Demonstrated

- Windows Security Event Analysis
- Active Directory Log Analysis
- Authentication Monitoring
- Splunk SPL
- Event Correlation
- Brute-Force Detection
- Incident Investigation
- Security Monitoring
