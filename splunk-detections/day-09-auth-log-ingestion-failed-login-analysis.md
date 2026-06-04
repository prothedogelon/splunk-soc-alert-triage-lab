# Day 9 — Splunk Auth Log Ingestion and Failed Login Analysis

## Date

June 3, 2026

## Project Context

This lab continues the Splunk/SOC learning path. Day 8 focused on getting Splunk back online, recovering access, creating an index, and preparing fake authentication log data. Day 9 moved into data onboarding, troubleshooting, and the first analyst-style findings from SSH authentication logs.

The goal was to get `auth-test.log` into Splunk, confirm where the data landed, search for failed SSH login activity, extract source IPs and targeted usernames, and write a basic SOC analyst note.

## Lab Environment

- **Operating system:** Kali Linux
- **Tool:** Splunk Enterprise
- **Log file:** `auth-test.log`
- **Custom source type:** `linux_auth`
- **Expected index:** `linux_lab`
- **Actual index used:** `main`
- **Use case:** SSH authentication log analysis

## What I Worked On

- Saved a custom source type
- Uploaded `auth-test.log` into Splunk
- Confirmed the file uploaded successfully
- Troubleshot no-result searches
- Confirmed the data landed in `main`, not `linux_lab`
- Searched for failed password events
- Used `rex` to extract source IPs
- Counted failed attempts by source IP
- Used `rex` and `coalesce()` to extract targeted usernames
- Identified `root` as the most targeted account
- Wrote a first analyst note based on the findings
- Troubleshot Splunk stability issues and learned about Linux swap

## Source Type Setup

I created a custom source type:

```text
linux_auth
```

Description:

```text
Linux authentication and sudo logs
```

This helped label the uploaded authentication log data more clearly inside Splunk.

## File Upload

The file upload completed successfully through Splunk Add Data.

Log file:

```text
auth-test.log
```

Splunk confirmed:

```text
File has been uploaded successfully.
```

## Issue: No Results at First

At first, searches such as this returned no results:

```spl
index=auth-test.log
```

That was wrong because `auth-test.log` is a source/file name, not an index.

Then I tested:

```spl
index="auth-test.log"
```

That also returned no results.

## Validation Search

To figure out where the data actually landed, I ran:

```spl
index=* "Failed password"
| stats count by index sourcetype source
```

This confirmed that the uploaded file was searchable and showed the actual index, source type, and source.

Result summary:

```text
index: main
sourcetype: linux_auth
source: auth-test.log
count: 67
```

## Key Troubleshooting Lesson

The file landed in:

```text
main
```

not:

```text
linux_lab
```

This explained the no-result searches. The issue was not that the log file failed. The issue was that I was searching the wrong index/context.

Correct search pattern:

```spl
index=main source="auth-test.log"
```

or broader validation:

```spl
index=* source="auth-test.log"
```

## Failed Login Count by Source IP

I used `rex` to extract IP addresses from failed password events.

```spl
index=* "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

This produced a table of source IPs and failed attempt counts.

Top source IP examples:

```text
185.199.108.23 — 10 failed attempts
203.0.113.10 — 10 failed attempts
10.0.0.25 — 7 failed attempts
45.33.32.10 — 6 failed attempts
198.51.100.77 — 5 failed attempts
203.0.113.99 — 5 failed attempts
66.249.66.1 — 5 failed attempts
```

## User Target Analysis

I then extracted targeted usernames from failed password events.

```spl
index=* "Failed password"
| rex "invalid user (?<target_user>\w+)"
| rex "Failed password for (?<direct_user>\w+) from"
| eval user_targeted=coalesce(target_user,direct_user)
| stats count as attempts by user_targeted
| sort - attempts
```

This helped answer:

> Which usernames were targeted most often in the authentication logs?

Observed result:

```text
root — 21 attempts
admin — 9 attempts
manager — 5 attempts
backup — 3 attempts
security — 3 attempts
test — 3 attempts
```

## Root-Focused Search

Because `root` was the most targeted account, I ran a more focused search:

```spl
index=* "Failed password" "root"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as root_failed_attempts by src_ip
| sort - root_failed_attempts
```

Root-focused source IP results included:

```text
203.0.113.10 — 10
66.249.66.1 — 5
185.199.108.23 — 4
192.168.1.60 — 2
```

## Analyst Note

Root was the most targeted account in the SSH authentication logs. This indicates that attackers or automated scanners attempted to gain privileged access to the system. No conclusion of compromise can be made from failed attempts alone, but repeated root login attempts should be treated as high priority because successful root access would give full administrative control.

## Troubleshooting: Swap and Stability

During the lab, Splunk had stability/performance issues. I worked through Linux swap troubleshooting.

I initially hit this error:

```text
swapon: /swapfile: read swap header failed
```

The fix was to recreate the swap file properly and run `mkswap` before enabling it.

Commands practiced:

```bash
sudo rm -f /swapfile
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
free -h
```

This confirmed swap was active and helped stabilize the lab environment.

## What I Learned

1. A successful upload does not mean I am searching the right index.
2. `source`, `sourcetype`, and `index` are different and must be validated.
3. No-result searches are part of the troubleshooting process.
4. `rex` can extract useful fields such as source IPs and usernames.
5. `stats count by` can quickly turn raw logs into analyst findings.
6. Repeated root login attempts should be treated as high priority.
7. Splunk stability can depend on system resources, and swap can help in a lab VM.
8. A SOC analyst must verify context before making conclusions.

## Commands and Searches Used

### Validate data location

```spl
index=* "Failed password"
| stats count by index sourcetype source
```

### Count failed attempts by source IP

```spl
index=* "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### Count targeted usernames

```spl
index=* "Failed password"
| rex "invalid user (?<target_user>\w+)"
| rex "Failed password for (?<direct_user>\w+) from"
| eval user_targeted=coalesce(target_user,direct_user)
| stats count as attempts by user_targeted
| sort - attempts
```

### Root-focused failed login analysis

```spl
index=* "Failed password" "root"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as root_failed_attempts by src_ip
| sort - root_failed_attempts
```

## Current Status

Completed:

- Uploaded `auth-test.log`
- Saved custom source type `linux_auth`
- Confirmed file upload
- Troubleshot no-result searches
- Confirmed data landed in `main`
- Found failed password events
- Counted failed attempts by source IP
- Counted failed attempts by targeted username
- Identified `root` as the highest-risk targeted account
- Wrote a first analyst note
- Fixed swap issue to improve lab stability

Next:

- Re-upload or route future auth data to `linux_lab`
- Practice `timechart` for failed logins over time
- Build a simple dashboard panel
- Create a saved search for repeated root login attempts
- Add detection logic and severity notes

## Portfolio Value

This lab shows the full SOC workflow beginning to form: data onboarding, troubleshooting, validation, field extraction, aggregation, interpretation, and analyst notes.

This was the first point where the lab moved from setup into actual security analysis.
