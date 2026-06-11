# Day 12 — SSH Authentication Investigation Dashboard

## Lab Focus

Build a reusable Splunk dashboard from the SSH authentication investigation work.

This lab continues the prior investigation work by moving from individual searches and reports into a dashboard that can support faster triage and cleaner analyst review.

## Environment

- Platform: Kali Linux lab machine
- Tool: Splunk Enterprise
- Dataset: Linux SSH authentication and sudo activity logs
- Dashboard name: `SSH Authentication Investigation Dashboard`
- Main investigation theme: failed logins, targeted usernames, successful logins, and sudo activity

## What I Built

I created a Splunk dashboard with multiple panels to support SSH authentication analysis:

1. Top failed login source IPs
2. Most targeted usernames
3. IPs with both failed and successful logins
4. Statistics table for failed and successful login activity
5. Sudo command timeline by risky users

The goal was to move beyond running one search at a time and begin building a repeatable analyst view.

---

## Panel 1 — Top Failed Login Source IPs

### Purpose

Identify which source IPs generated the most failed SSH login attempts.

### SPL

```spl
index=* "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### Analyst Value

This helps prioritize which source IPs should be reviewed first during an SSH brute-force or credential-guessing investigation.

### Result Observed

The dashboard showed multiple source IPs with repeated failed login activity. The top two IPs each had 10 failed attempts.

---

## Panel 2 — Most Targeted Usernames

### Purpose

Identify which usernames were most frequently targeted in failed SSH attempts.

### SPL

```spl
index=* "Failed password"
| rex "invalid user (?<target_user>\w+)"
| rex "Failed password for (?<direct_user>\w+) from"
| eval user_targeted=coalesce(target_user,direct_user)
| stats count as attempts by user_targeted
| sort - attempts
```

### Analyst Value

This helps show whether attackers are targeting privileged accounts, common usernames, service accounts, or specific named users.

### Result Observed

The `root` account was the most targeted username. This is high priority because successful root access would provide full administrative control.

---

## Panel 3 — IPs with Failed and Successful Logins

### Purpose

Find IP addresses that had both failed login attempts and successful login events.

### SPL

```spl
index=* ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "Failed password for (invalid user )?(?<failed_user>\w+)"
| rex "Accepted password for (?<success_user>\w+)"
| eval user=coalesce(failed_user, success_user)
| stats 
    count(eval(searchmatch("Failed password"))) as failed_logins
    count(eval(searchmatch("Accepted password"))) as successful_logins
    values(user) as users_seen
    by src_ip
| where failed_logins > 0 AND successful_logins > 0
| sort - failed_logins
```

### Analyst Value

This panel helps identify potentially suspicious login patterns where failed attempts are followed by successful authentication.

### Result Observed

Several IPs had both failed and successful login activity. These are higher-priority review targets than failed-only sources.

---

## Panel 4 — Statistics Table for Failed and Successful Login Activity

### Purpose

Provide a clean table version of the failed and successful login analysis.

### Analyst Value

The chart is useful for quick visibility, while the statistics table provides precise values for documentation and incident notes.

Key fields reviewed:

- `src_ip`
- `failed_logins`
- `successful_logins`
- `users_seen`

---

## Panel 5 — Sudo Command Timeline by Risky Users

### Purpose

Review sudo activity by users that required closer attention during the investigation.

### SPL

```spl
index=* "sudo:"
| rex "sudo:\s(?<sudo_user>\w+)"
| rex "COMMAND=(?<command>.*)"
| search sudo_user IN ("john","backup","support","devops","security")
| stats count as command_count by sudo_user command
| sort - command_count
```

### Analyst Value

This helps connect authentication activity to post-login behavior. A successful login becomes more important when followed by sudo activity.

### Result Observed

The user `john` executed:

```text
/usr/bin/whoami
```

This command is not automatically malicious by itself, but in this lab it mattered because it appeared after the suspicious SSH sequence involving failed attempts and a successful login.

---

## Dashboard Build Notes

### Actions Completed

- Confirmed Splunk was running
- Built first dashboard panel from failed login source IP analysis
- Saved the first visualization to a new dashboard
- Added a second panel for most targeted usernames
- Added a third panel for IPs with failed and successful logins
- Corrected a panel issue by adding a cleaner replacement panel
- Added a sudo command panel for risky users
- Rearranged the dashboard layout manually
- Created a final dashboard view with charts and tables

### Dashboard Name

```text
SSH Authentication Investigation Dashboard
```

### Panel Titles

```text
Top Failed Login Source IPs
Most Targeted Usernames
IPs with Failed and Successful Logins
Statistics of IPs with Failed and Successful Logins
Sudo Command Timeline by Risky Users
```

---

## Key Learning Points

### 1. Dashboards are different from searches

A search answers one question. A dashboard organizes multiple questions into one analyst workflow.

### 2. Visuals help prioritize faster

Bar charts made it easier to quickly identify the highest failed login sources and the most targeted usernames.

### 3. Tables are still important

Tables gave the exact values needed for investigation notes, reporting, and GitHub documentation.

### 4. Failed + successful login activity is more important than failed-only activity

An IP with failed attempts and a successful login deserves closer review because it may show credential guessing followed by valid access.

### 5. Sudo activity adds post-login context

Sudo commands help answer: what happened after access was gained?

---

## Analyst Summary

A Splunk dashboard was created to support SSH authentication investigation. The dashboard includes panels for failed login source IPs, targeted usernames, IPs with both failed and successful logins, and sudo command activity by risky users.

The dashboard improves the investigation workflow by turning separate SPL searches into a repeatable view that can help identify suspicious SSH behavior and support incident triage.

The most important investigation path remains:

```text
Failed SSH attempts → Successful SSH login → Sudo command activity → Analyst review
```

## Final Reflection

Today was a step forward because the work moved from individual searches into a dashboard. This is closer to how an analyst would organize findings for repeat use.

The main progress was not just getting results. The progress was building a structure that makes the results easier to review, explain, and reuse.
