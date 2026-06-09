# Day 11 — Sudo Activity Review and Focused SSH Incident Report

## Date

June 5, 2026

## Project Context

This lab continues the Splunk/SOC investigation workflow from Day 10. The previous investigation identified a suspicious SSH sequence involving source IP `192.168.1.90`, failed logins against `john` and `johnny`, a successful login as `john`, and a follow-up sudo command.

Day 11 focused on strengthening the investigation by reviewing sudo activity from risky users, building a cleaner detection search, isolating the suspected account and source IP, and saving the search as a Splunk report.

## Lab Environment

- **Tool:** Splunk Enterprise
- **Data:** Linux SSH/authentication logs
- **Source:** `auth-test.log`
- **Sourcetype:** `linux_auth`
- **Primary suspicious account:** `john`
- **Primary suspicious source IP:** `192.168.1.90`
- **Suspicious command:** `/usr/bin/whoami`
- **Severity:** High

## Investigation Goal

The main investigation question was:

> After finding failed logins followed by a successful login, did the suspicious user perform sudo activity?

This matters because a successful login alone is not the end of the story. Post-login activity helps determine whether the behavior looks normal, suspicious, or potentially malicious.

## Search 1 — Find Sudo Commands by Risky Users

```spl
index=* "sudo:"
| rex "sudo:\s(?<sudo_user>\w+)"
| rex "COMMAND=(?<command>.*)"
| search sudo_user IN ("john","backup","support","devops","security")
| table _time sudo_user command _raw
| sort _time
```

## Result Summary

The search returned sudo activity for several risky or investigation-relevant users:

| User | Command | Initial Interpretation |
|---|---|---|
| `john` | `/usr/bin/whoami` | Highest concern because it happened after the suspicious SSH sequence |
| `backup` | `/usr/bin/rsync -av /home /mnt/backup` | Could be normal backup activity, but should be reviewed |
| `support` | `/usr/bin/systemctl restart ssh` | Service restart can affect access and logging |
| `devops` | `/usr/bin/docker ps` and `/usr/bin/docker logs webapp` | Could be normal DevOps work |
| `security` | `/usr/bin/grep Failed /var/log/auth.log` | Likely security review activity |

## Why John Became the Primary Concern

Based on the previous and current results, `john` became the primary suspicious account.

Reasoning:

```text
Failed login as john
Failed login as johnny
Successful login as john
sudo /usr/bin/whoami
```

This sequence suggests possible username guessing followed by successful credential-based access and privilege validation.

## Incident Details

```text
Project title: Suspicious SSH Login Followed by Sudo Activity
Primary suspicious account: john
Primary suspicious source IP: 192.168.1.90
Suspicious command: sudo /usr/bin/whoami
Severity: High
Status: Investigation Required
```

## Search 2 — Clean Detection Search

The next step was to create a cleaner detection search that could capture failed logins, successful logins, and sudo commands in one timeline.

```spl
index=* ("Failed password" OR "Accepted password" OR "sudo:")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "Failed password for (invalid user )?(?<failed_user>\w+)"
| rex "Accepted password for (?<success_user>\w+)"
| rex "sudo:\s(?<sudo_user>\w+)"
| rex "COMMAND=(?<command>.*)"
| eval user=coalesce(failed_user, success_user, sudo_user)
| eval event_type=case(
    searchmatch("Failed password"), "failed_login",
    searchmatch("Accepted password"), "successful_login",
    searchmatch("sudo:"), "sudo_command"
)
| table _time src_ip user event_type command _raw
| sort _time
```

## Detection Logic

This search does four important things:

1. Finds SSH failed logins, SSH successful logins, and sudo activity.
2. Extracts source IP addresses from SSH events.
3. Extracts usernames from failed login, successful login, and sudo events.
4. Labels the event as `failed_login`, `successful_login`, or `sudo_command`.

That makes the output easier to read and closer to an incident timeline.

## Search 3 — Focused Detection for John and 192.168.1.90

After identifying the suspicious account and source IP, I created a focused detection search.

```spl
index=* ("john" OR "192.168.1.90")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "Failed password for (invalid user )?(?<failed_user>\w+)"
| rex "Accepted password for (?<success_user>\w+)"
| rex "sudo:\s(?<sudo_user>\w+)"
| rex "COMMAND=(?<command>.*)"
| eval user=coalesce(failed_user, success_user, sudo_user)
| eval finding=case(
    searchmatch("Failed password"), "Failed SSH login",
    searchmatch("Accepted password"), "Successful SSH login",
    searchmatch("sudo:"), "Sudo command executed"
)
| table _time src_ip user finding command _raw
| sort _time
```

## Focused Timeline Result

The focused search produced a clean timeline:

| Time | Source IP | User | Finding | Command |
|---|---|---|---|---|
| 2026-06-02 08:32:55 | `192.168.1.90` | `john` | Failed SSH login |  |
| 2026-06-02 08:33:22 | `192.168.1.90` | `johnny` | Failed SSH login |  |
| 2026-06-02 08:34:49 | `192.168.1.90` | `john` | Successful SSH login |  |
| 2026-06-02 08:35:18 |  | `john` | Sudo command executed | `/usr/bin/whoami` |

## Incident Summary

A suspicious SSH authentication sequence was identified from source IP `192.168.1.90`. The source attempted failed logins against `john` and `johnny`, then successfully authenticated as `john`. Shortly after successful authentication, the `john` account executed:

```text
sudo /usr/bin/whoami
```

This command can indicate privilege validation behavior. The pattern is consistent with username guessing followed by successful credential-based access and post-login privilege checking.

## Severity

**Severity: High**

Reason:

- Failed logins were followed by a successful login.
- The successful login involved the account `john`.
- The same sequence included a sudo command shortly after access.
- The sudo command tested execution context using `whoami`.
- This could indicate credential-based access followed by privilege validation.

## Recommended Analyst Actions

- Confirm whether `192.168.1.90` is an authorized workstation.
- Confirm whether `john` was expected to log in at that time.
- Ask the user or system owner whether the activity was expected.
- Review additional commands run by `john`.
- Check for additional successful logins from the same source IP.
- Check whether the same source IP targeted other usernames.
- Review sudo activity around the same time window.
- Consider disabling or rotating credentials if activity is unauthorized.

## Report Created in Splunk

I saved the focused detection as a Splunk report.

Report name:

```text
SSH Authentication Investigation - Failed Login to Sudo Activity
```

Report description:

```text
Identifies SSH failed logins, successful logins, and sudo command activity to support investigation of suspicious authentication behavior.
```

A second focused report/timeline was also created:

```text
Incident Timeline - 192.168.1.90 John SSH Activity
```

This makes the investigation easier to revisit and gives the lab a more professional workflow.

## What I Learned

1. Sudo activity matters after suspicious authentication.
2. The most suspicious user is not always the user with the most total activity.
3. Context creates risk: failed login, successful login, then sudo activity is stronger than any single event alone.
4. `coalesce()` helps combine users extracted from different log patterns.
5. `case()` helps label different event types for a cleaner timeline.
6. A focused search is easier to explain than a broad search.
7. Saving a Splunk report turns a one-time search into reusable investigation work.
8. A SOC finding should include who, where, what, why it matters, severity, and next actions.

## Current Status

Completed:

- Reviewed sudo commands from risky users
- Identified `john` as the primary suspicious account
- Identified `192.168.1.90` as the primary suspicious source IP
- Confirmed `sudo /usr/bin/whoami` after successful login
- Created a clean detection search
- Created a focused John/IP timeline
- Wrote a High severity SOC finding
- Saved the search as a Splunk report

Next:

- Add the saved report to a dashboard
- Create a panel for failed vs successful logins
- Create a panel for risky sudo commands
- Build an incident review dashboard
- Add detection logic notes and response recommendations

## Portfolio Value

This lab shows a complete SOC investigation pattern: identify suspicious authentication, review successful access, inspect post-login activity, isolate the user and source IP, write a finding, assign severity, and save the search as a reusable report.

This is no longer only a Splunk setup lab. This is an investigation workflow.
