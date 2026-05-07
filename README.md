# sentinel-detection-library

![Python](https://img.shields.io/badge/python-3.11-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Tests](https://img.shields.io/badge/tests-17%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

This repository contains 17 production-quality KQL detection rules for Microsoft Sentinel, organized by MITRE ATT&CK tactic, paired with a Python automated testing framework that validates each rule fires correctly on malicious samples and produces zero false positives on benign samples. The framework mirrors each rule's detection logic in Python lambdas, enabling full offline validation — no Azure subscription or Sentinel workspace required to run the test suite. Rules are ready for direct deployment into the Sentinel Analytics Rule wizard.

---

## Detection Coverage

| Tactic | Rule | MITRE Technique | Severity |
|--------|------|-----------------|----------|
| Initial Access | Brute Force Login Attempts Detected | T1110.001 | Medium |
| Initial Access | Password Spray Attack Detected | T1110.003 | High |
| Initial Access | Impossible Travel Detected | T1078 | High |
| Initial Access | Successful Login After Multiple Failures | T1110 | Medium |
| Initial Access | MFA Fatigue Attack - Excessive Push Notifications | T1621 | High |
| Privilege Escalation | Privileged Role Assigned to User | T1078.004 | High |
| Privilege Escalation | New Administrative Account Created | T1136 | Medium |
| Execution | Suspicious PowerShell Execution Detected | T1059.001 | High |
| Execution | WMI Remote Code Execution | T1047 | High |
| Execution | Suspicious cmd.exe Spawned by Unexpected Parent | T1059.003 | Medium |
| Defense Evasion | Base64 Encoded PowerShell Command | T1027 | High |
| Defense Evasion | Security Tool or Audit Logging Disabled | T1562.001 | Critical |
| Defense Evasion | Windows Event Log Cleared | T1070.001 | High |
| Persistence | Suspicious Scheduled Task Created | T1053.005 | Medium |
| Lateral Movement | Lateral Movement via PsExec or SMB | T1570 | High |
| Exfiltration | Large Data Upload to External IP | T1048 | High |
| Exfiltration | DNS Tunneling Indicators | T1071.004 | High |

---

## Repository Structure

```
sentinel-detection-library/
├── rules/
│   ├── initial_access/        # 5 rules
│   ├── execution/             # 3 rules
│   ├── persistence/           # 1 rule
│   ├── privilege_escalation/  # 2 rules
│   ├── defense_evasion/       # 3 rules
│   ├── lateral_movement/      # 1 rule
│   └── exfiltration/          # 2 rules
├── framework/
│   ├── base_checker.py        # Abstract base class (BaseRuleChecker)
│   ├── kql_parser.py          # Parses .kql files and extracts metadata
│   ├── sample_loader.py       # Loads JSON test data by tactic/rule
│   ├── rule_validator.py      # Field-based detection logic per rule
│   └── report_generator.py   # Colored table + JSON report output
├── tests/
│   ├── test_rules.py          # pytest suite — 17 tests
│   └── sample_data/           # 34 JSON files (malicious + benign per rule)
├── reports/                   # JSON test reports (git-ignored)
├── main.py                    # CLI entry point
├── requirements.txt
└── README.md
```

---

## How It Works — Testing Approach

Since KQL cannot execute outside of a Sentinel workspace, the framework implements field-based matching logic in Python that mirrors each rule's detection conditions. Each rule has a corresponding `RULE_INDICATORS` entry in `rule_validator.py` defining `malicious_conditions` and `benign_conditions` as Python lambdas that operate on the same fields a deployed Sentinel rule would evaluate. The framework runs every sample through these conditions and reports true positive rate and false positive rate per rule. This design lets detection rules be validated in a local CI/CD pipeline — catching logic errors and false positive regressions before deployment to production.

---

## KQL Rule Format

Every `.kql` file opens with a standardized 7-line header:

```kql
// Rule: <name>
// Description: <description>
// MITRE ATT&CK Technique: <ID> - <name>
// MITRE Tactic: <tactic>
// Severity: <Critical|High|Medium|Low>
// Author: solosurge
// Version: 1.0
```

**Example — `rules/initial_access/brute_force_login.kql`:**

```kql
// Rule: Brute Force Login Attempts Detected
// Description: Detects accounts with 10 or more failed login attempts within a 1-hour window.
// MITRE ATT&CK Technique: T1110.001 - Password Guessing
// MITRE Tactic: Initial Access
// Severity: Medium
// Author: solosurge
// Version: 1.0

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize
    FailureCount = count(),
    DistinctLocations = dcount(Location),
    Applications = make_set(AppDisplayName),
    FirstAttempt = min(TimeGenerated),
// ... full query in rules/initial_access/brute_force_login.kql
```

---

## Framework Architecture

`RuleValidator` inherits from `BaseRuleChecker`, the same abstract base class pattern used in [Project 1 (security-scanner)](https://github.com/solosurge/security-scanner). This enforces a consistent interface across checker components: every checker declares a `name` property and a `validate()` method, and inherits shared utilities for timing and finding construction.

```
BaseRuleChecker (abstract)
├── name (abstract property)
├── validate() (abstract method)
├── _start_timer()
├── _get_duration_ms()
└── _create_finding()
    └── RuleValidator (concrete)
        └── RULE_INDICATORS: dict of 17 lambda-based detection conditions
```

---

## Usage

#### Run all rules

```bash
python main.py
```

#### Run a single rule

```bash
python main.py --rule brute_force_login
```

#### Run all rules in a tactic

```bash
python main.py --tactic initial_access
```

#### Save JSON report

```bash
python main.py --json
```

#### Run pytest suite

```bash
python -m pytest tests/test_rules.py -v
```

---

## Test Results

```
============================================================
  SENTINEL DETECTION LIBRARY — TEST REPORT
============================================================
Severity    Rule                                Technique    Tactic                Status    TP Rate    FP Rate
----------  ----------------------------------  -----------  --------------------  --------  ---------  ---------
High        Base64 Encoded PowerShell Command   T1027        Defense Evasion       PASS      100%       0%
High        Windows Event Log Cleared           T1070.001    Defense Evasion       PASS      100%       0%
Critical    Security Tool or Audit Logging...   T1562.001    Defense Evasion       PASS      100%       0%
Medium      Suspicious cmd.exe Spawned by...    T1059.003    Execution             PASS      100%       0%
High        Suspicious PowerShell Execution     T1059.001    Execution             PASS      100%       0%
High        WMI Remote Code Execution           T1047        Execution             PASS      100%       0%
High        DNS Tunneling Indicators            T1071.004    Exfiltration          PASS      100%       0%
High        Large Data Upload to External IP    T1048        Exfiltration          PASS      100%       0%
Medium      Brute Force Login Attempts          T1110.001    Initial Access        PASS      100%       0%
High        Impossible Travel Detected          T1078        Initial Access        PASS      100%       0%
High        MFA Fatigue Attack                  T1621        Initial Access        PASS      100%       0%
High        Password Spray Attack Detected      T1110.003    Initial Access        PASS      100%       0%
Medium      Successful Login After Failures     T1110        Initial Access        PASS      100%       0%
High        Lateral Movement via PsExec/SMB     T1570        Lateral Movement      PASS      100%       0%
Medium      Suspicious Scheduled Task Created   T1053.005    Persistence           PASS      100%       0%
Medium      New Administrative Account          T1136        Privilege Escalation  PASS      100%       0%
High        Privileged Role Assigned to User    T1078.004    Privilege Escalation  PASS      100%       0%
------------------------------------------------------------
  Total rules tested : 17   Passed: 17   Failed: 0   Skipped: 0
============================================================

17 passed in 0.08s
```

---

## Setup

```bash
git clone https://github.com/solosurge/sentinel-detection-library.git
cd sentinel-detection-library
pip install -r requirements.txt
python main.py
```

---

## Deploying Rules to Microsoft Sentinel

Each `.kql` file in the `rules/` directory is a production-ready query that can be pasted directly into the Microsoft Sentinel Analytics Rule wizard. Map the MITRE ATT&CK technique and tactic from the file header when configuring the rule in Sentinel.

---

## Portfolio Context

This project demonstrates detection engineering, a core competency for Security Operations Automation roles. The automated testing framework applies software engineering discipline to security rule development — validating that rules fire correctly before production deployment. Combined with Project 1 (Python security tooling) and Project 2 (Azure SOAR automation), this completes a portfolio covering Python scripting, cloud platform operation, SOAR automation, and detection engineering.

- **Project 1 — Python Security Scanner:** https://github.com/solosurge/security-scanner
- **Project 2 — Azure SOAR Phishing Response Pipeline:** https://github.com/solosurge/phishing-response-pipeline

---

## License

MIT License
