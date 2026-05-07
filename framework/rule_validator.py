from pathlib import Path
from .base_checker import BaseRuleChecker, TestResult, TestStatus
from .kql_parser import KQLRule


class RuleValidator(BaseRuleChecker):
    """
    Validates a KQL rule against sample log data using field-based matching.
    Since we cannot run KQL locally, validation works by:
    - Malicious samples: must contain the key indicator fields the rule targets
    - Benign samples: must NOT match the indicator fields (no false positives)
    Each rule defines its expected indicator fields in RULE_INDICATORS.
    """

    RULE_INDICATORS = {
        "brute_force_login": {
            "required_fields": ["UserPrincipalName", "IPAddress", "ResultType"],
            "malicious_conditions": lambda s: s.get("ResultType") != "0" and s.get("FailureCount", 0) >= 10,
            "benign_conditions": lambda s: s.get("ResultType") == "0" or s.get("FailureCount", 0) < 10,
        },
        "password_spray": {
            "required_fields": ["IPAddress", "UserPrincipalName", "ResultType"],
            "malicious_conditions": lambda s: s.get("TargetedAccounts", 0) >= 5 and s.get("AttemptsPerUser", 99) < 3,
            "benign_conditions": lambda s: s.get("TargetedAccounts", 0) < 5,
        },
        "impossible_travel": {
            "required_fields": ["UserPrincipalName", "CountryOrRegion", "ResultType"],
            "malicious_conditions": lambda s: s.get("ResultType") == "0" and s.get("CountryOrRegion") != s.get("CountryOrRegion2") and s.get("TravelTimeMinutes", 999) <= 60,
            "benign_conditions": lambda s: s.get("CountryOrRegion") == s.get("CountryOrRegion2"),
        },
        "successful_login_after_failures": {
            "required_fields": ["UserPrincipalName", "FailureCount", "SuccessTime"],
            "malicious_conditions": lambda s: s.get("FailureCount", 0) >= 5 and s.get("MinutesAfterLastFailure", 999) <= 30,
            "benign_conditions": lambda s: s.get("FailureCount", 0) < 5,
        },
        "mfa_fatigue": {
            "required_fields": ["UserPrincipalName", "MFAPushCount"],
            "malicious_conditions": lambda s: s.get("MFAPushCount", 0) >= 10,
            "benign_conditions": lambda s: s.get("MFAPushCount", 0) < 10,
        },
        "privileged_role_assignment": {
            "required_fields": ["AssignedRole", "TargetUserUPN", "InitiatedByUPN"],
            "malicious_conditions": lambda s: s.get("AssignedRole", "") in ["Global Administrator", "Privileged Role Administrator", "Security Administrator"],
            "benign_conditions": lambda s: s.get("AssignedRole", "") not in ["Global Administrator", "Privileged Role Administrator", "Security Administrator"],
        },
        "new_admin_account_created": {
            "required_fields": ["NewUserUPN", "AssignedRole", "HoursToPromotion"],
            "malicious_conditions": lambda s: s.get("HoursToPromotion", 999) <= 24 and s.get("AssignedRole", "") != "",
            "benign_conditions": lambda s: s.get("HoursToPromotion", 999) > 24,
        },
        "suspicious_powershell": {
            "required_fields": ["DeviceName", "ProcessCommandLine", "FileName"],
            "malicious_conditions": lambda s: any(kw in s.get("ProcessCommandLine", "").lower() for kw in ["-encodedcommand", "iex", "downloadstring", "-windowstyle hidden", "bypass"]),
            "benign_conditions": lambda s: not any(kw in s.get("ProcessCommandLine", "").lower() for kw in ["-encodedcommand", "iex", "downloadstring", "-windowstyle hidden", "bypass"]),
        },
        "encoded_powershell": {
            "required_fields": ["DeviceName", "ProcessCommandLine", "PayloadLength"],
            "malicious_conditions": lambda s: s.get("PayloadLength", 0) > 100 and any(flag in s.get("ProcessCommandLine", "").lower() for flag in ["-enc", "-encodedcommand"]),
            "benign_conditions": lambda s: s.get("PayloadLength", 0) <= 100,
        },
        "wmi_remote_execution": {
            "required_fields": ["DeviceName", "InitiatingProcessFileName", "FileName"],
            "malicious_conditions": lambda s: s.get("InitiatingProcessFileName", "").lower() == "wmiprvse.exe" and s.get("FileName", "").lower() in ["cmd.exe", "powershell.exe", "cscript.exe"],
            "benign_conditions": lambda s: s.get("InitiatingProcessFileName", "").lower() != "wmiprvse.exe",
        },
        "suspicious_cmd_spawn": {
            "required_fields": ["DeviceName", "InitiatingProcessFileName", "FileName"],
            "malicious_conditions": lambda s: s.get("FileName", "").lower() == "cmd.exe" and s.get("InitiatingProcessFileName", "").lower() in ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe"],
            "benign_conditions": lambda s: s.get("InitiatingProcessFileName", "").lower() not in ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe"],
        },
        "scheduled_task_creation": {
            "required_fields": ["Computer", "TaskName", "TaskContent"],
            "malicious_conditions": lambda s: any(kw in s.get("TaskContent", "").lower() for kw in ["powershell", "encodedcommand", "downloadstring", "\\temp\\", "\\appdata\\local\\temp\\"]),
            "benign_conditions": lambda s: not any(kw in s.get("TaskContent", "").lower() for kw in ["powershell", "encodedcommand", "downloadstring", "\\temp\\", "\\appdata\\local\\temp\\"]),
        },
        "security_tool_disabled": {
            "required_fields": ["Computer", "EventID", "ServiceName"],
            "malicious_conditions": lambda s: s.get("EventID") in [4719, 7036, 7040] and any(svc in s.get("ServiceName", "") for svc in ["Defender", "WinDefend", "EventLog", "MsMpEng"]),
            "benign_conditions": lambda s: s.get("EventID") not in [4719, 7036, 7040],
        },
        "log_clearing": {
            "required_fields": ["Computer", "EventID", "SubjectUserName"],
            "malicious_conditions": lambda s: s.get("EventID") in [1102, 104],
            "benign_conditions": lambda s: s.get("EventID") not in [1102, 104],
        },
        "psexec_smb_movement": {
            "required_fields": ["DeviceName", "FileName", "EventSource"],
            "malicious_conditions": lambda s: s.get("FileName", "").lower() in ["psexec.exe", "psexec64.exe"] or s.get("ShareName", "").endswith("ADMIN$"),
            "benign_conditions": lambda s: s.get("FileName", "").lower() not in ["psexec.exe", "psexec64.exe"] and not s.get("ShareName", "").endswith("ADMIN$"),
        },
        "large_data_upload": {
            "required_fields": ["SourceIP", "DestinationIP", "TotalSentBytes"],
            "malicious_conditions": lambda s: s.get("TotalSentBytes", 0) > 500000000 and not s.get("DestinationIP", "").startswith(("10.", "192.168.", "172.16.")),
            "benign_conditions": lambda s: s.get("TotalSentBytes", 0) <= 500000000,
        },
        "dns_tunneling": {
            "required_fields": ["ClientIP", "Name", "DetectionReason"],
            "malicious_conditions": lambda s: s.get("SubdomainLength", 0) > 50 or s.get("QueryCount", 0) > 200,
            "benign_conditions": lambda s: s.get("SubdomainLength", 0) <= 50 and s.get("QueryCount", 0) <= 200,
        },
    }

    @property
    def name(self) -> str:
        return "RuleValidator"

    def validate(self, rule: KQLRule, malicious_samples: list, benign_samples: list) -> TestResult:
        self._start_timer()
        rule_stem = Path(rule.file_path).stem
        indicators = self.RULE_INDICATORS.get(rule_stem)

        result = TestResult(
            rule_name=rule.rule_name,
            rule_file=rule.file_path,
            mitre_technique=rule.mitre_technique,
            mitre_tactic=rule.mitre_tactic,
            severity=rule.severity,
            status=TestStatus.SKIP,
        )

        if not indicators:
            result.errors.append(f"No indicator definition found for rule: {rule_stem}")
            result.status = TestStatus.ERROR
            result.duration_ms = self._get_duration_ms()
            return result

        if not malicious_samples and not benign_samples:
            result.errors.append("No sample data found — skipping validation")
            result.status = TestStatus.SKIP
            result.duration_ms = self._get_duration_ms()
            return result

        tp = 0
        fp = 0
        mal_cond = indicators["malicious_conditions"]
        ben_cond = indicators["benign_conditions"]

        for sample in malicious_samples:
            matched = mal_cond(sample)
            result.findings.append(self._create_finding(sample, matched, "malicious sample"))
            if matched:
                tp += 1

        for sample in benign_samples:
            matched = not ben_cond(sample)
            result.findings.append(self._create_finding(sample, matched, "benign sample"))
            if matched:
                fp += 1

        result.true_positive_count = tp
        result.false_positive_count = fp
        result.true_positive_rate = round(tp / len(malicious_samples) * 100, 1) if malicious_samples else 0.0
        result.false_positive_rate = round(fp / len(benign_samples) * 100, 1) if benign_samples else 0.0

        if result.true_positive_rate == 100.0 and result.false_positive_rate == 0.0:
            result.status = TestStatus.PASS
        elif result.false_positive_rate > 0:
            result.status = TestStatus.FAIL
        elif result.true_positive_rate < 100.0:
            result.status = TestStatus.FAIL
        else:
            result.status = TestStatus.PASS

        result.duration_ms = self._get_duration_ms()
        return result
