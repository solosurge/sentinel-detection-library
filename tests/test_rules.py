"""
pytest test suite for sentinel-detection-library
Tests that each rule correctly identifies malicious samples (true positives)
and does not flag benign samples (false positives).
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from framework.kql_parser import KQLParser
from framework.sample_loader import SampleDataLoader
from framework.rule_validator import RuleValidator
from framework.base_checker import TestStatus

RULES_DIR = str(Path(__file__).parent.parent / "rules")
SAMPLE_DATA_DIR = str(Path(__file__).parent / "sample_data")

parser = KQLParser()
loader = SampleDataLoader(SAMPLE_DATA_DIR)
validator = RuleValidator()
all_rules = parser.parse_all(RULES_DIR)
rules_by_stem = {Path(r.file_path).stem: r for r in all_rules}


def validate_rule(rule_stem: str):
    rule = rules_by_stem.get(rule_stem)
    assert rule is not None, f"Rule not found: {rule_stem}"
    malicious, benign = loader.load(rule.tactic_folder, Path(rule.file_path).name)
    result = validator.validate(rule, malicious, benign)
    return result


class TestInitialAccess:
    def test_brute_force_login(self):
        result = validate_rule("brute_force_login")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_password_spray(self):
        result = validate_rule("password_spray")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_impossible_travel(self):
        result = validate_rule("impossible_travel")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_successful_login_after_failures(self):
        result = validate_rule("successful_login_after_failures")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_mfa_fatigue(self):
        result = validate_rule("mfa_fatigue")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestPrivilegeEscalation:
    def test_privileged_role_assignment(self):
        result = validate_rule("privileged_role_assignment")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_new_admin_account_created(self):
        result = validate_rule("new_admin_account_created")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestExecution:
    def test_suspicious_powershell(self):
        result = validate_rule("suspicious_powershell")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_wmi_remote_execution(self):
        result = validate_rule("wmi_remote_execution")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_suspicious_cmd_spawn(self):
        result = validate_rule("suspicious_cmd_spawn")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestDefenseEvasion:
    def test_encoded_powershell(self):
        result = validate_rule("encoded_powershell")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_security_tool_disabled(self):
        result = validate_rule("security_tool_disabled")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_log_clearing(self):
        result = validate_rule("log_clearing")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestPersistence:
    def test_scheduled_task_creation(self):
        result = validate_rule("scheduled_task_creation")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestLateralMovement:
    def test_psexec_smb_movement(self):
        result = validate_rule("psexec_smb_movement")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0


class TestExfiltration:
    def test_large_data_upload(self):
        result = validate_rule("large_data_upload")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0

    def test_dns_tunneling(self):
        result = validate_rule("dns_tunneling")
        assert result.status == TestStatus.PASS, f"Expected PASS, got {result.status}. Errors: {result.errors}"
        assert result.true_positive_rate == 100.0
        assert result.false_positive_rate == 0.0
