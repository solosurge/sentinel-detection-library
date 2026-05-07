#!/usr/bin/env python3
"""
sentinel-detection-library — KQL Detection Rule Validator
Validates 17 Microsoft Sentinel KQL rules against local sample data.
Usage:
  python main.py                    # test all rules
  python main.py --rule brute_force_login   # test one rule
  python main.py --tactic initial_access    # test one tactic folder
  python main.py --json             # also save JSON report
"""

import argparse
import sys
from pathlib import Path
from colorama import Fore, Style, init

from framework.kql_parser import KQLParser
from framework.sample_loader import SampleDataLoader
from framework.rule_validator import RuleValidator
from framework.report_generator import ReportGenerator

init(autoreset=True)

RULES_DIR = "rules"
SAMPLE_DATA_DIR = "tests/sample_data"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate KQL detection rules against sample log data",
        epilog="""
Examples:
  python main.py
  python main.py --rule brute_force_login
  python main.py --tactic initial_access
  python main.py --json
        """
    )
    parser.add_argument("--rule", help="Test a single rule by filename stem (e.g. brute_force_login)")
    parser.add_argument("--tactic", help="Test all rules in a tactic folder (e.g. initial_access)")
    parser.add_argument("--json", action="store_true", help="Save JSON report to reports/")
    return parser.parse_args()


def main():
    args = parse_args()
    parser = KQLParser()
    loader = SampleDataLoader(SAMPLE_DATA_DIR)
    validator = RuleValidator()
    reporter = ReportGenerator()

    print(Fore.CYAN + "\n  Loading KQL rules..." + Style.RESET_ALL)
    all_rules = parser.parse_all(RULES_DIR)
    print(f"  Found {len(all_rules)} rules\n")

    if args.rule:
        all_rules = [r for r in all_rules if Path(r.file_path).stem == args.rule]
        if not all_rules:
            print(Fore.RED + f"  No rule found with stem: {args.rule}" + Style.RESET_ALL)
            sys.exit(1)

    if args.tactic:
        all_rules = [r for r in all_rules if r.tactic_folder == args.tactic]
        if not all_rules:
            print(Fore.RED + f"  No rules found for tactic: {args.tactic}" + Style.RESET_ALL)
            sys.exit(1)

    results = []
    for rule in all_rules:
        print(f"  Testing: {rule.rule_name}")
        malicious, benign = loader.load(rule.tactic_folder, Path(rule.file_path).name)
        result = validator.validate(rule, malicious, benign)
        results.append(result)

    reporter.print_summary(results)

    if args.json:
        output_path = reporter.to_json(results)
        print(f"  JSON report saved: {output_path}\n")


if __name__ == "__main__":
    main()
