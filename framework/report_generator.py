import json
from datetime import datetime
from pathlib import Path
from dataclasses import asdict
from colorama import Fore, Style, init
from tabulate import tabulate
from .base_checker import TestResult, TestStatus

init(autoreset=True)


class ReportGenerator:
    STATUS_COLORS = {
        TestStatus.PASS: Fore.GREEN,
        TestStatus.FAIL: Fore.RED,
        TestStatus.ERROR: Fore.YELLOW,
        TestStatus.SKIP: Fore.CYAN,
    }

    SEVERITY_COLORS = {
        "Critical": Fore.RED,
        "High": Fore.YELLOW,
        "Medium": Fore.CYAN,
        "Low": Fore.WHITE,
    }

    def to_table(self, results: list) -> str:
        rows = []
        for r in results:
            status_color = self.STATUS_COLORS.get(r.status, "")
            severity_color = self.SEVERITY_COLORS.get(r.severity, "")
            rows.append([
                severity_color + r.severity + Style.RESET_ALL,
                r.rule_name[:45] + ("..." if len(r.rule_name) > 45 else ""),
                r.mitre_technique.split(" - ")[0],
                r.mitre_tactic,
                status_color + r.status.value + Style.RESET_ALL,
                f"{r.true_positive_rate:.0f}%",
                f"{r.false_positive_rate:.0f}%",
                f"{r.duration_ms:.1f}ms",
            ])
        headers = ["Severity", "Rule", "Technique", "Tactic", "Status", "TP Rate", "FP Rate", "Duration"]
        return tabulate(rows, headers=headers, tablefmt="simple")

    def print_summary(self, results: list):
        total = len(results)
        passed = sum(1 for r in results if r.status == TestStatus.PASS)
        failed = sum(1 for r in results if r.status == TestStatus.FAIL)
        errors = sum(1 for r in results if r.status == TestStatus.ERROR)
        skipped = sum(1 for r in results if r.status == TestStatus.SKIP)

        print("\n" + "=" * 60)
        print(Fore.CYAN + "  SENTINEL DETECTION LIBRARY — TEST REPORT" + Style.RESET_ALL)
        print("=" * 60)
        print(self.to_table(results))
        print("\n" + "-" * 60)
        print(f"  Total rules tested : {total}")
        print(f"  {Fore.GREEN}Passed{Style.RESET_ALL}             : {passed}")
        print(f"  {Fore.RED}Failed{Style.RESET_ALL}             : {failed}")
        print(f"  {Fore.YELLOW}Errors{Style.RESET_ALL}             : {errors}")
        print(f"  {Fore.CYAN}Skipped{Style.RESET_ALL}            : {skipped}")
        print("=" * 60 + "\n")

    def to_json(self, results: list, output_dir: str = "reports") -> str:
        Path(output_dir).mkdir(exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = Path(output_dir) / f"test_report_{timestamp}.json"

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_rules": len(results),
            "summary": {
                "passed": sum(1 for r in results if r.status == TestStatus.PASS),
                "failed": sum(1 for r in results if r.status == TestStatus.FAIL),
                "errors": sum(1 for r in results if r.status == TestStatus.ERROR),
                "skipped": sum(1 for r in results if r.status == TestStatus.SKIP),
            },
            "results": [asdict(r) for r in results],
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return str(output_file)
