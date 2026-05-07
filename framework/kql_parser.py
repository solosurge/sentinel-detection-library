import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class KQLRule:
    file_path: str
    rule_name: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    author: str
    version: str
    query: str
    tactic_folder: str


class KQLParser:
    HEADER_FIELDS = {
        "rule_name": r"//\s*Rule:\s*(.+)",
        "description": r"//\s*Description:\s*(.+)",
        "mitre_technique": r"//\s*MITRE ATT&CK Technique:\s*(.+)",
        "mitre_tactic": r"//\s*MITRE Tactic:\s*(.+)",
        "severity": r"//\s*Severity:\s*(.+)",
        "author": r"//\s*Author:\s*(.+)",
        "version": r"//\s*Version:\s*(.+)",
    }

    def parse(self, file_path: str) -> KQLRule:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"KQL file not found: {file_path}")

        content = path.read_text(encoding="utf-8")
        metadata = {}

        for field, pattern in self.HEADER_FIELDS.items():
            match = re.search(pattern, content)
            metadata[field] = match.group(1).strip() if match else "Unknown"

        lines = content.split("\n")
        query_lines = []
        header_done = False
        for line in lines:
            if header_done:
                query_lines.append(line)
            elif not line.strip().startswith("//") and line.strip() != "":
                header_done = True
                query_lines.append(line)

        tactic_folder = path.parent.name

        return KQLRule(
            file_path=str(path),
            query="\n".join(query_lines).strip(),
            tactic_folder=tactic_folder,
            **metadata
        )

    def parse_all(self, rules_dir: str) -> list:
        rules_path = Path(rules_dir)
        kql_files = list(rules_path.rglob("*.kql"))
        rules = []
        for f in sorted(kql_files):
            try:
                rules.append(self.parse(str(f)))
            except Exception as e:
                print(f"  [WARNING] Could not parse {f.name}: {e}")
        return rules
