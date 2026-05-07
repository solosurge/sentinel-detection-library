import json
from pathlib import Path
from typing import Tuple


class SampleDataLoader:
    def __init__(self, sample_data_dir: str):
        self.sample_data_dir = Path(sample_data_dir)

    def load(self, tactic_folder: str, rule_filename: str) -> Tuple[list, list]:
        """
        Looks for:
          tests/sample_data/<tactic_folder>/<rule_stem>_malicious.json
          tests/sample_data/<tactic_folder>/<rule_stem>_benign.json
        Returns (malicious_samples, benign_samples).
        Missing files return empty lists with a warning.
        """
        rule_stem = Path(rule_filename).stem
        tactic_path = self.sample_data_dir / tactic_folder

        malicious_file = tactic_path / f"{rule_stem}_malicious.json"
        benign_file = tactic_path / f"{rule_stem}_benign.json"

        malicious = self._load_file(malicious_file)
        benign = self._load_file(benign_file)

        return malicious, benign

    def _load_file(self, file_path: Path) -> list:
        if not file_path.exists():
            print(f"  [WARNING] Sample data not found: {file_path.name}")
            return []
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError as e:
            print(f"  [ERROR] Invalid JSON in {file_path.name}: {e}")
            return []
