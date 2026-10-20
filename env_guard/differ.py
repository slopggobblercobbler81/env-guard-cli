"""Diffing engine for comparing environment files."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .parser import parse_env


@dataclass
class DiffResult:
    source_path: str
    target_path: str
    missing_in_target: List[str]
    missing_in_source: List[str]
    value_differences: Dict[str, tuple[str, str]]
    identical_keys: List[str]

    @property
    def has_differences(self) -> bool:
        return bool(self.missing_in_target or self.missing_in_source or self.value_differences)


class EnvDiffer:
    """Compares two environment files."""

    @staticmethod
    def compare(source_path: str, target_path: str, compare_values: bool = False) -> DiffResult:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            source_content = f.read()
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            target_content = f.read()

        source_dict = parse_env(source_content)
        target_dict = parse_env(target_content)

        source_keys = set(source_dict.keys())
        target_keys = set(target_dict.keys())

        missing_in_target = sorted(list(source_keys - target_keys))
        missing_in_source = sorted(list(target_keys - source_keys))

        common_keys = source_keys & target_keys
        value_differences: Dict[str, tuple[str, str]] = {}
        identical_keys: List[str] = []

        for key in sorted(common_keys):
            if compare_values:
                if source_dict[key] != target_dict[key]:
                    value_differences[key] = (source_dict[key], target_dict[key])
                else:
                    identical_keys.append(key)
            else:
                identical_keys.append(key)

        return DiffResult(
            source_path=source_path,
            target_path=target_path,
            missing_in_target=missing_in_target,
            missing_in_source=missing_in_source,
            value_differences=value_differences,
            identical_keys=identical_keys,
        )
