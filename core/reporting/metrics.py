# core/reporting/metrics.py
"""Thin wrapper around analyzers — backwards compatibility."""
from typing import Dict, Any, List
from .analyzers.baseline import BaselineAnalyzer
from .analyzers.compare import CompareAnalyzer


def calculate_baseline_metrics(files: Dict[str, Any]) -> Dict[str, Any]:
    return BaselineAnalyzer(files).analyze()


def calculate_compare_metrics(old_files: Dict[str, Any], new_files: Dict[str, Any],
                              diff_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return CompareAnalyzer(old_files, new_files, diff_entries).analyze()