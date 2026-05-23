import pandas as pd
import numpy as np
import json
import functools
from math import log2


@functools.lru_cache(maxsize=100000)
def _fast_parse(ranges_data_str: str) -> list:
    if not ranges_data_str or pd.isna(ranges_data_str): return []
    try:
        return json.loads(ranges_data_str)
    except Exception:
        return []

def get_ranges(ranges_data) -> list:
    """Безопасный интерфейс для парсинга, использующий кэш."""
    if isinstance(ranges_data, str):
        return _fast_parse(ranges_data)
    elif isinstance(ranges_data, list):
        return ranges_data
    return []

# =================================================================================
# 1. ИНДЕКС ПРОТУХАНИЯ (Staleness Index)
# =================================================================================
def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    if df.empty or 'vulnerability_published' not in df.columns or 'affected_ranges' not in df.columns:
        return 0.0

    def is_unfixed(ranges_data) -> bool:
        ranges = get_ranges(ranges_data)
        if not ranges: return True
        for r in ranges:
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'fixed' in event:
                        return False
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask].copy()
    if unfixed_df.empty: return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - published).dt.days.dropna()
    return round(float(((ages > 730).sum() / len(df)) * 100), 2)

# =================================================================================
# 2. СРЕДНЕЕ ВРЕМЯ ЖИЗНИ (Avg Unfixed Life)
# =================================================================================
def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    if df.empty or 'vulnerability_published' not in df.columns or 'affected_ranges' not in df.columns:
        return 0.0

    def is_unfixed(ranges_data) -> bool:
        ranges = get_ranges(ranges_data)
        if not ranges: return True
        for r in ranges:
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'fixed' in event:
                        return False
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask].copy()
    if unfixed_df.empty: return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - published).dt.days.dropna()
    ages = ages[ages >= 0]
    
    return round(float(ages.mean()), 1) if not ages.empty else 0.0

# =================================================================================
# 3. ИНТЕГРАЛЬНАЯ МЕТРИКА РИСКА (Integral Severity)
# =================================================================================
def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-22', sev_col: str = 'vulnerability_severity_text') -> float:
    if df.empty: return 0.0

    def count_affections(ranges_data) -> tuple:
        ranges = get_ranges(ranges_data)
        if not ranges: return (1, 1)

        total_aff = len(ranges)
        unfixed_aff = 0
        for r in ranges:
            is_fixed = False
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'fixed' in event:
                        is_fixed = True
                        break
            if not is_fixed: unfixed_aff += 1
        return (total_aff, unfixed_aff)

    if 'affected_ranges' in df.columns:
        counts = df['affected_ranges'].apply(count_affections)
        total_aff_series = counts.apply(lambda x: x[0])
        unfixed_aff_series = counts.apply(lambda x: x[1])
    else:
        total_aff_series = pd.Series([1] * len(df), index=df.index)
        unfixed_aff_series = pd.Series([1] * len(df), index=df.index)

    def get_weight(sev_val) -> float:
        if pd.isna(sev_val): return 1.0
        try:
            numeric_score = float(sev_val)
            if numeric_score > 0: return numeric_score
        except ValueError: pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    weights = df[sev_col].apply(get_weight) if sev_col in df.columns else pd.Series([1.0] * len(df), index=df.index)

    if 'vulnerability_published' in df.columns:
        published = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        ages = (current - published).dt.days.fillna(0).clip(lower=0)
    else:
        ages = pd.Series([0] * len(df), index=df.index)
        
    active_risk = weights * np.log1p(ages) * unfixed_aff_series
    abs_A = total_aff_series.sum()
    
    return round(float(active_risk.sum() / abs_A), 2) if abs_A > 0 else 0.0

# =================================================================================
# 4. ДОЛЯ КРИТИЧЕСКИХ УЯЗВИМОСТЕЙ (High Severity Ratio)
# =================================================================================
def calc_high_severity_ratio(df: pd.DataFrame, sev_col: str = 'vulnerability_severity_text') -> float:
    if df.empty: return 0.0

    def is_unfixed(ranges_data) -> bool:
        ranges = get_ranges(ranges_data)
        if not ranges: return True
        for r in ranges:
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'fixed' in event: return False
        return True

    def get_weight(sev_val) -> float:
        if pd.isna(sev_val): return 1.0
        try:
            numeric_score = float(sev_val)
            if numeric_score > 0: return numeric_score
        except ValueError: pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    unfixed_mask = df['affected_ranges'].apply(is_unfixed) if 'affected_ranges' in df.columns else pd.Series([True] * len(df), index=df.index)
    weights = df[sev_col].apply(get_weight) if sev_col in df.columns else pd.Series([1.0] * len(df), index=df.index)

    dangerous_count = (unfixed_mask & (weights >= 7.0)).sum()
    return round(float((dangerous_count / len(df)) * 100), 2)

# =================================================================================
# 5. ПЛОТНОСТЬ ДЕФЕКТОВ (Defect Density)
# =================================================================================
def calc_defect_density(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    if df.empty: return 0.0
    unique_packages = df[pkg_col].nunique() if pkg_col in df.columns and df[pkg_col].nunique() > 0 else 1
    return round(float(len(df) / unique_packages), 2)

# =================================================================================
# 6. ИНДЕКС РЕГРЕССИИ КОДА (Regression Rate)
# =================================================================================
def calc_regression_rate(df: pd.DataFrame) -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def has_regression(ranges_data) -> bool:
        ranges = get_ranges(ranges_data)
        if not ranges: return False
        intro_count = 0
        for r in ranges:
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'introduced' in event:
                        intro_count += 1
        return intro_count > 1

    regression_count = df['affected_ranges'].apply(has_regression).sum()
    return round(float((regression_count / len(df)) * 100), 2)

# =================================================================================
# БЕЗОПАСНАЯ НОРМАЛИЗАЦИЯ ДЛЯ ГРАФИКОВ (Защита от деления на ноль)
# =================================================================================
def normalize(values: list[float], total_pr: float = 1) -> list[float]:
    mx = max(values, default=1)
    if mx == 0: return [0.0 for _ in values] # Защита от NaN/Infinity
    return [log2(1 + el / mx) for el in values]
