 import pandas as pd
import numpy as np
import json
import functools
from math import log2

# =================================================================================
# 1. Индекс протухания
# =================================================================================
def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-23') -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def is_unfixed(r_data) -> bool:
        if isinstance(r_data, str):
            try: ranges = json.loads(r_data)
            except: return True
        elif isinstance(r_data, list): ranges = r_data
        else: return True

        if not ranges: return True
        for r in ranges:
            if not isinstance(r, dict): continue
            events = r.get('events')
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and 'fixed' in e: return False
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask]
    if unfixed_df.empty or 'vulnerability_published' not in df.columns: return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    ages = (pd.to_datetime(ref_date, utc=True) - published).dt.days.dropna()
    
    stale_count = (ages > 730).sum()
    return round(float((stale_count / len(df)) * 100), 2)


# =================================================================================
# 2. Среднее время жизни
# =================================================================================
def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-23') -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def is_unfixed(r_data) -> bool:
        if isinstance(r_data, str):
            try: ranges = json.loads(r_data)
            except: return True
        elif isinstance(r_data, list): ranges = r_data
        else: return True

        if not ranges: return True
        for r in ranges:
            if not isinstance(r, dict): continue
            events = r.get('events')
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and 'fixed' in e: return False
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask]
    if unfixed_df.empty or 'vulnerability_published' not in df.columns: return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    ages = (pd.to_datetime(ref_date, utc=True) - published).dt.days.dropna()
    ages = ages[ages >= 0]
    
    return round(float(ages.mean()), 1) if not ages.empty else 0.0


# =================================================================================
# 3. Интегральная логарифмическая метрика
# =================================================================================
def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-23', sev_col: str = 'vulnerability_severity_text') -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def count_affections(r_data) -> tuple:
        if isinstance(r_data, str):
            try: ranges = json.loads(r_data)
            except: return (1, 1)
        elif isinstance(r_data, list): ranges = r_data
        else: return (1, 1)

        if not ranges: return (1, 1)
        unfixed_aff = 0
        valid_ranges = 0
        for r in ranges:
            if not isinstance(r, dict): continue
            valid_ranges += 1
            is_fixed = False
            events = r.get('events')
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and 'fixed' in e: is_fixed = True
            if not is_fixed: unfixed_aff += 1
            
        return (max(1, valid_ranges), unfixed_aff)

    counts = df['affected_ranges'].apply(count_affections)
    total_aff_series = counts.apply(lambda x: x[0])
    unfixed_aff_series = counts.apply(lambda x: x[1])

    def extract_weight(sev_val):
        if sev_val is None or (isinstance(sev_val, float) and np.isnan(sev_val)): return 1.0
        sev = str(sev_val).strip().upper()
        try:
            num = float(sev)
            if num > 0: return num
        except ValueError: pass
        if 'CRITICAL' in sev: return 10.0
        if 'HIGH' in sev: return 7.0
        if 'MODERATE' in sev or 'MEDIUM' in sev: return 4.0
        return 1.0
        
    weights = df[sev_col].apply(extract_weight) if sev_col in df.columns else pd.Series([1.0]*len(df), index=df.index)

    if 'vulnerability_published' in df.columns:
        published = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
        ages = (pd.to_datetime(ref_date, utc=True) - published).dt.days.fillna(0).clip(lower=0)
    else:
        ages = pd.Series([0]*len(df), index=df.index)

    active_risk = weights * np.log1p(ages) * unfixed_aff_series
    abs_A = total_aff_series.sum()
    
    return round(float(active_risk.sum() / abs_A), 2) if abs_A > 0 else 0.0


# =================================================================================
# 4. Доля критических уязвимостей
# =================================================================================
def calc_high_severity_ratio(df: pd.DataFrame, sev_col: str = 'vulnerability_severity_text') -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def is_unfixed(r_data) -> bool:
        if isinstance(r_data, str):
            try: ranges = json.loads(r_data)
            except: return True
        elif isinstance(r_data, list): ranges = r_data
        else: return True

        if not ranges: return True
        for r in ranges:
            if not isinstance(r, dict): continue
            events = r.get('events')
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and 'fixed' in e: return False
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    
    def extract_weight(sev_val):
        if sev_val is None or (isinstance(sev_val, float) and np.isnan(sev_val)): return 1.0
        sev = str(sev_val).strip().upper()
        try:
            num = float(sev)
            if num > 0: return num
        except ValueError: pass
        if 'CRITICAL' in sev: return 10.0
        if 'HIGH' in sev: return 7.0
        if 'MODERATE' in sev or 'MEDIUM' in sev: return 4.0
        return 1.0

    weights = df[sev_col].apply(extract_weight) if sev_col in df.columns else pd.Series([1.0]*len(df), index=df.index)
    
    dangerous_count = (unfixed_mask & (weights >= 7.0)).sum()
    return round(float((dangerous_count / len(df)) * 100), 2)


# =================================================================================
# 5. Плотность дефектов
# =================================================================================
def calc_defect_density(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    if df.empty: return 0.0
    unique_packages = df[pkg_col].nunique() if pkg_col in df.columns and df[pkg_col].nunique() > 0 else 1
    return round(float(len(df) / unique_packages), 2)


# =================================================================================
# 6. Индекс регрессии кода
# =================================================================================
def calc_regression_rate(df: pd.DataFrame) -> float:
    if df.empty or 'affected_ranges' not in df.columns: return 0.0

    def has_regression(r_data) -> bool:
        if isinstance(r_data, str):
            try: ranges = json.loads(r_data)
            except: return False
        elif isinstance(r_data, list): ranges = r_data
        else: return False

        if not ranges: return False
        
        for r in ranges:
            if not isinstance(r, dict): continue
            intro_count = 0
            events = r.get('events')
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and 'introduced' in e:
                        intro_count += 1
            if intro_count > 1:
                return True
        return False

    regression_count = df['affected_ranges'].apply(has_regression).sum()
    return round(float((regression_count / len(df)) * 100), 2)



def normalize(values: list[float], total_pr: float = 1) -> list[float]:
    mx = max(values, default=1)
    if mx == 0: return [0.0 for _ in values]
    return [log2(1 + el / mx) for el in values]
