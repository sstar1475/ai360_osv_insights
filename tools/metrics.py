import pandas as pd
import numpy as np
import json


def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """Вычисляет долю уязвимостей (%), которые остаются без исправления более 730 дней."""
    if df.empty or 'vulnerability_published' not in df.columns or 'affected_ranges' not in df.columns:
        return 0.0

    def is_unfixed(ranges_data) -> bool:
        if pd.isna(ranges_data) or not ranges_data: return True
        try:
            ranges = json.loads(ranges_data) if isinstance(ranges_data, str) else ranges_data
            if not isinstance(ranges, list): return True
            for r in ranges:
                if isinstance(r.get('events'), list):
                    for event in r['events']:
                        if isinstance(event, dict) and 'fixed' in event:
                            return False
        except Exception:
            pass
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask].copy()

    if unfixed_df.empty:
        return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - published).dt.days.dropna()

    stale_count = (ages > 730).sum()
    return round(float((stale_count / len(df)) * 100), 2)


def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """Вычисляет средний возраст (в днях) всех незакрытых уязвимостей."""
    if df.empty or 'vulnerability_published' not in df.columns or 'affected_ranges' not in df.columns:
        return 0.0

    def is_unfixed(ranges_data) -> bool:
        if pd.isna(ranges_data) or not ranges_data: return True
        try:
            ranges = json.loads(ranges_data) if isinstance(ranges_data, str) else ranges_data
            if not isinstance(ranges, list): return True
            for r in ranges:
                if isinstance(r.get('events'), list):
                    for event in r['events']:
                        if isinstance(event, dict) and 'fixed' in event:
                            return False
        except Exception:
            pass
        return True

    unfixed_mask = df['affected_ranges'].apply(is_unfixed)
    unfixed_df = df[unfixed_mask].copy()

    if unfixed_df.empty:
        return 0.0

    published = pd.to_datetime(unfixed_df['vulnerability_published'], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - published).dt.days.dropna()
    ages = ages[ages >= 0]  # Защита от дат из будущего

    if ages.empty:
        return 0.0
    return round(float(ages.mean()), 1)


def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-22',
                           sev_col: str = 'vulnerability_severity_text') -> float:
    """
    Ультимативная метрика риска по всем Affections.
    Формула: Sum(sev(aff) * ln(patch_gap(aff) + 1)) / |A|,
    где |A| - общее количество всех диапазонов (affections) в датасете.
    """
    if df.empty:
        return 0.0

    def count_affections(ranges_data) -> tuple:
        if pd.isna(ranges_data) or not ranges_data:
            return (1, 1)  # Фолбэк: считаем как 1 диапазон, который не закрыт

        try:
            ranges = json.loads(ranges_data) if isinstance(ranges_data, str) else ranges_data
            if not isinstance(ranges, list) or len(ranges) == 0:
                return (1, 1)

            total_aff = len(ranges)
            unfixed_aff = 0

            for r in ranges:
                is_fixed = False
                if isinstance(r.get('events'), list):
                    for event in r['events']:
                        if isinstance(event, dict) and 'fixed' in event:
                            is_fixed = True
                            break
                if not is_fixed:
                    unfixed_aff += 1

            return (total_aff, unfixed_aff)
        except Exception:
            return (1, 1)

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
        except ValueError:
            pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    if sev_col in df.columns:
        weights = df[sev_col].apply(get_weight)
    else:
        weights = pd.Series([1.0] * len(df), index=df.index)

    if 'vulnerability_published' in df.columns:
        published = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        ages = (current - published).dt.days.fillna(0).clip(lower=0)
    else:
        ages = pd.Series([0] * len(df), index=df.index)
    active_risk = weights * np.log1p(ages) * unfixed_aff_series
    numerator_sum = active_risk.sum()

    abs_A = total_aff_series.sum()
    if abs_A == 0:
        return 0.0

    return round(float(numerator_sum / abs_A), 2)


from math import log2


def normalize(values: list[float], total_pr: float = 1) -> list[float]:
    mx = max(values, default=1)
    norm = mx * total_pr
    return [log2(1 + el / mx) for el in values]