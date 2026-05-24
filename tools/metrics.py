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
    if isinstance(ranges_data, str):
        return _fast_parse(ranges_data)
    elif isinstance(ranges_data, list):
        return ranges_data
    return []


def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """
    1. ИНДЕКС ПРОТУХАНИЯ (Staleness Index).
    Находит процент незакрытых уязвимостей, чей возраст превышает 2 года.
    """
    # Умный выбор даты: ищем intro_date, если нет - берем published
    date_col = 'intro_date' if 'intro_date' in df.columns else 'vulnerability_published'

    if df.empty or date_col not in df.columns or 'affected_ranges' not in df.columns:
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

    # Используем найденную колонку
    start_dates = pd.to_datetime(unfixed_df[date_col], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - start_dates).dt.days.dropna()
    return round(float(((ages > 730).sum() / len(df)) * 100), 2)


def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """
    2. СРЕДНЕЕ ВРЕМЯ ЖИЗНИ (Average Unfixed Life).
    Измеряет средний возраст активных дефектов.
    """
    date_col = 'intro_date' if 'intro_date' in df.columns else 'vulnerability_published'

    if df.empty or date_col not in df.columns or 'affected_ranges' not in df.columns:
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

    start_dates = pd.to_datetime(unfixed_df[date_col], errors='coerce', utc=True)
    current = pd.to_datetime(ref_date, utc=True)
    ages = (current - start_dates).dt.days.dropna()
    ages = ages[ages >= 0]

    return round(float(ages.mean()), 1) if not ages.empty else 0.0


def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-22',
                           sev_col: str = 'vulnerability_severity_text') -> float:
    """
    3. ИНТЕГРАЛЬНАЯ МЕТРИКА РИСКА (Integral Severity со ступенчатым штрафом).
    """
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
        except ValueError:
            pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    weights = df[sev_col].apply(get_weight) if sev_col in df.columns else pd.Series([1.0] * len(df), index=df.index)

    # Умный выбор колонки с датой
    date_col = 'intro_date' if 'intro_date' in df.columns else 'vulnerability_published'
    
    if date_col in df.columns:
        start_dates = pd.to_datetime(df[date_col], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        ages = (current - start_dates).dt.days.fillna(0).clip(lower=0)
    else:
        ages = pd.Series([0] * len(df), index=df.index)

    conditions = [
        (ages < 180),
        (ages >= 180) & (ages < 365),
        (ages >= 365) & (ages < 730),
        (ages >= 730)
    ]
    choices = [0.5, 1.0, 2.5, 5.0]

    aging_coeff = pd.Series(np.select(conditions, choices, default=0.0), index=df.index)

    unfixed_weight_sum = weights * unfixed_aff_series
    abandonment_penalty = aging_coeff * unfixed_weight_sum

    total_penalty = abandonment_penalty.sum()
    total_affections = total_aff_series.sum()

    return round(float(total_penalty / total_affections), 2) if total_affections > 0 else 0.0


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
        except ValueError:
            pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    unfixed_mask = df['affected_ranges'].apply(is_unfixed) if 'affected_ranges' in df.columns else pd.Series(
        [True] * len(df), index=df.index)
    weights = df[sev_col].apply(get_weight) if sev_col in df.columns else pd.Series([1.0] * len(df), index=df.index)

    dangerous_count = (unfixed_mask & (weights >= 7.0)).sum()
    return round(float((dangerous_count / len(df)) * 100), 2)


def calc_defect_density(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    """
    5. ПЛОТНОСТЬ ДЕФЕКТОВ (Top-100 Defect Density).
    Рассчитывает среднее количество уязвимостей на пакет среди 100 самых
    проблемных библиотек (глубокий эпицентр).
    """
    if df.empty or pkg_col not in df.columns:
        return 0.0

    vulnerability_counts = df[pkg_col].value_counts()
    if vulnerability_counts.empty:
        return 0.0

    # Берем топ 100 пакетов
    top_100 = vulnerability_counts.head(100)
    return round(float(top_100.mean()), 2)


def calc_risk_concentration(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    if df.empty or pkg_col not in df.columns:
        return 0.0

    vulnerability_counts = df[pkg_col].value_counts()
    if vulnerability_counts.empty:
        return 0.0

    top_5_sum = vulnerability_counts.head(5).sum()
    total_sum = len(df)

    return round(float((top_5_sum / total_sum) * 100), 2) if total_sum > 0 else 0.0


def calc_open_to_close_ratio(df: pd.DataFrame) -> float:
    if df.empty or 'affected_ranges' not in df.columns:
        return 0.0

    def has_fix(ranges_data) -> bool:
        ranges = get_ranges(ranges_data)
        if not ranges: return False
        for r in ranges:
            events = r.get('events')
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict) and 'fixed' in event:
                        return True
        return False

    fixed_mask = df['affected_ranges'].apply(has_fix)
    fixed_count = fixed_mask.sum()
    unfixed_count = len(df) - fixed_count

    if fixed_count == 0:
        return float(unfixed_count)

    return round(float(unfixed_count / fixed_count), 2)


def calc_global_security_rating(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """
    ГЛОБАЛЬНЫЙ РЕЙТИНГ БЕЗОПАСНОСТИ (GSR от 1 до 100).
    Мультипликативная модель оценки здоровья экосистемы.
    
    Формула:
      1. Нормализация базовых штрафов (0-100):
         P_S (Риск) = min((S / 25.0) * 100, 100)
         P_D (Плотность Топ-100) = min((D / 10.0) * 100, 100)
      
      2. Взвешенный базовый штраф (Риск составляет 3/4 веса, Плотность - 1/4):
         Base_Penalty = ((P_S * 3.0) + (P_D * 1.0)) / 4.0
         
      3. Мультипликатор критичности (Увеличивает штраф за высокую долю багов >= 7.0):
         Multiplier = 1.0 + (HSR / 150.0)
         
      4. Итоговый рейтинг (не ниже 1):
         GSR = max(100 - (Base_Penalty * Multiplier), 1)
    """
    if df.empty: return 100.0

    # 1. Сбор сырых метрик
    S = calc_integral_severity(df, ref_date)
    D = calc_defect_density(df)             # Top-100 плотность
    HSR = calc_high_severity_ratio(df)      # Процент критических багов (>= 7.0)

    # 2. Нормализация базовых штрафов к шкале 0-100
    p_S = min((S / 25.0) * 100.0, 100.0)
    p_D = min((D / 10.0) * 100.0, 100.0)
    
    # 3. Базовый штраф с распределением весов 3/4 (риск) и 1/4 (плотность)
    base_penalty = ((p_S * 3.0) + (p_D * 1.0)) / 4.0

    # 4. Модификатор: Доля критических багов (HSR / 150)
    multiplier = 1.0 + (HSR / 150.0)
    total_penalty = base_penalty * multiplier

    # 5. Итоговый глобальный рейтинг безопасности (GSR)
    gsr = 100.0 - total_penalty
    return round(max(gsr, 1.0), 1)


def normalize(values: list[float]) -> list[float]:
    mx = max(values, default=1)
    if mx == 0:
        return [0.0 for _ in values]
    return [100 * log2(1 + el / mx) for el in values]
