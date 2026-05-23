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
    Находит процент незакрытых уязвимостей, чей возраст с момента публикации
              превышает 2 года
    """
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


def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-22') -> float:
    """
    2. СРЕДНЕЕ ВРЕМЯ ЖИЗНИ (Average Unfixed Life).
    Измеряет средний возраст активных дефектов.
    """
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


def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-22',
                           sev_col: str = 'vulnerability_severity_text') -> float:
    """
    3. ИНТЕГРАЛЬНАЯ МЕТРИКА РИСКА (Integral Severity со ступенчатым штрафом).

    Суть: Комплексный показатель опасности с учетом штрафа за заброшенность (abandonment risk).
    Алгоритм:
      1. Каждой уязвимости присваивается вес CVSS (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1).
      2. Вес умножается на количество незакрытых веток пакета (unfixed_aff).
      3. Применяется ступенчатый штраф (aging_coeff) в зависимости от возраста уязвимости:
         - До 6 мес (<180 дней): 0.5
         - От 6 до 12 мес: 1.0
         - От 1 до 2 лет: 2.5
         - Старше 2 лет: 5.0
      4. Сумма всех штрафов делится на общее историческое количество веток (total_affections).
    Бизнес-смысл: Метрика жестко пессимизирует классы уязвимостей, которые комьюнити
                  игнорирует годами, и прощает те классы, где баги чинятся быстро.
    """
    if df.empty: return 0.0

    # Шаг 1. Подсчет общего числа веток и незакрытых веток
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

    # Шаг 2. Назначаем веса по CVSS
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

    if 'vulnerability_published' in df.columns:
        published = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        ages = (current - published).dt.days.fillna(0).clip(lower=0)
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

    # Шаг 5. Итоговая математика (как в твоем примере)
    unfixed_weight_sum = weights * unfixed_aff_series
    abandonment_penalty = aging_coeff * unfixed_weight_sum

    total_penalty = abandonment_penalty.sum()
    total_affections = total_aff_series.sum()

    return round(float(total_penalty / total_affections), 2) if total_affections > 0 else 0.0


def calc_high_severity_ratio(df: pd.DataFrame, sev_col: str = 'vulnerability_severity_text') -> float:
    """
    4. ДОЛЯ КРИТИЧЕСКИХ УЯЗВИМОСТЕЙ (High Severity Ratio).
    Возвращает процент НЕЗАКРЫТЫХ уязвимостей, имеющих оценку CVSS >= 7.0
              (статусы HIGH и CRITICAL), от общего числа всех багов в выборке.
    """
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
    5. ПЛОТНОСТЬ ДЕФЕКТОВ (Defect Density).
    Среднее количество уязвимостей на пакет
    """
    if df.empty: return 0.0
    unique_packages = df[pkg_col].nunique() if pkg_col in df.columns and df[pkg_col].nunique() > 0 else 1
    return round(float(len(df) / unique_packages), 2)


def calc_risk_concentration(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    """
    6. КОНЦЕНТРАЦИЯ РИСКА (Принцип Парето / Risk Concentration).

    Суть: Выявление главных виновников уязвимостей в экосистеме.
    Алгоритм: Считает долю (в процентах) уязвимостей, которая генерируется всего
              5-ю самыми проблемными (часто встречающимися) пакетами.
    Если показатель высокий (например, 80%),
    значит можно радикально улучшить безопасность проекта, заменив всего 5 зависимостей.
    """
    if df.empty or pkg_col not in df.columns:
        return 0.0

    vulnerability_counts = df[pkg_col].value_counts()
    if vulnerability_counts.empty:
        return 0.0

    top_5_sum = vulnerability_counts.head(5).sum()
    total_sum = len(df)

    return round(float((top_5_sum / total_sum) * 100), 2) if total_sum > 0 else 0.0


def calc_open_to_close_ratio(df: pd.DataFrame) -> float:
    """
    7. КОЭФФИЦИЕНТ НАКОПЛЕНИЯ ДОЛГА (Open-to-Close Ratio).
    Оценка скорости решения проблем сообществом (тренд).
    Отношение количества открытых (unfixed) багов к количеству закрытых (fixed).
    """
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


def normalize(values: list[float]) -> list[float]:
    mx = max(values, default=1)
    if mx == 0:
        return [0.0 for _ in values]
    return [100 * log2(1 + el / mx) for el in values]
