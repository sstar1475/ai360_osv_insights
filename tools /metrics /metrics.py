import pandas as pd
import numpy as np
import json
from typing import Tuple

def _prepare_vulnerability_data(df: pd.DataFrame, ref_date: str, sev_col: str) -> pd.DataFrame:
    """
    Выполняет первичный анализ датасета за один проход:
    - Парсит json диапазонов и считает total_aff / unfixed_aff
    - Рассчитывает точный возраст (age) уязвимости в днях
    - Вытаскивает точные веса критичности (weights)
    """
    if df.empty:
        return pd.DataFrame()
        
    working_df = df.copy()

    # 1. Функция парсинга affected_ranges
    def parse_ranges(ranges_data) -> Tuple[int, int, bool]:
        if pd.isna(ranges_data) or not ranges_data:
            return (1, 1, True) # Фолбэк: 1 диапазон, 1 незакрыт, общее состояние - незакрыт
        try:
            ranges = json.loads(ranges_data) if isinstance(ranges_data, str) else ranges_data
            if not isinstance(ranges, list) or len(ranges) == 0:
                return (1, 1, True)
                
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
            
            # Баг считается незакрытым в целом, если хотя бы один его диапазон не закрыт
            is_any_unfixed = unfixed_aff > 0
            return (total_aff, unfixed_aff, is_any_unfixed)
        except Exception:
            return (1, 1, True)

    # Применяем парсер диапазонов
    if 'affected_ranges' in working_df.columns:
        range_stats = working_df['affected_ranges'].apply(parse_ranges)
        working_df['total_aff'] = range_stats.apply(lambda x: x[0])
        working_df['unfixed_aff'] = range_stats.apply(lambda x: x[1])
        working_df['is_unfixed_vuln'] = range_stats.apply(lambda x: x[2])
    else:
        working_df['total_aff'] = 1
        working_df['unfixed_aff'] = 1
        working_df['is_unfixed_vuln'] = True

    # 2. Парсер весов критичности
    def get_weight(sev_val) -> float:
        if pd.isna(sev_val): return 1.0
        try:
            numeric_score = float(sev_val)
            if numeric_score > 0: return numeric_score
        except ValueError:
            pass
        sev_weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        return sev_weights.get(str(sev_val).strip().upper(), 1.0)

    if sev_col in working_df.columns:
        working_df['weight'] = working_df[sev_col].apply(get_weight)
    else:
        working_df['weight'] = 1.0

    # 3. Расчет возраста (в днях)
    if 'vulnerability_published' in working_df.columns:
        published = pd.to_datetime(working_df['vulnerability_published'], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        working_df['age'] = (current - published).dt.days.fillna(0).clip(lower=0)
    else:
        working_df['age'] = 0.0

    return working_df


def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-22', sev_col: str = 'vulnerability_severity_text') -> float:
    """Вычисляет долю уязвимостей (%), которые остаются без исправления более 730 дней."""
    prepared_df = _prepare_vulnerability_data(df, ref_date, sev_col)
    if prepared_df.empty:
        return 0.0

    # Оставляем только незакрытые в целом уязвимости
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    if unfixed_df.empty:
        return 0.0

    stale_count = (unfixed_df['age'] > 730).sum()
    return round(float((stale_count / len(df)) * 100), 2)


def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-22', sev_col: str = 'vulnerability_severity_text') -> float:
    """Вычисляет средний возраст (в днях) всех незакрытых уязвимостей."""
    prepared_df = _prepare_vulnerability_data(df, ref_date, sev_col)
    if prepared_df.empty:
        return 0.0

    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    
    # Фильтруем валидный возраст (отсекаем возможные аномалии будущего времени)
    ages = unfixed_df['age'].dropna()
    ages = ages[ages >= 0]

    if ages.empty:
        return 0.0
    return round(float(ages.mean()), 1)



def calc_integral_severity(df: pd.DataFrame, ref_date: str = '2026-05-22', sev_col: str = 'vulnerability_severity_text') -> float:
    """
    Ультимативная метрика риска по всем Affections.
    Формула: Sum(sev(aff) * ln(patch_gap(aff) + 1)) / |A|
    """
    prepared_df = _prepare_vulnerability_data(df, ref_date, sev_col)
    if prepared_df.empty:
        return 0.0

    # Числитель: Риск только по НЕЗАКРЫТЫМ диапазонам
    active_risk = prepared_df['weight'] * np.log1p(prepared_df['age']) * prepared_df['unfixed_aff']
    numerator_sum = active_risk.sum()

    # Знаменатель: |A| (абсолютно все диапазоны во всех багах датасета)
    abs_A = prepared_df['total_aff'].sum()
    
    if abs_A == 0:
        return 0.0

    return round(float(numerator_sum / abs_A), 2)
