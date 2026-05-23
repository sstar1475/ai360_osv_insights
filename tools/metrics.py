import pandas as pd
import numpy as np
import json
from math import log2

def _prepare_db_data(df: pd.DataFrame, ref_date: str = '2026-05-23',
                     sev_col: str = 'vulnerability_severity_text') -> pd.DataFrame:
    """
    Скрытая функция предобработки, настроенная СТРОГО под структуру
    вывода get_detailed_report() из OSVDataClient.
    """
    if df.empty: return pd.DataFrame()
    if 'is_unfixed_vuln' in df.columns: return df.copy()

    working_df = df.copy()

    def extract_weight(sev_val) -> float:
        if pd.isna(sev_val): return 1.0
        sev_str = str(sev_val).strip().upper()
        try:
            num = float(sev_str)
            if num > 0: return num
        except ValueError:
            pass
        weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        for k, v in weights.items():
            if k in sev_str: return v
        return 1.0

    # 1. Глобальный вес (из vulnerabilities)
    working_df['global_weight'] = working_df.get(sev_col, pd.Series([1.0] * len(working_df))).apply(extract_weight)

    # 2. Локальный вес (из affections)
    if 'affected_severity' in working_df.columns:
        working_df['local_weight'] = working_df['affected_severity'].apply(extract_weight)
    else:
        working_df['local_weight'] = 1.0

    def parse_row(row):
        ranges_data = row.get('affected_ranges')

        # Выбираем максимальный приоритет (локальный перебивает глобальный)
        g_w = row.get('global_weight', 1.0)
        l_w = row.get('local_weight', 1.0)
        final_w = max(g_w, l_w) if l_w > 1.0 else g_w

        if pd.isna(ranges_data) or not ranges_data:
            return pd.Series({'total_aff': 1, 'unfixed_aff': 1, 'is_unfixed_vuln': True, 'has_regression': False,
                              'unfixed_weight_sum': final_w})

        # Безопасный парсинг строки от asyncpg
        ranges = ranges_data
        if isinstance(ranges_data, str):
            try:
                ranges = json.loads(ranges_data)
            except:
                ranges = []

        if not isinstance(ranges, list) or len(ranges) == 0:
            return pd.Series({'total_aff': 1, 'unfixed_aff': 1, 'is_unfixed_vuln': True, 'has_regression': False,
                              'unfixed_weight_sum': final_w})

        total_aff = len(ranges)
        unfixed_aff = 0
        intro_count = 0

        for r in ranges:
            is_fixed = False
            if isinstance(r, dict):
                events = r.get('events', [])
                if isinstance(events, list):
                    for e in events:
                        if isinstance(e, dict):
                            if 'introduced' in e:
                                intro_count += 1
                                is_fixed = False
                            if 'fixed' in e:
                                is_fixed = True
            if not is_fixed:
                unfixed_aff += 1

        return pd.Series({
            'total_aff': total_aff,
            'unfixed_aff': unfixed_aff,
            'is_unfixed_vuln': unfixed_aff > 0,
            'has_regression': intro_count > 1,
            'unfixed_weight_sum': final_w * unfixed_aff
        })

    stats = working_df.apply(parse_row, axis=1)
    working_df = pd.concat([working_df, stats], axis=1)

    # 3. Возраст уязвимостей (привязка к правильному SQL-алиасу)
    pub_col = 'vulnerability_published'
    if pub_col in working_df.columns:
        published = pd.to_datetime(working_df[pub_col], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        working_df['age'] = (current - published).dt.days.fillna(0).clip(lower=0)
    else:
        working_df['age'] = 0.0

    return working_df


# =================================================================================
# 1. Метрика: Индекс протухания
# =================================================================================
def calc_staleness_index(df: pd.DataFrame, ref_date: str = '2026-05-23') -> float:
    """Индекс протухания (>2 лет без патча)."""
    prepared_df = _prepare_db_data(df, ref_date)
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    if unfixed_df.empty: return 0.0

    stale_count = (unfixed_df['age'] > 730).sum()
    return round(float((stale_count / len(prepared_df)) * 100), 2)


# =================================================================================
# 2. Метрика: Среднее время жизни
# =================================================================================
def calc_avg_unfixed_life(df: pd.DataFrame, ref_date: str = '2026-05-23') -> float:
    """Среднее время жизни (MTTR в днях) незакрытых уязвимостей."""
    prepared_df = _prepare_db_data(df, ref_date)
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    ages = unfixed_df['age'].dropna()
    ages = ages[ages >= 0]
    return round(float(ages.mean()), 1) if not ages.empty else 0.0


# =================================================================================
# 3. Метрика: Интегральный риск заброшенности (ступенчатая оценка)
# =================================================================================
def calc_abandonment_risk_score(df: pd.DataFrame, ref_date: str = '2026-05-23') -> float:
    """
    Ступенчатый риск заброшенности кодовой базы.
    Штрафы по интервалам: <6 мес(0.0), >6 мес(1.0), >1 года(2.5), >2 лет(5.0).
    """
    prepared_df = _prepare_db_data(df, ref_date)
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']].copy()
    if unfixed_df.empty: return 0.0

    conditions = [
        (unfixed_df['age'] < 180),
        (unfixed_df['age'] >= 180) & (unfixed_df['age'] < 365),
        (unfixed_df['age'] >= 365) & (unfixed_df['age'] < 730),
        (unfixed_df['age'] >= 730)
    ]
    choices = [0.0, 1.0, 2.5, 5.0]
    unfixed_df['aging_coeff'] = np.select(conditions, choices, default=0.0)
    unfixed_df['abandonment_penalty'] = unfixed_df['aging_coeff'] * unfixed_df['unfixed_weight_sum']

    total_penalty = unfixed_df['abandonment_penalty'].sum()
    total_affections = prepared_df['total_aff'].sum()

    return round(float(total_penalty / total_affections), 2) if total_affections > 0 else 0.0


# =================================================================================
# 4. Метрика: Доля критических багов
# =================================================================================
def calc_high_severity_ratio(df: pd.DataFrame, sev_col: str = 'vulnerability_severity_text') -> float:
    """Доля критически опасных уязвимостей (>= 7.0 или HIGH/CRITICAL)."""
    prepared_df = _prepare_db_data(df, sev_col=sev_col)
    if prepared_df.empty: return 0.0

    dangerous_count = ((prepared_df['unfixed_weight_sum'] >= 7.0) & prepared_df['is_unfixed_vuln']).sum()
    return round(float((dangerous_count / len(prepared_df)) * 100), 2)


# =================================================================================
# 5. Метрика: Плотность дефектов
# =================================================================================
def calc_defect_density(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    """Плотность дефектов (уязвимостей на один уникальный пакет)."""
    prepared_df = _prepare_db_data(df)
    if prepared_df.empty: return 0.0

    if pkg_col in prepared_df.columns and prepared_df[pkg_col].nunique() > 0:
        unique_packages = prepared_df[pkg_col].nunique()
    else:
        unique_packages = 1

    return round(float(len(prepared_df) / unique_packages), 2) if unique_packages > 0 else 0.0


# =================================================================================
# 6. Метрика: Индекс регрессии кода
# =================================================================================
def calc_regression_rate(df: pd.DataFrame) -> float:
    """Индекс регрессии кода (Bug Bounce Rate)."""
    prepared_df = _prepare_db_data(df)
    if prepared_df.empty: return 0.0
    return round(float((prepared_df['has_regression'].sum() / len(prepared_df)) * 100), 2)


def normalize(values: list[float], total_pr: float = 1) -> list[float]:
    mx = max(values, default=1)
    norm = mx * total_pr
    return [log2(1 + el / mx) if mx != 0 else 0 for el in values]