import pandas as pd
import numpy as np

def calc_abandonment_risk_score(prepared_df: pd.DataFrame) -> float:
    """
    Вычисляет интегральный риск заброшенности кодовой базы (Aging Risk Matrix).
    Штрафует проект на основе веса открытых уязвимостей и длительности отсутствия патча
    по временным интервалам: до полугода, до года, до двух лет и более двух лет.
    """
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


def calc_staleness_index(prepared_df: pd.DataFrame) -> float:
    """
    Вычисляет индекс протухания зависимостей экосистемы.
    Возвращает процентный показатель активных уязвимостей, которые остаются 
    неисправными в кодовой базе дольше двух лет (730 дней).
    """
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    if unfixed_df.empty: return 0.0

    stale_count = (unfixed_df['age'] > 730).sum()
    return round(float((stale_count / len(prepared_df)) * 100), 2)


def calc_avg_unfixed_life(prepared_df: pd.DataFrame) -> float:
    """
    Вычисляет среднее время жизни (MTTR в днях) незакрытых дефектов безопасности.
    Показывает среднюю длительность нахождения активных уязвимостей в системе без исправлений.
    """
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    ages = unfixed_df['age'].dropna()
    ages = ages[ages >= 0]
    return round(float(ages.mean()), 1) if not ages.empty else 0.0


def calc_high_severity_ratio(prepared_df: pd.DataFrame, sev_col: str = 'severity') -> float:
    """
    Вычисляет долю критически опасных уязвимостей в общей массе рисков экосистемы.
    Определяет процент дефектов с уровнем критичности >= 7.0 (категории HIGH и CRITICAL) 
    на основе приоритетной проверки глобальных и локальных метрик.
    """
    if prepared_df.empty: return 0.0

    def is_dangerous_cve(row) -> bool:
        global_sev = row.get(sev_col)
        if global_sev is not None and not (isinstance(global_sev, float) and np.isnan(global_sev)):
            try:
                if float(global_sev) >= 7.0: return True
            except ValueError:
                pass
            if any(k in str(global_sev).upper() for k in ['HIGH', 'CRITICAL']): return True

        return row.get('unfixed_weight_sum', 0.0) >= 7.0

    dangerous_count = prepared_df.apply(is_dangerous_cve, axis=1).sum()
    return round(float((dangerous_count / len(prepared_df)) * 100), 2)


def calc_defect_density(prepared_df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    """
    Вычисляет плотность дефектов безопасности (Defect Density).
    Возвращает среднее количество зарегистрированных уязвимостей, приходящихся 
    на один уникальный программный пакет, извлеченный из метаданных.
    """
    if prepared_df.empty: return 0.0

    if pkg_col in prepared_df.columns and prepared_df[pkg_col].nunique() > 0:
        unique_packages = prepared_df[pkg_col].nunique()
    else:
        all_pkgs = set()
        for p_list in prepared_df.get('extracted_packages', pd.Series(dtype=object)).dropna():
            all_pkgs.update(p_list)
        unique_packages = len(all_pkgs)

    return round(float(len(prepared_df) / unique_packages), 2) if unique_packages > 0 else 0.0


def calc_regression_rate(prepared_df: pd.DataFrame) -> float:
    """
    Вычисляет индекс повторного появления уязвимостей (Bug Bounce Rate).
    Показывает процент дефектов, которые были исправлены мейнтейнерами в прошлых 
    релизах, но ошибочно вернулись в последующих версиях программного обеспечения.
    """
    if prepared_df.empty: return 0.0
    
    # Защита на случай, если колонка has_regression не была передана
    if 'has_regression' not in prepared_df.columns: return 0.0
        
    return round(float((prepared_df['has_regression'].sum() / len(prepared_df)) * 100), 2)
