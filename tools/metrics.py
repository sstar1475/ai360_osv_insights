import pandas as pd
import numpy as np

def prepare_db_data(df: pd.DataFrame, ref_date: str, sev_col: str = 'severity') -> pd.DataFrame:
    """
    Выполняет сквозную предобработку сырого датасета из PostgreSQL (jsonb).
    Определяет статус уязвимости строго по последнему хронологическому событию.
    """
    if df.empty:
        return pd.DataFrame()

    working_df = df.copy()

    def extract_weight(sev_val) -> float:
        if sev_val is None or (isinstance(sev_val, float) and np.isnan(sev_val)):
            return 1.0

        if isinstance(sev_val, list):
            for item in sev_val:
                if isinstance(item, dict) and 'score' in item:
                    score_str = str(item['score']).strip()
                    if '/' not in score_str:
                        try:
                            return float(score_str)
                        except ValueError:
                            pass
            return 1.0

        sev_str = str(sev_val).strip().upper()
        try:
            numeric = float(sev_str)
            if numeric > 0: return numeric
        except ValueError:
            pass

        weights = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MODERATE': 4.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        for k, v in weights.items():
            if k in sev_str:
                return v
        return 1.0

    working_df['global_weight'] = working_df.get(sev_col, pd.Series([1.0] * len(working_df))).apply(extract_weight)

    def parse_row(row) -> pd.Series:
        col_name = 'affected' if 'affected' in row.index else 'affected_ranges'
        affected_list = row.get(col_name)
        global_w = row.get('global_weight', 1.0)

        if not isinstance(affected_list, list) or len(affected_list) == 0:
            return pd.Series({
                'total_aff': 1, 'unfixed_aff': 1, 'is_unfixed_vuln': True,
                'has_regression': False, 'unfixed_weight_sum': global_w, 'extracted_packages': []
            })

        total_aff = len(affected_list)
        unfixed_aff = 0
        has_regression = False
        unfixed_weight_sum = 0.0
        extracted_packages = []

        for aff in affected_list:
            if not isinstance(aff, dict):
                continue

            # Извлекаем имя пакета для корректного подсчета плотности дефектов
            pkg_name = aff.get('package', {}).get('name')
            if pkg_name:
                extracted_packages.append(pkg_name)

            # Собираем все события в единый хронологический трек
            all_events = []
            ranges = aff.get('ranges', [])
            for r in ranges:
                events = r.get('events', [])
                if isinstance(events, list):
                    all_events.extend(events)

            is_fixed = False
            intro_count = 0

            # Анализируем реальный порядок событий
            for e in all_events:
                if not isinstance(e, dict): continue
                if 'introduced' in e:
                    intro_count += 1
                    is_fixed = False  # Новое появление сбрасывает статус фикса
                if 'fixed' in e:
                    is_fixed = True

            if not is_fixed:
                unfixed_aff += 1
                local_sev = aff.get('database_specific', {}).get('severity')
                branch_weight = extract_weight(local_sev) if local_sev else global_w
                unfixed_weight_sum += branch_weight

            if intro_count > 1:
                has_regression = True

        return pd.Series({
            'total_aff': total_aff,
            'unfixed_aff': unfixed_aff,
            'is_unfixed_vuln': unfixed_aff > 0,
            'has_regression': has_regression,
            'unfixed_weight_sum': unfixed_weight_sum,
            'extracted_packages': extracted_packages
        })

    stats = working_df.apply(parse_row, axis=1)
    working_df = pd.concat([working_df, stats], axis=1)

    if 'published' in working_df.columns:
        published = pd.to_datetime(working_df['published'], errors='coerce', utc=True)
        current = pd.to_datetime(ref_date, utc=True)
        working_df['age'] = (current - published).dt.days.fillna(0).clip(lower=0)
    else:
        working_df['age'] = 0.0

    return working_df


# =====================================================================
# ВЫЧИСЛИТЕЛЬНЫЕ МОДУЛИ (Принимают уже ГОТОВЫЙ prepared_df)
# =====================================================================

def calc_abandonment_risk_score(prepared_df: pd.DataFrame) -> float:
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
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    if unfixed_df.empty: return 0.0

    stale_count = (unfixed_df['age'] > 730).sum()
    return round(float((stale_count / len(prepared_df)) * 100), 2)


def calc_avg_unfixed_life(prepared_df: pd.DataFrame) -> float:
    if prepared_df.empty: return 0.0
    unfixed_df = prepared_df[prepared_df['is_unfixed_vuln']]
    ages = unfixed_df['age'].dropna()
    ages = ages[ages >= 0]
    return round(float(ages.mean()), 1) if not ages.empty else 0.0


def calc_high_severity_ratio(prepared_df: pd.DataFrame, sev_col: str = 'severity') -> float:
    """Вычисляет долю критически опасных уязвимостей (>= 7.0 или HIGH/CRITICAL)"""
    if prepared_df.empty: return 0.0

    def is_dangerous_cve(row) -> bool:
        global_sev = row.get(sev_col)
        if global_sev is not None and not (isinstance(global_sev, float) and np.isnan(global_sev)):
            try:
                if float(global_sev) >= 7.0: return True
            except ValueError:
                pass
            if any(k in str(global_sev).upper() for k in ['HIGH', 'CRITICAL']): return True

        # Если глобального статуса нет, проверяем накопленный вес открытых веток
        return row.get('unfixed_weight_sum', 0.0) >= 7.0

    dangerous_count = prepared_df.apply(is_dangerous_cve, axis=1).sum()
    return round(float((dangerous_count / len(prepared_df)) * 100), 2)


def calc_defect_density(prepared_df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    if prepared_df.empty: return 0.0

    # Пытаемся взять имена пакетов из плоской колонки, либо извлеченные из jsonb структуры
    if pkg_col in prepared_df.columns and prepared_df[pkg_col].nunique() > 0:
        unique_packages = prepared_df[pkg_col].nunique()
    else:
        # Извлекаем уникальные имена из вложенных списков
        all_pkgs = set()
        for p_list in prepared_df['extracted_packages'].dropna():
            all_pkgs.update(p_list)
        unique_packages = len(all_pkgs)

    return round(float(len(prepared_df) / unique_packages), 2) if unique_packages > 0 else 0.0


def calc_regression_rate(prepared_df: pd.DataFrame) -> float:
    if prepared_df.empty: return 0.0
    return round(float((prepared_df['has_regression'].sum() / len(prepared_df)) * 100), 2)
