import pandas as pd
import numpy as np

def calc_abandonment_risk_score(df: pd.DataFrame) -> float:
    """
    Вычисляет интегральный риск заброшенности кодовой базы (Aging Risk Matrix).
    """
    if df.empty: return 0.0
    
    def get_row_unfixed_weight(row) -> float:
        col_name = 'affected' if 'affected' in row else 'affected_ranges'
        affected_list = row.get(col_name)
        if not isinstance(affected_list, list) or len(affected_list) == 0:
            return 1.0 
            
        unfixed_weight_sum = 0.0
        for aff in affected_list:
            if not isinstance(aff, dict): continue
            
            all_events = []
            for r in aff.get('ranges', []):
                events = r.get('events', [])
                if isinstance(events, list): all_events.extend(events)
            
            is_fixed = False
            for e in all_events:
                if not isinstance(e, dict): continue
                if 'introduced' in e: is_fixed = False
                if 'fixed' in e: is_fixed = True
                
            if not is_fixed:
                local_sev = aff.get('database_specific', {}).get('severity')
                unfixed_weight_sum += 10.0 if local_sev == 'CRITICAL' else 1.0 
                
        return unfixed_weight_sum

    working_df = df.copy()
    working_df['unfixed_weight'] = working_df.apply(get_row_unfixed_weight, axis=1)
    working_df['age_days'] = working_df['age'] if 'age' in working_df.columns else 0.0
    
    unfixed_df = working_df[working_df['unfixed_weight'] > 0].copy()
    if unfixed_df.empty: return 0.0
    
    conditions = [
        (unfixed_df['age_days'] < 180),
        (unfixed_df['age_days'] >= 180) & (unfixed_df['age_days'] < 365),
        (unfixed_df['age_days'] >= 365) & (unfixed_df['age_days'] < 730),
        (unfixed_df['age_days'] >= 730)
    ]
    choices = [0.0, 1.0, 2.5, 5.0]
    unfixed_df['aging_coeff'] = np.select(conditions, choices, default=0.0)
    
    total_penalty = (unfixed_df['aging_coeff'] * unfixed_df['unfixed_weight']).sum()
    return round(float(total_penalty / len(df)), 2)


def calc_staleness_index(df: pd.DataFrame) -> float:
    """
    Вычисляет индекс протухания зависимостей экосистемы (>2 лет без фикса).
    """
    if df.empty: return 0.0
    
    def is_unfixed(affected_list) -> bool:
        if not isinstance(affected_list, list): return True
        for aff in affected_list:
            if not isinstance(aff, dict): continue
            all_events = []
            for r in aff.get('ranges', []):
                events = r.get('events', [])
                if isinstance(events, list): all_events.extend(events)
            is_fixed = False
            for e in all_events:
                if not isinstance(e, dict): continue
                if 'introduced' in e: is_fixed = False
                if 'fixed' in e: is_fixed = True
            if not is_fixed: return True 
        return False

    col = 'affected' if 'affected' in df.columns else 'affected_ranges'
    age_col = 'age' if 'age' in df.columns else 'age_days'
    
    if col in df.columns and age_col in df.columns:
        stale_mask = (df[age_col] > 730) & (df[col].apply(is_unfixed))
        return round(float((stale_mask.sum() / len(df)) * 100), 2)
    return 0.0


def calc_avg_unfixed_life(df: pd.DataFrame) -> float:
    """
    Вычисляет среднее время жизни (MTTR в днях) незакрытых дефектов безопасности.
    """
    if df.empty: return 0.0
    
    def is_unfixed(affected_list) -> bool:
        if not isinstance(affected_list, list): return True
        for aff in affected_list:
            if not isinstance(aff, dict): continue
            all_events = []
            for r in aff.get('ranges', []):
                events = r.get('events', [])
                if isinstance(events, list): all_events.extend(events)
            is_fixed = False
            for e in all_events:
                if not isinstance(e, dict): continue
                if 'introduced' in e: is_fixed = False
                if 'fixed' in e: is_fixed = True
            if not is_fixed: return True
        return False

    col = 'affected' if 'affected' in df.columns else 'affected_ranges'
    age_col = 'age' if 'age' in df.columns else 'age_days'
    
    if col in df.columns and age_col in df.columns:
        unfixed_mask = df[col].apply(is_unfixed)
        ages = df.loc[unfixed_mask, age_col].dropna()
        ages = ages[ages >= 0]
        return round(float(ages.mean()), 1) if not ages.empty else 0.0
    return 0.0


def calc_high_severity_ratio(df: pd.DataFrame, sev_col: str = 'severity') -> float:
    """
    Вычисляет долю критически опасных уязвимостей (>= HIGH / 7.0) в общей массе.
    """
    if df.empty: return 0.0

    def is_dangerous_cve(row) -> bool:
        global_sev = row.get(sev_col)
        if global_sev is not None and not (isinstance(global_sev, float) and np.isnan(global_sev)):
            try:
                if float(global_sev) >= 7.0: return True
            except ValueError: pass
            if any(k in str(global_sev).upper() for k in ['HIGH', 'CRITICAL']): return True

        col_name = 'affected' if 'affected' in row.index else 'affected_ranges'
        affected_list = row.get(col_name)
        if isinstance(affected_list, list):
            for aff in affected_list:
                if not isinstance(aff, dict): continue
                local_sev = aff.get('database_specific', {}).get('severity')
                if local_sev:
                    try:
                        if float(local_sev) >= 7.0: return True
                    except ValueError: pass
                    if any(k in str(local_sev).upper() for k in ['HIGH', 'CRITICAL']): return True
        return False

    dangerous_count = df.apply(is_dangerous_cve, axis=1).sum()
    return round(float((dangerous_count / len(df)) * 100), 2)


def calc_defect_density(df: pd.DataFrame, pkg_col: str = 'package_name') -> float:
    """
    Вычисляет плотность дефектов безопасности (Defect Density).
    """
    if df.empty: return 0.0
    if pkg_col in df.columns and df[pkg_col].nunique() > 0:
        unique_packages = df[pkg_col].nunique()
    else:
        all_pkgs = set()
        col = 'affected' if 'affected' in df.columns else 'affected_ranges'
        if col in df.columns:
            for affected_list in df[col].dropna():
                if isinstance(affected_list, list):
                    for aff in affected_list:
                        if not isinstance(aff, dict): continue
                        pkg_name = aff.get('package', {}).get('name')
                        if pkg_name: all_pkgs.add(pkg_name)
        unique_packages = len(all_pkgs)
    return round(float(len(df) / unique_packages), 2) if unique_packages > 0 else 0.0


def calc_regression_rate(df: pd.DataFrame) -> float:
    """
    Вычисляет индекс повторного появления уязвимостей (Bug Bounce Rate).
    """
    if df.empty: return 0.0
    
    def check_regression(affected_list) -> bool:
        if not isinstance(affected_list, list): return False
        for aff in affected_list:
            if not isinstance(aff, dict): continue
            intro_count = 0
            for r in aff.get('ranges', []):
                for e in r.get('events', []):
                    if isinstance(e, dict) and 'introduced' in e: 
                        intro_count += 1
            if intro_count > 1: return True
        return False

    col = 'affected' if 'affected' in df.columns else 'affected_ranges'
    if col in df.columns:
        regression_count = df[col].apply(check_regression).sum()
        return round(float((regression_count / len(df)) * 100), 2)
    return 0.0
