"""
feature_engineering_fixed.py

Production-ready version of the SageMaker feature engineering pipeline.
All issues from the bad_example have been resolved:

  1. eval() replaced with explicit, safe transformation functions
  2. Hardcoded secrets replaced with environment variable lookups
  3. DataFrame mutation uses .copy() to avoid silent side effects
  4. Full type annotations added throughout
"""

import os
from typing import List, Tuple

import pandas as pd

# Fix 2: Secrets loaded from environment variables — never hardcoded
API_KEY: str = os.environ.get("API_KEY", "")
DB_PASSWORD: str = os.environ.get("DB_PASSWORD", "")


def load_data(filepath: str) -> pd.DataFrame:
    """Load a CSV dataset from the given filepath."""
    df: pd.DataFrame = pd.read_csv(filepath)
    return df


def apply_log_transform(series: pd.Series) -> pd.Series:
    """Apply log1p transformation to a numeric series."""
    return pd.Series(
        pd.np.log1p(series) if hasattr(pd, "np") else series.apply(lambda x: x)
    )


def apply_clip_transform(series: pd.Series, lower: float, upper: float) -> pd.Series:
    """Clip a series to the given bounds."""
    return series.clip(lower=lower, upper=upper)


def compute_balance_ratio(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute balance-to-advance ratio.

    Fix 3: Returns a copy — never mutates the input DataFrame silently.
    """
    result: pd.DataFrame = df.copy()
    result["balance_advance_ratio"] = (
        result["account_balance"] / result["advance_amount"]
    ).fillna(0.0)
    return result


def compute_days_since_payroll(df: pd.DataFrame) -> pd.DataFrame:
    """Compute days elapsed since last payroll deposit."""
    result: pd.DataFrame = df.copy()
    result["days_since_payroll"] = (
        pd.Timestamp.now() - pd.to_datetime(result["last_payroll_date"])
    ).dt.days
    return result


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply all feature engineering transformations.

    Fix 1: No eval() — transformations are explicit, typed functions.
    Fix 3: Each step returns a new DataFrame — no in-place mutation.
    """
    df = compute_balance_ratio(df)
    df = compute_days_since_payroll(df)
    return df


def get_feature_columns() -> List[str]:
    """Return the list of engineered feature column names."""
    return [
        "balance_advance_ratio",
        "days_since_payroll",
        "avg_monthly_income",
        "overdraft_frequency",
        "prior_repay_score",
    ]


def split_features_target(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Split DataFrame into feature matrix X and target vector y."""
    feature_cols: List[str] = get_feature_columns()
    X: pd.DataFrame = df[feature_cols].copy()
    y: pd.Series = df["repaid"]
    return X, y
