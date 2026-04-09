"""
feature_engineering_ai.py

⚠️  WARNING: This file contains INTENTIONAL security vulnerabilities
and code quality issues for demonstration purposes.
DO NOT use this code in production.

Issues present:
  1. CRITICAL — eval() usage (Bandit B307)
  2. HIGH     — hardcoded secret (Bandit B105)
  3. MEDIUM   — silent in-place DataFrame mutation (logic bug)
  4. LOW      — missing type annotations (mypy strict)
"""

import pandas as pd
import numpy as np

# Issue 2: Hardcoded secret — Bandit B105 HIGH
API_KEY = "sk-prod-1234567890abcdef"
DB_PASSWORD = "super_secret_password_123"


def load_data(filepath):
    df = pd.read_csv(filepath)
    return df


def apply_transformation(df, transform_expr):
    # Issue 1: eval() — Bandit B307 CRITICAL
    # Executes arbitrary Python from a string — remote code execution risk
    result = eval(transform_expr)
    return result


def compute_balance_ratio(df):
    # Issue 3: Silent in-place DataFrame mutation
    # Modifies the original DataFrame without warning — produces wrong results
    # when the caller expects the original to be unchanged
    df["balance_advance_ratio"] = df["account_balance"] / df["advance_amount"]
    df["balance_advance_ratio"] = df["balance_advance_ratio"].fillna(0)
    return df


def compute_days_since_payroll(df):
    df["days_since_payroll"] = (
        pd.Timestamp.now() - pd.to_datetime(df["last_payroll_date"])
    ).dt.days
    return df


def engineer_features(df, extra_transform=None):
    df = compute_balance_ratio(df)
    df = compute_days_since_payroll(df)

    if extra_transform:
        # Passes user-controlled input directly to eval()
        df = apply_transformation(df, extra_transform)

    return df


def get_feature_columns():
    return [
        "balance_advance_ratio",
        "days_since_payroll",
        "avg_monthly_income",
        "overdraft_frequency",
        "prior_repay_score",
    ]


def split_features_target(df):
    feature_cols = get_feature_columns()
    X = df[feature_cols]
    y = df["repaid"]
    return X, y
