import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")

df = pd.read_csv("data/raw/archive/phishing_email.csv")

print("Columns:", df.columns.tolist())
print("Rows:", len(df))

for col in df.columns:
    if df[col].nunique() <= 5:
        print(f"\nValues in '{col}':")
        print(df[col].value_counts())

print("\nFirst row:")
print(df.iloc[0].to_string()[:600])