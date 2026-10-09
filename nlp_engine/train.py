import os
import sys

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

sys.stdout.reconfigure(encoding="utf-8")

df = pd.read_csv("data/raw/archive/phishing_email.csv")
df = df.dropna().drop_duplicates(subset="text_combined")
print("Rows after cleaning:", len(df))

X_train, X_test, y_train, y_test = train_test_split(
    df["text_combined"],
    df["label"],
    test_size=0.2,
    random_state=42,
    stratify=df["label"],
)

vectorizer = TfidfVectorizer(
    max_features=50000,
    ngram_range=(1, 2),
    stop_words="english",
    sublinear_tf=True,
    min_df=3,
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

pred = model.predict(X_test_vec)

print("\nAccuracy :", round(accuracy_score(y_test, pred), 4))
print("Precision:", round(precision_score(y_test, pred), 4))
print("Recall   :", round(recall_score(y_test, pred), 4))
print("F1-score :", round(f1_score(y_test, pred), 4))
print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
print(confusion_matrix(y_test, pred))

names = vectorizer.get_feature_names_out()
top = model.coef_[0].argsort()[-15:][::-1]
print("\nTop words for label 1:", [names[i] for i in top])

os.makedirs("nlp_engine/models", exist_ok=True)
joblib.dump(
    {"vectorizer": vectorizer, "model": model},
    "nlp_engine/models/phishing_model.joblib",
)
print("\nSaved model to nlp_engine/models/phishing_model.joblib")