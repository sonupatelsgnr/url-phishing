import os
import pickle
import pandas as pd
from tqdm import tqdm

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split

from feature_extractor import extract_features

print("=" * 60)
print("       PHISHING URL DETECTION MODEL TRAINING ")
print("=" * 60)

# ---------------------------------------------------
# Load Dataset
# ---------------------------------------------------
print("\n[1/7] Loading dataset...")
df = pd.read_csv("dataset/phishing_site_urls.csv")
df.columns = df.columns.str.strip()

print("Dataset Loaded Successfully")
print(f"Total Rows: {len(df):,}")

# ---------------------------------------------------
# Prepare Labels
# ---------------------------------------------------
print("\n[2/7] Preparing labels...")
df["Label"] = df["Label"].str.lower()
df["Label"] = df["Label"].map({
    "good": 0,
    "bad": 1
})
df = df.dropna()

print(f"Legitimate (0): {df['Label'].value_counts().get(0, 0):,}")
print(f"Phishing (1):   {df['Label'].value_counts().get(1, 0):,}")

# ---------------------------------------------------
# Feature Extraction
# ---------------------------------------------------
print("\n[3/7] Extracting Features...")
X = []
for url in tqdm(df["URL"], desc="Extracting features"):
    X.append(extract_features(url))

y = df["Label"]

# ---------------------------------------------------
# Train Test Split
# ---------------------------------------------------
print("\n[4/7] Splitting Dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training Samples: {len(X_train):,}")
print(f"Testing Samples:  {len(X_test):,}")

# ---------------------------------------------------
# Train Random Forest
# ---------------------------------------------------
print("\n[5/7] Training Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=100,  # Highly optimal number of estimators for speed and accuracy
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)
print("Training Completed!")

# ---------------------------------------------------
# Evaluation
# ---------------------------------------------------
print("\n[6/7] Evaluating Model...")
pred = model.predict(X_test)
accuracy = accuracy_score(y_test, pred)

print("\n" + "=" * 40)
print(f"Accuracy: {accuracy * 100:.2f}%")
print("=" * 40)

print("\nClassification Report:\n")
print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))

print("Confusion Matrix:\n")
print(confusion_matrix(y_test, pred))

# ---------------------------------------------------
# Save Model
# ---------------------------------------------------
print("\n[7/7] Saving Model...")
os.makedirs("model", exist_ok=True)

with open("model/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model Saved to model/phishing_model.pkl")
print("\nTraining Finished Successfully!")