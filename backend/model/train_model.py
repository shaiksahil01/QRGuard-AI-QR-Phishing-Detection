import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from utils.feature_extractor import extract_features

# Load dataset
df = pd.read_csv(os.path.join(os.path.dirname(__file__), '..', 'data', 'dataset.csv'))
print(f"Loaded {len(df)} URLs")

# Extract features
print("Extracting features...")
features = df['url'].apply(extract_features).apply(pd.Series)
X = features
y = df['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Save model
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
with open(model_path, 'wb') as f:
    pickle.dump(model, f)
print(f"\nModel saved to {model_path}")