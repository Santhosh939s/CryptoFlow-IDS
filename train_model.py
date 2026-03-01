import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# 1. Load the dataset
print("Loading dataset.csv...")
df = pd.read_csv("dataset.csv")

# 2. Separate Features (X) and Labels (y)
# These map directly to Algorithm 1 and 3 in your paper
X = df[['Entropy', 'PacketSize', 'DstPort']]
y = df['Label']

# 3. Split data: 80% for training, 20% for testing
print("Splitting data (80% Train, 20% Test)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train the Random Forest Model
print("Training the Random Forest AI (100 estimators)...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 5. Evaluate the Model's Accuracy
accuracy = rf_model.score(X_test, y_test)
print(f"\n--- Results ---")
print(f"Accuracy on Test Set: {accuracy * 100:.2f}%")

# 6. Save the trained model if it meets the paper's standard (> 95%)
if accuracy > 0.95:
    joblib.dump(rf_model, "traffic_classifier.pkl")
    print("Model is highly accurate! Saved as 'traffic_classifier.pkl'.")
else:
    print("Model accuracy is below 95%. Try checking your dataset.")
