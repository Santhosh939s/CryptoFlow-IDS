import os
import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

def generate_calibrated_dataset(filename="dataset.csv", n_samples=10000):
    """
    Generates a calibrated side-channel dataset representing real-world benign
    web browsing vs malicious high-entropy exfiltration attacks.
    """
    print(f"Generating calibrated training dataset with {n_samples} flow samples...")
    data = []

    # 1. Benign Traffic (Label 0) - 50%
    for _ in range(n_samples // 2):
        traffic_type = random.random()
        if traffic_type < 0.6:
            # Standard TLS/HTTPS browsing (Entropy ~4.5 - 6.8, common ports 443/8443)
            entropy = random.uniform(4.5, 6.8)
            packet_size = random.choice([250, 520, 850, 1100, 1420, 1500])
            dst_port = random.choice([443, 443, 443, 8443])
        elif traffic_type < 0.85:
            # Plaintext HTTP, DNS, internal RPC (Entropy ~2.0 - 4.2)
            entropy = random.uniform(1.8, 4.2)
            packet_size = random.randint(64, 1200)
            dst_port = random.choice([80, 8080, 53, 22])
        else:
            # Short low-entropy keepalives and ACKs
            entropy = random.uniform(0.5, 3.5)
            packet_size = random.randint(64, 300)
            dst_port = random.choice([443, 80, 53])
        data.append([round(entropy, 4), packet_size, dst_port, 0])

    # 2. Malicious Exfiltration Traffic (Label 1) - 50%
    for _ in range(n_samples // 2):
        attack_type = random.random()
        if attack_type < 0.7:
            # High-entropy encrypted exfiltration chunks (Entropy ~7.4 - 7.99)
            entropy = random.uniform(7.45, 7.98)
            packet_size = random.choice([512, 1024, 1024, 1024, 1200, 1400])
            dst_port = random.choice([443, 443, 8443, 443])
        else:
            # Covert UDP/QUIC high-entropy botnet channel
            entropy = random.uniform(7.35, 7.95)
            packet_size = random.randint(800, 1400)
            dst_port = random.choice([443, 8443, 53])
        data.append([round(entropy, 4), packet_size, dst_port, 1])

    random.shuffle(data)
    df = pd.DataFrame(data, columns=['Entropy', 'PacketSize', 'DstPort', 'Label'])
    df.to_csv(filename, index=False)
    print(f"Dataset generated and saved to '{filename}'.")
    return df

def train():
    dataset_file = "dataset.csv"
    if os.path.exists(dataset_file):
        print(f"Loading existing {dataset_file}...")
        df = pd.read_csv(dataset_file)
    else:
        print(f"'{dataset_file}' not found. Auto-generating calibrated seed dataset...")
        df = generate_calibrated_dataset(dataset_file)

    X = df[['Entropy', 'PacketSize', 'DstPort']]
    y = df['Label']

    print("Splitting data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest AI (100 estimators)...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    accuracy = rf_model.score(X_test, y_test)
    print(f"\n--- Results ---")
    print(f"Accuracy on Test Set: {accuracy * 100:.2f}%")

    model_filename = "traffic_classifier.pkl"
    joblib.dump(rf_model, model_filename)
    print(f"[SUCCESS] Model successfully saved as '{model_filename}'!")

if __name__ == "__main__":
    train()
