# 🛡️ Zero-Day Malware Detection SOC (Command Center)
A high-performance, distributed Network Intrusion Detection System (NIDS) and Security Operations Center (SOC). This project utilizes a Random Forest Machine Learning architecture to identify and neutralize zero-day threats—attacks that have no known signature—by analyzing real-time network telemetry.

# 🔬 Theoretical Foundation
## Zero-Day Anomaly Detection :
Traditional security systems rely on signature matching (detecting known "fingerprints" of malware). This system employs Anomaly-Based Detection. By establishing a mathematical baseline of "Safe Traffic," the AI can identify novel exploits the moment they deviate from normal behavior, effectively stopping "Zero-Day" attacks before they are documented by security vendors.

## Random Forest Intelligence :
The detection engine utilizes a Random Forest Classifier (nids_random_forest.pkl).

- Ensemble Learning: Instead of a single decision path, the model utilizes an ensemble of hundreds of decision trees to "vote" on traffic classification, which drastically reduces false positives.

- Feature Importance: The model specifically monitors 15+ critical network features, including Flow Bytes/s, Packet Length Variance, and RST Flag Counts, to distinguish between legitimate spikes and malicious floods.

- Batched Inference: The backend utilizes ultra-optimized batched processing. It evaluates up to 60 telemetry packets in a single vector operation, ensuring the system remains responsive even during high-volume DDoS attacks.

## Distributed SOC Architecture
The system is built on a decoupled, four-layer architecture for maximum scalability:

- Sensor Layer: Local agent.py scripts capture raw socket data and parse it into numerical telemetry.

- Persistence Layer: Telemetry is pushed to a Supabase (PostgreSQL) cloud cluster, acting as a centralized brain for multiple sensor nodes.

- Intelligence Layer: A Flask backend runs the AI engine and manages automated alert logic.

- Presentation Layer: A sharp, responsive dashboard built with Plotly.js for real-time forensic visualization.
# 📂 Repository Breakdown
## 🧠 AI & Machine Learning Artifacts

- ```nids_random_forest.pkl```: The core trained model.

- ``nids_scaler.pkl``: Normalizes live data to match the model’s training distribution.

- ``nids_features.pkl``: Serialized list of required mathematical network features.

- ``attack_classes.pkl`` / label_encoder.pkl: Mappings to translate AI predictions into human-readable threat labels (e.g., "DDoS", "Web Attack").
