# 🛡️ Zero-Day Malware Detection SOC (Command Center)
A high-performance, distributed Network Intrusion Detection System (NIDS) and Security Operations Center (SOC). This project utilizes a Random Forest Machine Learning architecture to identify and neutralize zero-day threats—attacks that have no known signature—by analyzing real-time network telemetry.

# 🔬 Theoretical Foundation
1. Zero-Day Anomaly Detection :
Traditional security systems rely on signature matching (detecting known "fingerprints" of malware). This system employs Anomaly-Based Detection. By establishing a mathematical baseline of "Safe Traffic," the AI can identify novel exploits the moment they deviate from normal behavior, effectively stopping "Zero-Day" attacks before they are documented by security vendors.

2. Random Forest Intelligence :
The detection engine utilizes a Random Forest Classifier (nids_random_forest.pkl).

- Ensemble Learning: Instead of a single decision path, the model utilizes an ensemble of hundreds of decision trees to "vote" on traffic classification, which drastically reduces false positives.

- Feature Importance: The model specifically monitors 15+ critical network features, including Flow Bytes/s, Packet Length Variance, and RST Flag Counts, to distinguish between legitimate spikes and malicious floods.

- Batched Inference: The backend utilizes ultra-optimized batched processing. It evaluates up to 60 telemetry packets in a single vector operation, ensuring the system remains responsive even during high-volume DDoS attacks.
