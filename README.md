🛡️ Zero-Day Malware Detection SOC (Command Center)
A distributed, AI-powered Network Intrusion Detection System (NIDS) designed for real-time cybersecurity monitoring. This system leverages advanced Machine Learning to identify and neutralize zero-day threats, including DDoS floods, web exploits, and brute force attacks, before they can compromise critical infrastructure.

🔬 Theoretical Foundation
1. Zero-Day Malware Detection
Traditional antivirus software relies on "signatures" of known threats. This SOC employs anomaly-based detection, which allows it to identify "Zero-Day" attacks—malware that has never been seen before. By learning the mathematical baseline of "Safe Traffic," the system can flag any deviation as a potential exploit.

2. Random Forest Intelligence
The "brain" of this project is a Random Forest Classifier (nids_random_forest.pkl).

Ensemble Learning: Instead of relying on one decision tree, it uses hundreds of trees to vote on the traffic type, significantly reducing false positives.

Feature Importance: The model specifically monitors 15+ network features, such as Flow Bytes/s, Packet Length Variance, and RST Flag Counts.

Batched Inference: For production efficiency, the backend performs batched AI predictions. It processes up to 60 packets in a single mathematical operation, ensuring sub-millisecond response times even under heavy load.

3. Distributed Architecture
The system is built on a decoupled 4-layer architecture:

Sensor Layer (agent.py): Local scripts that parse raw network packets into numerical telemetry.

Persistence Layer (Supabase): A cloud-based PostgreSQL database that acts as a central nervous system for all sensor nodes.

Intelligence Layer (manager_app.py): A Flask-based server that runs the AI models and manages automated threat response.

Presentation Layer (index.html): A razor-sharp dashboard providing real-time visual forensics.

📂 Repository Components
🧠 Machine Learning Artifacts
nids_random_forest.pkl: The trained AI model.

nids_scaler.pkl: Normalizes live data to match training parameters.

nids_features.pkl: A serialized list of the 15 required network metrics.

attack_classes.pkl: Mapping for human-readable threat labels (e.g., "Web Attack").

⚙️ Central Management (Backend)
manager_app.py: The core engine. It manages data flow from Supabase, triggers the AI, handles system settings, and dispatches SMTP alerts.

requirements.txt: List of dependencies including flask, scikit-learn, and supabase.

Procfile: Essential for production deployment on Render.

💻 User Interface (Frontend)
templates/index.html: A responsive, sharp enterprise dashboard.

Live SOC: Real-time visualization of network volume and AI confidence.

Forensics: A deep-dive searchable table of historical traffic.

Portfolio-Style Mobile View: Automatically converts into a sleek bottom navigation bar for mobile access.

📡 Sensors & Simulation
agent.py: The local monitoring script that pushes traffic telemetry to the cloud.

attack_simulator.py: A diagnostic tool used to simulate DDoS and Brute Force patterns to verify system response.

Malware_Detection.ipynb: The original research notebook documenting the model training and feature selection process.

🚀 Quick Start
1. Local Setup
Clone the repository.

Install requirements: pip install -r requirements.txt.

Configure your .env file with your SUPABASE_URL, SUPABASE_KEY, and email credentials.

Run the SOC: python manager_app.py.

2. Connect Sensors
Start the local monitor: python agent.py.

(Optional) Run python attack_simulator.py to test the AI's detection capabilities.

🛠️ Technology Stack
Languages: Python 3.12+, JavaScript (Plotly.js)

Frameworks: Flask (Backend), CSS Media Queries (Responsive Mobile UI)

AI/ML: Scikit-Learn (Random Forest), Pandas, NumPy

Cloud Database: Supabase (PostgreSQL)

Deployment: Render

Lead Developer: Shubham Gajanan Tade
Research Area: AI-Driven Cybersecurity & Autonomous Threat Mitigation
