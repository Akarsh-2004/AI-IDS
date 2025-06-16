# 🛡️ AI-IDS — AI-Powered Intrusion Detection System (LINUX FRIENDLY)

**AI-IDS** is a real-time intrusion detection system designed for Linux environments. It leverages machine learning to analyze syscalls and detect potential malicious behavior. The system is split into a FastAPI backend for detection and control, and a modern React-based frontend for monitoring and visualization.

> 💡 **Want a plug-and-play version?**  
> Run [`backend/monitor_syscalls.py`](backend/monitor_syscalls.py) after installing dependencies — you're good to go!



![Screenshot 2025-06-16 085239](https://github.com/user-attachments/assets/84a076c2-b218-4e88-90f2-cf7e7c42fc04)


![Screenshot 2025-06-15 233408](https://github.com/user-attachments/assets/32f1e889-9aab-4e5a-ac48-a939e2a998b1)


![Screenshot 2025-06-16 092050](https://github.com/user-attachments/assets/814276c7-26bb-4160-a1ae-2b96acc3ca9a)


![Screenshot 2025-06-16 092106](https://github.com/user-attachments/assets/f5f63179-b55b-4fa1-beb9-7a35805fb045)

![Screenshot 2025-06-16 092136](https://github.com/user-attachments/assets/c01b1c7b-3fec-468a-b49e-aa1eb18966f4)




## 🏗️ Project Structure

AI-IDS/
├── backend/ # FastAPI backend for real-time detection
│ ├── main.py
│ ├── my_project_ids.py
│ ├── common.py
│ ├── models/
│ └── alerts.log
├── frontend/ # React frontend for dashboard
│ ├── src/
│ ├── public/
│ └── .env
├── README.md # This file
└── .gitignore


## ⚙️ Features

### ✅ Backend (FastAPI)
- Real-time syscall monitoring via `audit.log`
- ML-based threat detection (Random Forest or LSTM)
- WebSocket-based live alert broadcast
- RESTful APIs for starting/stopping detection, fetching stats
- Configurable alert thresholds, whitelisting, cooldowns

📡 API Endpoints
Method	Endpoint	Description
GET	/health	API health check
POST	/control/start	Start real-time syscall monitor
POST	/control/stop	Stop syscall monitor
GET	/stats	Get real-time system stats
GET	/model/info	Show current model metadata
GET	/alerts/latest	Get latest structured alerts
POST	/alerts/test	Trigger a fake test alert
GET	/config	View runtime IDS configuration
POST	/config	Update configuration dynamically
WS	/ws/alerts	WebSocket stream of live alerts

📘 Open http://localhost:8000/docs for Swagger UI.


### ⚛️ Frontend (React)
- Dashboard to display live alerts and system status
- Control panel to start/stop monitoring
- Stats view and log viewer
- Dynamic API config via `.env`

---

## 🚀 Getting Started

### 🔧 Prerequisites
- Linux (for backend, uses `auditd`)
- Node.js + npm (for frontend)
- Python 3.8+
- Git

---

## 🔥 Backend Setup

### 1. Setup (Kali/Linux)
```bash
cd backend/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
2. Run the API
bash
Copy code
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
🎨 Frontend Setup
1. Setup (Windows/Host)
bash
Copy code
cd frontend/
npm install
2. Configure API Endpoint
In frontend/.env:

ini
Copy code
VITE_API_URL=http://<Kali_IP>:8000
Example:

ini
Copy code
VITE_API_URL=http://ipOfYourLinux
3. Run the React app
bash
Copy code
npm run dev
Then open http://localhost:5173

📡 API Endpoints
Method	Endpoint	Description
GET	/health	Server health check
POST	/control/start	Start monitoring
POST	/control/stop	Stop monitoring
GET	/stats	Get system stats
GET	/model/info	Model metadata
GET	/alerts/latest	Latest alert entries
WS	/ws/alerts	Live alert stream (WebSocket)

📘 Full Swagger UI: http://<IP>:8000/docs

🧠 Machine Learning (Backend)
Model: RandomForestClassifier

Input: TF-IDF vectorized syscall history

Training dataset: ADFA-LD syscall traces

Thresholds: Adjustable for confidence and suppression

Feature extraction: parse_enhanced_syscall_info()

🔍 Observed Behaviors & Engineering Insights
✔️ Optimized syscall ingestion via tail -F and subprocess.PIPE
✔️ Background monitoring via Python threads
✔️ WebSocket pushes decoupled from main loop for non-blocking updates
✔️ Alerts are structured, logged, and passed via queue
✔️ Frontend auto-refreshes stats and handles alert visibility
✔️ Cross-platform dev: Backend in Kali VM, Frontend on Windows
✔️ API 404 bugs resolved by matching route patterns
✔️ Used .env and dynamic base URLs for clean frontend integration

📁 Sample Alert Output
json
Copy code
{
  "id": 101,
  "severity": "MEDIUM",
  "details": {
    "pid": 3784,
    "syscall_id": 59,
    "process_name": "bash"
  },
  "confidence": 0.82,
  "triggered_by": "Model_Prediction",
  "type": "alert"
}
📜 License
AKARSH SAKLANI

🙋 Support
For issues, suggestions, or questions, open an issue on GitHub or contact:
📧 akarshsaklani222@gmail.com





