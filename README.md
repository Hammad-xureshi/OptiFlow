Here is a professional, comprehensive, and clean GitHub README based on your project summary.

***

# 🛡️ CyberWall: AI-Powered Security Monitoring System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green?logo=flask)
![MySQL](https://img.shields.io/badge/Database-MySQL-orange?logo=mysql)
![scikit-learn](https://img.shields.io/badge/ML-Isolation%20Forest-red?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## 📖 Project Overview

CyberWall is an advanced, full-stack cyber-security monitoring solution built with Flask. It is designed to visualize, detect, and mitigate security threats in real-time. 

Beyond standard logging, this system utilizes **Machine Learning (Isolation Forest)** to analyze user behavior patterns, detect anomalies, and generate risk scores. Coupled with a robust IP blacklisting system and detailed device fingerprinting, CyberWall provides a comprehensive dashboard for monitoring network activity and user actions.

---

✨ Key Features

🔐 Core Security
*   Secure Authentication: Session-based login system protected by `bcrypt` password hashing.
*   IP Blacklisting:
    *   **Manual:** Admin can manually ban suspicious IPs.
    *   **Automated:** System auto-blacklists IPs after repeated failed login attempts.
*   Emergency Access: Dedicated endpoint for emergency IP unblocking.

🕵️‍♂️ Advanced Monitoring 
*   
    *   Operating System (Windows, Linux, macOS, etc.)
    *   Browser (Chrome, Firefox, Safari, etc.)
    *   Device Type (Desktop, Mobile, Tablet)
*   **Granular Logging:** Tracks dashboard visits, specific user actions, and suspicious events.

🤖 AI & Anomaly Detection
*   **Isolation Forest Algorithm:** Uses unsupervised machine learning to detect outliers in log data.
*   **Risk Scoring:** Assigns a risk score to activities and categorizes them as **High**, **Medium**, or **Low** risk.
*   **Intelligent Alerting:** Automatically populates an `Alerts` table when the ML model detects deviations from normal behavior.

 📊 Real-Time Dashboard
*   Interactive Visualization:** Powered by Chart.js to display:
    *   Browser & OS Statistics.
    *   IP Address Distribution.
    *   Device Type breakdown.
*   Management Panels:
    *   Blacklist Manager: View and remove banned IPs.
    *   Login Monitor: Track recent failed attempts.
    *   Log Explorer: Detailed view of all recorded events with device info.

---

🛠️ Technologies Used

| Category | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python (Flask) | Core web framework and routing. |
| **Database** | MySQL | Storage for logs, users, alerts, and blacklists. |
| **Machine Learning** | Scikit-Learn | Isolation Forest implementation for anomaly detection. |
| **Security** | Bcrypt | Secure password hashing. |
| **Frontend** | HTML5, CSS3, JS | Responsive UI with animated dashboard components. |
| **Visualization** | Chart.js | Rendering real-time security charts. |
| **Data Processing** | Pandas / NumPy | Data manipulation for the ML pipeline. |

---

⚙️ How It Works Internally

1.  Data Inception:** Every request made to the application is intercepted. The system captures the IP address, timestamp, and parses the User-Agent header to extract device metadata.
2.  Validation:** The IP is checked against the MySQL `Blacklist` table. If listed, the request is immediately blocked.
3.  Authentication:** Login attempts are tracked. If a user fails to log in $X$ times (configurable), the Auto-Blacklist logic triggers.
4.                                             ML Analysis:
    *   The system fetches historical log data.
    *   Features (Time of day, Action frequency, IP variance) are engineered.
    *   The **Isolation Forest** model fits the data and predicts anomalies (outliers).
    *   Anomalies are assigned a severity score and stored in the `Alerts` database.
5.  Visualization:** The frontend polls the backend for the latest stats, rendering animated charts and tables for the administrator.

---

🚀 Installation & Setup

Prerequisites
*   Python 3.8+
*   MySQL Server

1. Clone the Repository
```bash
git clone https://github.com/yourusername/cyberwall.git
cd cyberwall
```

2. Install Dependencies
Create a virtual environment and install the required packages:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install flask pymysql flask-bcrypt scikit-learn pandas user-agents
```

3. Database Configuration
Login to your MySQL server and create the database and required tables using the SQL below:

```sql
CREATE DATABASE cyber_security_db;
USE cyber_security_db;

-- Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'admin'
);

-- Logs Table (Data source for ML)
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    username VARCHAR(50),
    action VARCHAR(255),
    ip_address VARCHAR(45),
    device_info TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Blacklist Table
CREATE TABLE blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE,
    reason VARCHAR(255),
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Login Attempts (For throttling)
CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Alerts (AI Generated)
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50),
    risk_level VARCHAR(20),
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

4. Configure Application
Open the main Python file (e.g., `app.py`) and update the MySQL connection details:

```python
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'your_password'
app.config['MYSQL_DB'] = 'cyber_security_db'
```

5. Create an Admin User
Since the app uses hashed passwords, you cannot simply insert plain text into the DB. You can use a small script or the registration route (if enabled) to create your first user.

---
🖥️ How to Run

1.  Ensure your MySQL server is running.
2.  Start the Flask application:

```bash
python app.py
```
3.  Open your web browser and navigate to:
    `http://127.0.0.1:5000`
---

📝 Conclusion

CyberWall serves as a robust foundation for a SIEM (Security Information and Event Management) system. By combining traditional rule-based security (blacklists, session management) with modern Machine Learning techniques (anomaly detection), it provides a layered defense mechanism suitable for educational purposes or lightweight production monitoring.

---

*Developed by Hammad Naeem.*
