# 🛡️ QRGuard – AI-Based QR Phishing Detection System

### Detect Phishing Threats Hidden in QR Codes Using Machine Learning

QRGuard is a cybersecurity project designed to identify potentially malicious URLs embedded in QR codes. It combines QR code decoding, URL feature extraction, and machine learning to help distinguish phishing URLs from legitimate URLs.

The project aims to improve security against **QR code phishing (quishing)**, where attackers use malicious QR codes to redirect users to fraudulent websites or credential-harvesting pages.

## 🚀 Key Features

* **QR Code Decoding:** Extracts URLs from QR code images.
* **URL Feature Extraction:** Analyzes URL characteristics to identify potential phishing indicators.
* **Machine Learning Detection:** Uses a trained machine learning model to classify URLs.
* **Phishing URL Analysis:** Identifies suspicious patterns in URLs.
* **Web Interface:** Provides a frontend for interacting with the detection system.
* **Backend API:** Processes requests and connects the detection components.
* **Dataset Management:** Supports preparing datasets for training and testing.

## 🧰 Technologies Used

| Category             | Technologies         |
| -------------------- | -------------------- |
| Programming Language | Python, JavaScript   |
| Backend              | Flask                |
| Frontend             | React.js             |
| Machine Learning     | Scikit-learn         |
| Image Processing     | OpenCV               |
| QR Code Processing   | Pyzbar               |
| Data Processing      | Pandas, NumPy        |
| Development Tools    | VS Code, Git, GitHub |

*The technologies listed above describe the intended project stack; adjust them to match the libraries and components actually used in your implementation.*

## 🏗️ Project Structure

```text
QRGuard-AI-QR-Phishing-Detection/
│
├── backend/
│   ├── app.py
│   ├── data/
│   │   ├── build_dataset.py
│   │   ├── dataset.csv
│   │   └── fetch_real_dataset.py
│   ├── model/
│   │   ├── model.pkl
│   │   └── train_model.py
│   └── utils/
│       ├── feature_extractor.py
│       └── qr_decoder.py
│
├── quishing-frontend/
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── README.md
│
├── generate_cert.py
├── package.json
├── package-lock.json
├── test_phishing_qr.png
└── .gitignore
```

## ⚙️ Installation and Setup

### Prerequisites

Install the following before running the project:

* Python 3.10 or a compatible version
* Node.js and npm
* Git

### 1. Clone the Repository

```bash
git clone https://github.com/shaiksahil01/QRGuard-AI-QR-Phishing-Detection.git
cd QRGuard-AI-QR-Phishing-Detection
```

### 2. Set Up the Python Backend

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the Python dependencies:

```powershell
pip install flask opencv-python pyzbar scikit-learn pandas numpy
```

> Install any additional packages required by your backend. If your project has a `requirements.txt`, use `pip install -r requirements.txt` instead.

### 3. Configure the Backend

Configure the backend URL and any required environment variables using local configuration files.

Do not commit passwords, API keys, private certificates, or environment files to GitHub.

### 4. Start the Backend

Terminal 1 - Flask Backend
From the project root, run:

```powershell
cd “D:\QR phishing detection”
venv\Scripts\activate
python backend/app.py
```

Confirm the port and startup instructions in `backend/app.py`. If the backend expects a different working directory or command, follow its implementation.

### 5. Set Up the Frontend

Terminal 2 - React Frontend
Open a second terminal:
```powershell
cd quishing-frontend
npm install
npm start
```

If your frontend uses a different start script, check the `scripts` section in `quishing-frontend/package.json`.

Configure the frontend's API URL to point to the backend address used by your local environment.

## 🔍 How It Works

1. **QR Code Input:** The user provides an image containing a QR code.
2. **URL Extraction:** The system decodes the QR code and extracts its embedded URL.
3. **Feature Extraction:** Relevant URL characteristics are calculated for analysis.
4. **Model Prediction:** The trained machine learning model evaluates the extracted features.
5. **Result Display:** The application presents the model's classification to the user.

## 🖼️ Images 

## **QRGuard Dashboard**


<img width="1900" height="936" alt="Screenshot 2026-10-26 104620" src="https://github.com/user-attachments/assets/869d2f4e-5603-4f05-bede-39a9fefc6706" />


## **Phishing Detection Result**


<img width="1898" height="934" alt="Screenshot 2026-10-26 105350" src="https://github.com/user-attachments/assets/7a695a7a-94d1-4dbd-81f7-b1c8c0a17dee" />


<img width="1892" height="927" alt="Screenshot 2026-10-26 105408" src="https://github.com/user-attachments/assets/013c4802-636b-4570-bb24-4c5f8270f4ab" />


## **Legitimate QR Code Detection**


<img width="1895" height="928" alt="Screenshot 2026-10-26 105455" src="https://github.com/user-attachments/assets/379aaf8d-f0d4-4d7e-b3f0-63df6e0929b1" />


<img width="1897" height="924" alt="Screenshot 2026-10-26 105512" src="https://github.com/user-attachments/assets/fab3edb1-c1ba-489d-b216-8be82cf7354b" />


## 🧪 Dataset

The project includes a dataset preparation script and a CSV file containing URL examples and labels.

In the current sample labeling scheme:

* `1` represents phishing.
* `0` represents legitimate.

Synthetic examples can be useful for development and demonstrations. However, they should not be represented as verified malicious URLs.

For meaningful evaluation, use a diverse, well-documented dataset and test the model on data that was not used during training.

## 🔐 Security Considerations

* Never enter credentials on websites solely because a QR code directs you there.
* Treat model predictions as indicators, not guarantees.
* Do not automatically open potentially malicious URLs during analysis.
* Keep private keys and environment variables outside version control.
* Avoid collecting or storing users' sensitive information unnecessarily.

## ⚠️ Limitations

Machine learning predictions can produce false positives and false negatives. Detection performance depends on the dataset, selected features, model quality, and changes in phishing techniques.

QRGuard is an educational cybersecurity project and should not be considered a guarantee that a URL is safe.

## 🎯 Project Objectives

* Explore QR code phishing detection techniques.
* Apply machine learning to URL classification.
* Integrate QR decoding with a web application.
* Demonstrate a practical cybersecurity detection workflow.
* Support further research into phishing prevention.

## 🔮 Future Enhancements

* Integrate regularly updated threat-intelligence feeds.
* Expand and validate the training dataset.
* Compare multiple classification algorithms.
* Add model performance metrics and confusion matrices.
* Improve the user interface and reporting capabilities.
* Introduce safe URL reputation checks.

## 👨‍💻 Author

**Shaik Sahil**

MCA – Cybersecurity | Cyber Forensics and Ethical Hacking

GitHub: [shaiksahil01](https://github.com/shaiksahil01)
