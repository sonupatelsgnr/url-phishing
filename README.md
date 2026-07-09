# URL Phishing Detection System

A Machine Learning-based web application that detects whether a given URL is **Legitimate**, **Suspicious**, 
or **Phishing** using a **Random Forest Classifier** and handcrafted URL features.

---

## 📌 Features

* Detects phishing URLs using Machine Learning.
* Extracts multiple security-related URL features.
* Calculates phishing risk percentage.
* Displays confidence score.
* Performs heuristic security checks such as:
  * HTTPS detection
  * IP address detection
  * Suspicious Top-Level Domain (TLD) detection
  * URL length analysis
  * Subdomain analysis
  * URL shortener detection
  * Hyphen and digit abuse detection
  * Suspicious query parameter detection
* Trusted domain whitelist support.
* Clean and responsive Flask web interface.

---

## 🛠 Technologies Used

* Python 3
* Flask
* Scikit-learn
* Pandas
* NumPy
* HTML
* CSS
* JavaScript

---

## 📂 Project Structure

```text
url-phishing/
│
├── app.py
├── Train.py
├── feature_extractor.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── dataset/
│   └── phishing_site_urls.csv
│
├── templates/
│   └── index.html
│
└── model/
    └── phishing_model.pkl (Generated after training)
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/sonupatelsgnr/url-phishing.git
```

Move into the project directory:

```bash
cd url-phishing
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## 🧠 Train the Model

The trained model is **not included** in this repository because it is too large for GitHub.

Generate the model locally by running:

```bash
python Train.py
```

This command automatically creates:

```text
model/
└── phishing_model.pkl
```

---

## ▶️ Run the Application

Start the Flask server:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## 📊 Model

* Algorithm: Random Forest Classifier
* Feature Extraction: Custom URL-based handcrafted features
* Binary Classification:

  * Legitimate
  * Phishing

---

## 🔍 URL Security Checks

The application performs several heuristic checks, including:

* HTTPS availability
* IP address usage
* URL length
* Number of subdomains
* Suspicious Top-Level Domains
* URL shorteners
* Hyphen abuse
* Digit abuse
* Suspicious query parameters
* Trusted domain whitelist verification

---

## 📸 Screenshots

Example:

```text
screenshots/
├── home.png
  <img width="1913" height="925" alt="Screenshot" src="https://github.com/user-attachments/assets/9b4ccbff-7615-4fe7-9f96-061c9c8bd467" />
├── result_safe.png
  <img width="1917" height="922" alt="Screenshot" src="https://github.com/user-attachments/assets/9a55f194-42a3-4f5d-b769-2a0994b15fc0" />
└── result_phishing.png
 <img width="1915" height="923" alt="Screenshot" src="https://github.com/user-attachments/assets/0bf4705f-440e-4e4a-9df6-e16cf00fd1bf" />
└── Heuristic_Integrity_Checks.png
  <img width="1918" height="930" alt="Screenshot" src="https://github.com/user-attachments/assets/dafe84c6-ac22-4cf8-a5f1-521d98ef8f9d" />
└── Prameters_check.png
  <img width="1918" height="927" alt="Screenshot" src="https://github.com/user-attachments/assets/75c31ee6-017a-49fc-90c3-c60e52d60cf6" />
```

---

## 📦 Requirements

Install all dependencies using:

```bash
pip install -r requirements.txt
```

---

## 👨‍💻 Author

**Sonu**

MCA (Cyber Security)

GitHub: https://github.com/sonupatelsgnr

---

## 📄 License

This project is developed for educational and learning purposes.

You can also enhance the repository by adding screenshots of your application's home page and phishing detection results—they make GitHub projects look much more polished and professional.
