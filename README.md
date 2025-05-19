# 🛡️ Intrusion Detection with GUI and Wingdings Encryption

This project is a machine learning-based intrusion and anomaly detection system with a graphical interface. It scans local files for malicious HTTP log activity using a trained model, classifies threats by risk level, and presents encrypted scan results using Wingdings. Decryption requires user authentication.

---

## 📁 Main Components

- **`scanner_gui.py`**  
  A Tkinter-based GUI that:
  - Allows secure login
  - Scans drives (excluding D:)
  - Uses the trained model to detect anomalies
  - Displays encrypted scan results (Wingdings)
  - Requires a password to decrypt results

- **`train.py`**  
  Trains a supervised learning model (Random Forest or Logistic Regression) using encoded HTTP logs. Features are extracted using a custom parser, balanced with SMOTE, and scaled with StandardScaler.

- **`utilities.py`**  
  Includes:
  - Wingdings encryption/decryption
  - Log file encoding and simulation
  - Model saving and accuracy evaluation
  - HTML report generation

---

## ⚙️ Features

- Supervised learning using HTTP log features
- Model training with SMOTE for class imbalance
- Scan encryption with password-protected decryption
- Real-time threat level classification
- Port-closing safety mechanism during scans
---

## 🚀 How to Use

1. **Train the model**  
   Run `train.py` to preprocess logs and generate a `.pkl` model file.

2. **Start the GUI**  
   Run `scanner_gui.py`. Use default login:
   
   username: "admin"
   
   password : "admin"


4. **Scan your system**  
- Choose to proceed with the scan
- Wait for completion
- View results in encrypted Wingdings
- Enter password to decrypt and view the final report

---

## 🧪 Model Accuracy

The model evaluates its precision after training using test data and outputs the results to the terminal. You can configure it to use either Random Forest (`rf`) or Logistic Regression (`lr`).

---

## 📌 Notes

- Encrypted reports are displayed in Wingdings until decrypted.
- Decryption password is set within the app (`admin` by default).
- Ensure `MODELS/` and `SAMPLE_DATA/` folders exist for full functionality.

---

## 🧠 Author

Developed and customized for educational and demonstration purposes by **FrostDeath12**.
