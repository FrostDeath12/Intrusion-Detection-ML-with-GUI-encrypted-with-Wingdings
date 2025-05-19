import os
import json
import joblib
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import psutil
import subprocess
import threading
from train import attack_classifier, parse_log_line  # Import trained model and parsing function

MODEL_PATH = "C:/Users/Nathan/Desktop/Intrusion-and-anomaly-detection-with-machine-learning-master/MODELS/attack_classifier_rf_1738419837.pkl"

# Load trained model
try:
    attack_classifier = joblib.load(MODEL_PATH)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    attack_classifier = None

# Function to check and close unused ports
def close_unused_ports():
    for conn in psutil.net_connections():
        if conn.status == psutil.CONN_CLOSE_WAIT or conn.status == psutil.CONN_TIME_WAIT:
            try:
                p = psutil.Process(conn.pid)
                p.terminate()
                print(f"Closed unused port: {conn.laddr.port}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

# Function to reopen closed ports
#open ports back
def reopen_ports():
    try:
        subprocess.run(["netsh", "interface", "portproxy", "reset"], check=True)
        print("Reopened previously closed ports.")
    except subprocess.CalledProcessError:
        print("Failed to reopen ports.")


# Function to retrieve all files (excluding D drive)
def get_all_files(start_dirs=["C:\\", "E:\\", "F:\\", "G:\\"]):
    file_list = []
    for start_dir in start_dirs:
        for root, _, files in os.walk(start_dir):
            file_list.extend(os.path.join(root, file) for file in files)
            if len(file_list) > 1000:
                return file_list
    return file_list


# Function to scan a file using the trained model
def scan_file(file_path):
    if attack_classifier is None:
        return {"risk": "Medium", "reason": "Model not trained yet", "fix": "Run train.py first."}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            log_line = f.readline().strip()

        features = np.array(parse_log_line(log_line)).reshape(1, -1)
        prediction = attack_classifier.predict(features)[0]
        confidence = max(attack_classifier.predict_proba(features)[0])

        if prediction == 1:
            risk = "High"
        elif confidence > 0.6:
            risk = "Medium"
        else:
            risk = "Safe"

        return {
            "risk": risk,
            "reason": f"Threat confidence: {confidence:.2f}",
            "fix": "Delete the file immediately or Deploy antivirus system." if risk == "High" else "Consider further analysis."
        }
    except Exception as e:
        return {"risk": "Medium", "reason": f"Error scanning file: {str(e)}", "fix": "Check file format and try again."}


# GUI Application
class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("The Unseen Defender: 24/7 Threat Monitoring")
        self.root.geometry("800x600")
        self.username = "admin"
        self.password = "admin"
        self.scan_results = {}
        self.setup_login_screen()
        close_unused_ports()  # Ensure ports are closed on startup
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)  # Capture close event

    def setup_login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Login", font=("Times New Roman", 24)).pack(pady=20)
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        tk.Label(self.root, text="Username", font=("Times New Roman", 14)).pack(pady=5)
        tk.Entry(self.root, textvariable=self.username_var, font=("Times New Roman", 14)).pack(pady=5)
        tk.Label(self.root, text="Password", font=("Times New Roman", 14)).pack(pady=5)
        tk.Entry(self.root, textvariable=self.password_var, font=("Times New Roman", 14), show="*").pack(pady=5)
        tk.Button(self.root, text="Log In", command=self.login, font=("Times New Roman", 14), bg="blue",
                  fg="white").pack(pady=10)
        tk.Button(self.root, text="Exit", command=self.root.quit, font=("Times New Roman", 14), bg="red",
                  fg="white").pack(pady=10)

    def login(self):
        if self.username_var.get().strip() == "admin" and self.password_var.get().strip() == "admin":
            self.setup_main_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def setup_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Antivirus Scanner", font=("Times New Roman", 24)).pack(pady=20)
        tk.Button(self.root, text="Scan PC", command=self.show_consent_page, font=("Times New Roman", 14), bg="orange", fg="white").pack(pady=10)

        tk.Button(self.root, text="Exit", command=self.root.quit, font=("Times New Roman", 14), bg="red",
                  fg="white").pack(pady=10)

    def show_consent_page(self):
        consent = messagebox.askyesno("User Consent",
                                      "Do you consent to this scan? The process may inspect files and system activities.")
        if consent:
            self.start_scan()  # Start scan only if user consents
        else:
            messagebox.showinfo("Consent Declined", "Scan canceled due to lack of user consent.")

    def start_scan(self):
        close_unused_ports()  # Close unused ports before scanning
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Scanning PC...", font=("Times New Roman", 24)).pack(pady=20)
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=10)
        self.progress_label = tk.Label(self.root, text="0%", font=("Times New Roman", 12))
        self.progress_label.pack()
        scan_thread = threading.Thread(target=self.perform_scan, daemon=True)
        scan_thread.start()

    def perform_scan(self):
        self.scan_results = sorted(
            {file: scan_file(file) for file in get_all_files()}.items(),
            key=lambda x: ["High", "Medium", "Safe"].index(x[1]['risk'])
        )
        self.display_encrypted_report()

    def display_encrypted_report(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Scan Complete", font=("Times New Roman", 24)).pack(pady=20)
        self.report_text = ScrolledText(self.root, wrap=tk.WORD, font=("Wingdings", 12), width=80, height=20)
        self.report_text.pack(pady=20)

        for file, details in self.scan_results:
            color = "red" if details['risk'] == "High" else "orange" if details['risk'] == "Medium" else "green"
            self.report_text.insert(tk.END,
                                    f"{file}:\n Risk: {details['risk']}\n Reason: {details['reason']}\n Fix: {details['fix']}\n\n",
                                    color)
            self.report_text.tag_configure("red", foreground="red")
            self.report_text.tag_configure("orange", foreground="orange")
            self.report_text.tag_configure("green", foreground="green")

        self.decrypt_button = tk.Button(self.root, text="Decrypt Report", command=self.decrypt_report,
                                        font=("Times New Roman", 14), bg="blue", fg="white")
        self.decrypt_button.pack(pady=10)
        tk.Button(self.root, text="Exit", command=self.setup_main_screen, font=("Times New Roman", 14), bg="red",
                  fg="white").pack(pady=10)

    def decrypt_report(self):
        password = simpledialog.askstring("Decrypt", "Enter the password to view the report:", show="*")
        if password == self.password:
            self.report_text.config(font=("Times New Roman", 12))
            self.decrypt_button.destroy()
        else:
            messagebox.showerror("Error", "Incorrect password.")

    def on_exit(self):
        reopen_ports()  # open ports back
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
