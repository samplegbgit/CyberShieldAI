import tkinter as tk
from tkinter import messagebox
import validators
import json
import os
from datetime import datetime
import matplotlib.pyplot as plt

DATA_FILE = "threat_history.json"


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"scans": []}
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


def phishing_score(url):
    suspicious_keywords = [
        "login", "verify", "secure", "account", "bank",
        "update", "free", "bonus", "confirm", "password"
    ]

    score = 0

    if url.count("-") > 2:
        score += 2

    if url.count(".") > 3:
        score += 2

    if "https" not in url:
        score += 2

    for word in suspicious_keywords:
        if word in url.lower():
            score += 1

    return score


def classify(score):
    if score >= 7:
        return "Dangerous Phishing Detected"
    elif score >= 4:
        return "Suspicious  Medium Risk"
    else:
        return "Safe Low Risk"


class CyberShieldAI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield AI – Phishing Detector")
        self.root.geometry("850x650")
        self.root.configure(bg="#0d1117")

        self.data = load_data()

        tk.Label(
            root,
            text="🛡 CyberShield AI",
            font=("Arial", 26, "bold"),
            fg="cyan",
            bg="#0d1117"
        ).pack(pady=15)

        tk.Label(
            root,
            text="Phishing URL & Threat Detection System",
            font=("Arial", 12),
            fg="white",
            bg="#0d1117"
        ).pack()

        tk.Label(
            root,
            text="Enter Website URL to Scan:",
            font=("Arial", 12),
            fg="white",
            bg="#0d1117"
        ).pack(pady=10)

        self.url_entry = tk.Entry(root, width=70, font=("Arial", 12))
        self.url_entry.pack(pady=5)

        tk.Button(
            root,
            text="Scan URL",
            font=("Arial", 12),
            bg="cyan",
            fg="black",
            command=self.scan_url
        ).pack(pady=15)

        tk.Button(
            root,
            text="View Threat Analytics",
            font=("Arial", 12),
            bg="lime",
            fg="black",
            command=self.show_graph
        ).pack(pady=10)

        tk.Label(
            root,
            text="Recent Scan History:",
            font=("Arial", 12),
            fg="white",
            bg="#0d1117"
        ).pack(pady=10)

        self.history_box = tk.Listbox(root, width=110, height=10)
        self.history_box.pack(pady=10)

        self.load_history()

    def scan_url(self):
        url = self.url_entry.get().strip()

        if not url:
            return messagebox.showwarning("Empty", "Please enter a URL.")

        if not validators.url(url):
            return messagebox.showerror("Invalid", "Enter a valid URL format.")

        score = phishing_score(url)
        result = classify(score)

        scan_log = {
            "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "url": url,
            "score": score,
            "result": result
        }

        self.data["scans"].append(scan_log)
        save_data(self.data)

        messagebox.showinfo("Scan Result", f"Threat Level:\n{result}")

        self.url_entry.delete(0, tk.END)
        self.load_history()

    def load_history(self):
        self.history_box.delete(0, tk.END)

        for scan in reversed(self.data["scans"][-8:]):
            self.history_box.insert(
                tk.END,
                f"{scan['date']} | {scan['url']} → {scan['result']}"
            )

    def show_graph(self):
        if len(self.data["scans"]) == 0:
            return messagebox.showinfo("No Data", "No scans available yet.")

        scores = [s["score"] for s in self.data["scans"]]
        scan_no = list(range(1, len(scores) + 1))

        plt.plot(scan_no, scores, marker="o")
        plt.title("CyberShield AI – Threat Score Over Time")
        plt.xlabel("Scan Number")
        plt.ylabel("Threat Score")
        plt.show()


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberShieldAI(root)
    root.mainloop()
