import tkinter as tk
from tkinter import messagebox, filedialog
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
        "update", "free", "bonus", "confirm", "password",
        "wallet", "payment", "crypto"
    ]

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]

    score = 0

    if url.count("-") > 2:
        score += 2

    if url.count(".") > 3:
        score += 2

    if "https" not in url:
        score += 2

    if any(short in url for short in shorteners):
        score += 3

    if url.replace(".", "").isdigit():
        score += 4

    for word in suspicious_keywords:
        if word in url.lower():
            score += 1

    return score


def classify(score):
    if score >= 8:
        return "Dangerous ", "red"
    elif score >= 4:
        return "Suspicious ", "orange"
    else:
        return "Safe ", "green"


class CyberShieldAI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield AI Pro – Phishing Detector")
        self.root.geometry("950x720")
        self.root.configure(bg="#0d1117")

        self.data = load_data()

        tk.Label(
            root,
            text="🛡 CyberShield AI Pro",
            font=("Arial", 28, "bold"),
            fg="cyan",
            bg="#0d1117"
        ).pack(pady=15)

        tk.Label(
            root,
            text="Advanced Phishing URL Threat Detection System",
            font=("Arial", 13),
            fg="white",
            bg="#0d1117"
        ).pack()

        tk.Label(
            root,
            text="Enter Website URL to Scan:",
            font=("Arial", 12),
            fg="white",
            bg="#0d1117"
        ).pack(pady=12)

        self.url_entry = tk.Entry(root, width=75, font=("Arial", 13))
        self.url_entry.pack(pady=5)

        tk.Button(
            root,
            text="🔍 Scan URL",
            font=("Arial", 12, "bold"),
            bg="cyan",
            fg="black",
            command=self.scan_url
        ).pack(pady=12)

        self.result_label = tk.Label(
            root,
            text="Threat Level: ---",
            font=("Arial", 14, "bold"),
            fg="white",
            bg="#0d1117"
        )
        self.result_label.pack(pady=10)

        self.meter = tk.Canvas(root, width=400, height=25, bg="#0d1117", highlightthickness=0)
        self.meter.pack()

        tk.Label(
            root,
            text="Recent Scan History:",
            font=("Arial", 12),
            fg="white",
            bg="#0d1117"
        ).pack(pady=10)

        self.history_box = tk.Listbox(root, width=120, height=10, font=("Arial", 10))
        self.history_box.pack(pady=8)

        btn_frame = tk.Frame(root, bg="#0d1117")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="Threat Analytics",
            font=("Arial", 11),
            bg="lime",
            command=self.show_graph
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            btn_frame,
            text="Export Report",
            font=("Arial", 11),
            bg="gold",
            command=self.export_report
        ).grid(row=0, column=1, padx=10)

        tk.Button(
            btn_frame,
            text="Clear History",
            font=("Arial", 11),
            bg="red",
            fg="white",
            command=self.clear_history
        ).grid(row=0, column=2, padx=10)

        tk.Label(
            root,
            text="Search Scan History:",
            font=("Arial", 11),
            fg="white",
            bg="#0d1117"
        ).pack(pady=5)

        self.search_entry = tk.Entry(root, width=50)
        self.search_entry.pack()

        tk.Button(
            root,
            text="Search",
            bg="white",
            command=self.search_history
        ).pack(pady=5)

        self.load_history()

    def scan_url(self):
        url = self.url_entry.get().strip()

        if not url:
            return messagebox.showwarning("Empty", "Please enter a URL.")

        if not validators.url(url):
            return messagebox.showerror("Invalid", "Enter a valid URL format.")

        score = phishing_score(url)
        result, color = classify(score)

        self.result_label.config(text=f"Threat Level: {result} (Score: {score})", fg=color)

        self.meter.delete("all")
        self.meter.create_rectangle(0, 0, score * 40, 25, fill=color)

        scan_log = {
            "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "url": url,
            "score": score,
            "result": result
        }

        self.data["scans"].append(scan_log)
        save_data(self.data)

        self.url_entry.delete(0, tk.END)
        self.load_history()

    def load_history(self):
        self.history_box.delete(0, tk.END)

        for scan in reversed(self.data["scans"][-10:]):
            self.history_box.insert(
                tk.END,
                f" {scan['date']} | {scan['url']} → {scan['result']} (Score: {scan['score']})"
            )

    def show_graph(self):
        if len(self.data["scans"]) == 0:
            return messagebox.showinfo("No Data", "No scans available yet.")

        scores = [s["score"] for s in self.data["scans"]]
        scan_no = list(range(1, len(scores) + 1))

        plt.figure(figsize=(8, 5))
        plt.plot(scan_no, scores, marker="o")
        plt.title("CyberShield AI – Threat Score Analytics")
        plt.xlabel("Scan Number")
        plt.ylabel("Threat Score")
        plt.grid(True)
        plt.show()

    def export_report(self):
        if len(self.data["scans"]) == 0:
            return messagebox.showinfo("No Data", "Nothing to export.")

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt")]
        )

        if not file_path:
            return

        with open(file_path, "w") as f:
            f.write("CyberShield AI Pro – Scan Report\n")
            f.write("=" * 50 + "\n\n")

            for scan in self.data["scans"]:
                f.write(f"{scan['date']} | {scan['url']} → {scan['result']} (Score: {scan['score']})\n")

        messagebox.showinfo("Exported", "Report exported successfully!")

    def clear_history(self):
        if not messagebox.askyesno("Confirm", "Delete all scan history?"):
            return

        self.data = {"scans": []}
        save_data(self.data)
        self.load_history()
        self.result_label.config(text="Threat Level: ---", fg="white")
        self.meter.delete("all")

    def search_history(self):
        keyword = self.search_entry.get().lower()

        self.history_box.delete(0, tk.END)

        for scan in reversed(self.data["scans"]):
            if keyword in scan["url"].lower():
                self.history_box.insert(
                    tk.END,
                    f"{scan['date']} | {scan['url']} → {scan['result']}"
                )


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberShieldAI(root)
    root.mainloop()
