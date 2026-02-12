import tkinter as tk
from tkinter import messagebox, filedialog
import validators
import json
import os
from datetime import datetime
import matplotlib.pyplot as plt
import csv
import re

DATA_FILE = "cybershield_database.json"




def load_data():
    if not os.path.exists(DATA_FILE):
        return {"scans": []}
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)



def threat_analysis(url):
    reasons = []
    score = 0

    suspicious_keywords = [
        "login", "verify", "secure", "bank", "update",
        "account", "bonus", "free", "confirm", "password",
        "wallet", "crypto", "payment"
    ]

    dangerous_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]

    if not url.startswith("https"):
        score += 3
        reasons.append("No HTTPS encryption detected")

    
    if url.count(".") > 4:
        score += 2
        reasons.append("Too many subdomains (possible fake domain)")

    if "@" in url or "//" in url[8:]:
        score += 4
        reasons.append("Suspicious redirect symbol (@ or //)")

    
    if re.match(r"^(http|https)://\d+\.\d+\.\d+\.\d+", url):
        score += 5
        reasons.append("URL uses IP address instead of domain")

 
    if any(short in url for short in shorteners):
        score += 4
        reasons.append("URL shortener detected (hidden destination)")

 
    if any(url.endswith(tld) for tld in dangerous_tlds):
        score += 3
        reasons.append("High-risk domain extension detected")

    for word in suspicious_keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword found: {word}")

    return score, reasons


def classify(score):
    if score >= 12:
        return " HIGH RISK (Phishing Attack)", "red"
    elif score >= 6:
        return " MEDIUM RISK (Suspicious)", "orange"
    else:
        return " SAFE (Low Risk)", "green"




class CyberShieldUltra:

    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield AI Ultra – Cyber Threat Detection Suite")
        self.root.geometry("1050x780")
        self.root.configure(bg="#0d1117")

        self.data = load_data()

        tk.Label(root,
                 text="🛡 CyberShield AI Ultra",
                 font=("Arial", 30, "bold"),
                 fg="cyan",
                 bg="#0d1117").pack(pady=10)

        tk.Label(root,
                 text="Advanced Cybersecurity Threat Intelligence Scanner",
                 font=("Arial", 13),
                 fg="white",
                 bg="#0d1117").pack()

        tk.Label(root,
                 text="Enter URL for Deep Scan:",
                 font=("Arial", 12),
                 fg="white",
                 bg="#0d1117").pack(pady=10)

        self.url_entry = tk.Entry(root, width=85, font=("Arial", 13))
        self.url_entry.pack()

        tk.Button(root,
                  text=" Run Threat Scan",
                  font=("Arial", 12, "bold"),
                  bg="cyan",
                  fg="black",
                  command=self.scan_url).pack(pady=12)

        self.result_label = tk.Label(root,
                                     text="Threat Level: ---",
                                     font=("Arial", 15, "bold"),
                                     fg="white",
                                     bg="#0d1117")
        self.result_label.pack()

        self.reason_box = tk.Text(root, width=110, height=6, font=("Arial", 10))
        self.reason_box.pack(pady=10)

  
        tk.Label(root,
                 text=" Recent Threat Scan Logs:",
                 font=("Arial", 12),
                 fg="white",
                 bg="#0d1117").pack()

        self.history_box = tk.Listbox(root, width=125, height=10)
        self.history_box.pack(pady=8)

      
        panel = tk.Frame(root, bg="#0d1117")
        panel.pack(pady=12)

        tk.Button(panel,
                  text=" Analytics Dashboard",
                  bg="lime",
                  font=("Arial", 11),
                  command=self.show_graph).grid(row=0, column=0, padx=10)

        tk.Button(panel,
                  text=" Export TXT Report",
                  bg="gold",
                  font=("Arial", 11),
                  command=self.export_txt).grid(row=0, column=1, padx=10)

        tk.Button(panel,
                  text=" Export CSV Report",
                  bg="orange",
                  font=("Arial", 11),
                  command=self.export_csv).grid(row=0, column=2, padx=10)

        tk.Button(panel,
                  text=" Clear Database",
                  bg="red",
                  fg="white",
                  font=("Arial", 11),
                  command=self.clear_history).grid(row=0, column=3, padx=10)

        self.load_history()


    def scan_url(self):
        url = self.url_entry.get().strip()

        if not url:
            return messagebox.showwarning("Empty Input", "Please enter a URL.")

        if not validators.url(url):
            return messagebox.showerror("Invalid URL", "Enter a valid website URL.")

        score, reasons = threat_analysis(url)
        result, color = classify(score)

        self.result_label.config(text=f"Threat Level: {result} (Score: {score})",
                                 fg=color)

        self.reason_box.delete("1.0", tk.END)
        self.reason_box.insert(tk.END, "Threat Explanation:\n\n")

        if reasons:
            for r in reasons:
                self.reason_box.insert(tk.END, f"• {r}\n")
        else:
            self.reason_box.insert(tk.END, "No suspicious patterns detected.\n")

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

        for scan in reversed(self.data["scans"][-12:]):
            self.history_box.insert(
                tk.END,
                f"{scan['date']} | {scan['url']} → {scan['result']} (Score: {scan['score']})"
            )

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            self.data = {"scans": []}
            save_data(self.data)
            self.load_history()
            self.reason_box.delete("1.0", tk.END)
            self.result_label.config(text="Threat Level: ---", fg="white")

 

    def export_txt(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")

        if not file_path:
            return

        with open(file_path, "w") as f:
            f.write("CyberShield AI Ultra Report\n")
            f.write("=" * 60 + "\n\n")

            for scan in self.data["scans"]:
                f.write(f"{scan['date']} | {scan['url']} → {scan['result']} (Score: {scan['score']})\n")

        messagebox.showinfo("Export Complete", "TXT Report Saved Successfully!")

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")

        if not file_path:
            return

        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Date", "URL", "Score", "Result"])

            for scan in self.data["scans"]:
                writer.writerow([scan["date"], scan["url"], scan["score"], scan["result"]])

        messagebox.showinfo("Export Complete", "CSV Report Saved Successfully!")


    def show_graph(self):
        if not self.data["scans"]:
            return messagebox.showinfo("No Data", "No scans available yet.")

        scores = [s["score"] for s in self.data["scans"]]

        plt.figure(figsize=(9, 5))
        plt.plot(scores, marker="o")
        plt.title("CyberShield Threat Score Analytics")
        plt.xlabel("Scan Number")
        plt.ylabel("Threat Score")
        plt.grid(True)
        plt.show()




if __name__ == "__main__":
    root = tk.Tk()
    app = CyberShieldUltra(root)
    root.mainloop()
