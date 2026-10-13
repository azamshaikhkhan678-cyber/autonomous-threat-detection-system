# main.py
import sys
import random
import tkinter as tk
from tkinter import messagebox
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from config.settings import *

class MachineLearningThreatEngine:
    def __init__(self):
        training_data = [
            [20, 1.2, 80, 0], [15, 0.5, 443, 0], [30, 2.0, 80, 0],
            [55, 4.5, 21, 1], [60, 5.2, 22, 1], [45, 6.0, 23, 1],
            [120, 9.5, 80, 2], [150, 12.1, 443, 2], [180, 14.0, 80, 2]
        ]
        columns = ['packets', 'duration', 'port', 'label']
        df = pd.DataFrame(training_data, columns=columns)
        X_train = df[['packets', 'duration', 'port']]
        y_train = df['label']
        self.classifier = DecisionTreeClassifier(random_state=42)
        self.classifier.fit(X_train, y_train)

    def analyze_log_row(self, packets, duration, port):
        features = pd.DataFrame([[packets, duration, port]], columns=['packets', 'duration', 'port'])
        prediction_class = self.classifier.predict(features)
        probabilities = self.classifier.predict_proba(features)
        confidence_metric = float(np.max(probabilities))
        if prediction_class == 0: return "NORMAL", COLOR_OK, confidence_metric
        elif prediction_class == 1: return "WARNING", COLOR_WARN, confidence_metric
        else: return "CRITICAL", COLOR_CRIT, confidence_metric

class SOCTerminalDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Powered Threat Detection Terminal - Core SOC Portal")
        self.root.geometry(f"{WIDTH}x{HEIGHT}")
        self.root.configure(bg=COLOR_BG_DARK)
        self.ml_engine = MachineLearningThreatEngine()
        self.total_count = 0
        self.normal_count = 0
        self.warning_count = 0
        self.critical_count = 0
        self.is_running = False
        self.assemble_ui()

    def assemble_ui(self):
        self.header = tk.Frame(self.root, bg=COLOR_PANEL_BG, height=60)
        self.header.pack(side=tk.TOP, fill=tk.X, padx=15, pady=10)
        tk.Label(self.header, text="🛡️ AI-POWERED THREAT DETECTION SECURITY HUB", font=("Courier New", 14, "bold"), fg=COLOR_TEXT_LIGHT, bg=COLOR_PANEL_BG).pack(side=tk.LEFT, padx=20, pady=15)
        self.btn_toggle = tk.Button(self.header, text="▶ ENGAGE NIDS MONITOR", font=("Courier New", 10, "bold"), fg="#ffffff", bg="#0088cc", command=self.toggle_monitor, width=22, bd=0)
        self.btn_toggle.pack(side=tk.RIGHT, padx=20, pady=10)
        self.metrics_container = tk.Frame(self.root, bg=COLOR_BG_DARK)
        self.metrics_container.pack(side=tk.TOP, fill=tk.X, padx=15, pady=5)
        self.box_total = self.create_card(self.metrics_container, "TOTAL DATA LOGS", "0", COLOR_TEXT_LIGHT, 0)
        self.box_normal = self.create_card(self.metrics_container, "SAFE CHANNELS", "0", COLOR_OK, 1)
        self.box_warn = self.create_card(self.metrics_container, "SUSPICIOUS SCANS", "0", COLOR_WARN, 2)
        self.box_crit = self.create_card(self.metrics_container, "CRITICAL ATTACKS", "0", COLOR_CRIT, 3)
        self.console = tk.Frame(self.root, bg=COLOR_PANEL_BG, bd=1, relief=tk.SUNKEN)
        self.console.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=15, pady=10)
        self.log_list = tk.Listbox(self.console, bg=COLOR_BG_DARK, fg="#ffffff", font=("Courier New", 9), bd=0, highlightthickness=0)
        self.log_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=10)

    def create_card(self, parent, title, val, color, col_idx):
        card = tk.Frame(parent, bg=COLOR_PANEL_BG, bd=1, relief=tk.RAISED)
        card.grid(row=0, column=col_idx, padx=8, pady=5, sticky="nsew")
        parent.grid_columnconfigure(col_idx, weight=1)
        tk.Label(card, text=title, font=("Courier New", 8, "bold"), fg=COLOR_TEXT_MUTED, bg=COLOR_PANEL_BG).pack(pady=5)
        lbl = tk.Label(card, text=val, font=("Courier New", 18, "bold"), fg=color, bg=COLOR_PANEL_BG)
        lbl.pack(pady=2)
        return lbl

    def toggle_monitor(self):
        self.is_running = not self.is_running
        if self.is_running:
            self.btn_toggle.config(text="⏸ PAUSE ANALYSIS", bg=COLOR_CRIT)
            self.run_simulation()
        else:
            self.btn_toggle.config(text="▶ ENGAGE NIDS MONITOR", bg="#0088cc")

    def run_simulation(self):
        if not self.is_running: return
        self.total_count += 1
        roll = random.random()
        if roll < 0.65:
            packets, duration, port, tag = random.randint(12, 35), round(random.uniform(0.2, 1.9), 2), random.choice([80, 443]), "HEALTHY_DATA"
        elif roll < 0.88:
            packets, duration, port, tag = random.randint(40, 70), round(random.uniform(3.0, 5.8), 2), random.choice([21, 22, 23]), "PORT_PROBE"
        else:
            packets, duration, port, tag = random.randint(100, 175), round(random.uniform(8.0, 14.0), 2), random.choice([80, 443]), "DDOS_ATTACK"

        status, color, confidence = self.ml_engine.analyze_log_row(packets, duration, port)
        if status == "NORMAL": self.normal_count += 1; self.box_normal.config(text=str(self.normal_count))
        elif status == "WARNING": self.warning_count += 1; self.box_warn.config(text=str(self.warning_count))
        else: self.critical_count += 1; self.box_crit.config(text=str(self.critical_count))
        self.box_total.config(text=str(self.total_count))

        log_msg = f"[{tag}] Port:{port:3d} | Packets:{packets:3d} | Len:{duration}s -> ML RESULT: {status} (Conf:{confidence:.2f})"
        self.log_list.insert(tk.END, log_msg)
        self.log_list.itemconfig(tk.END, {'fg': color})
        self.log_list.see(tk.END)

        if status == "CRITICAL" and self.critical_count % 6 == 1:
            self.is_running = False
            self.btn_toggle.config(text="▶ ENGAGE NIDS MONITOR", bg="#0088cc")
            messagebox.showwarning("SIEM CORE ALERT BANNER", f"CRITICAL intrusion identified by Scikit-Learn model!\n\nVector: {tag}\nAI Confidence: {confidence:.2f}\n\nIsolating server nodes...")

        self.root.after(450, self.run_simulation)

if __name__ == "__main__":
    win = tk.Tk()
    app = SOCTerminalDashboard(win)
    win.mainloop()
