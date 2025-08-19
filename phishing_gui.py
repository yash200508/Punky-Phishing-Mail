import tkinter as tk
from tkinter import scrolledtext, font, messagebox, filedialog
import re
import joblib
import sys, os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Then, use this to load your files:
model = joblib.load(resource_path('phishing_model.pkl'))
vectorizer = joblib.load(resource_path('tfidf_vectorizer.pkl'))


phishing_keywords = [
    "urgent", "verify", "password", "account", "login", "click here",
    "update", "security alert", "confirm", "suspend", "bank", "paypal"
]

whitelist_domains = [
    "example.com", "trusted.com", "yourcompany.com"
]

def extract_domain(email_address):
    match = re.search(r'@([A-Za-z0-9.-]+)$', email_address)
    return match.group(1).lower() if match else ""

def contains_phishing_keywords(text):
    text = text.lower()
    found = [word for word in phishing_keywords if word in text]
    return found

def suspicious_domain(domain):
    if domain not in whitelist_domains:
        if re.search(r'\d', domain):
            return True
    return False

def suspicious_links(text):
    urls = re.findall(r'https?://[^\s]+', text.lower())
    suspicious = []
    for url in urls:
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            suspicious.append(url)
    return suspicious

def predict_phishing_ml(subject, body):
    combined_text = subject + " " + body
    X = vectorizer.transform([combined_text])
    prediction = model.predict(X)[0]  # 0 = clean, 1 = phishing
    return bool(prediction)

history = []

window = tk.Tk()
window.title("Phishing Email Detector")
window.state('zoomed')  # Start maximized, comment out if you want normal size
window.configure(bg="#f0f4f7")

header_font = font.Font(family="Helvetica", size=14, weight="bold")
label_font = font.Font(family="Helvetica", size=10)
button_font = font.Font(family="Helvetica", size=12, weight="bold")

# --- INPUT FRAME ---
input_frame = tk.Frame(window, bg="#f0f4f7", padx=15, pady=15)
input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 0))

tk.Label(input_frame, text="Sender Email:", font=label_font, bg="#f0f4f7").grid(row=0, column=0, sticky="w", pady=5)
sender_entry = tk.Entry(input_frame, font=label_font)
sender_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=5)

tk.Label(input_frame, text="Email Subject:", font=label_font, bg="#f0f4f7").grid(row=1, column=0, sticky="w", pady=5)
subject_entry = tk.Entry(input_frame, font=label_font)
subject_entry.grid(row=1, column=1, sticky="ew", pady=5, padx=5)

risk_label = tk.Label(input_frame, text="Risk: N/A", font=label_font, bg="#f0f4f7")
risk_label.grid(row=2, column=1, sticky="w", pady=5)

tk.Label(input_frame, text="Email Body:", font=label_font, bg="#f0f4f7").grid(row=3, column=0, sticky="nw", pady=5)
body_text = scrolledtext.ScrolledText(input_frame, font=label_font, wrap=tk.WORD, height=10)
body_text.grid(row=3, column=1, sticky="nsew", pady=5, padx=5)

# Make columns and row 3 expandable in input_frame
input_frame.grid_columnconfigure(1, weight=1)
input_frame.grid_rowconfigure(3, weight=1)

# --- RESULT FRAME ---
result_frame = tk.Frame(window, bg="#f0f4f7", padx=15, pady=10)
result_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)

tk.Label(result_frame, text="Analysis Result:", font=header_font, bg="#f0f4f7").grid(row=0, column=0, sticky='w')
result_text = scrolledtext.ScrolledText(result_frame, font=label_font, wrap=tk.WORD, height=5, state=tk.DISABLED, bg="#e8f0fe")
result_text.grid(row=1, column=0, sticky="nsew", pady=5)

result_frame.grid_rowconfigure(1, weight=1)
result_frame.grid_columnconfigure(0, weight=1)

# --- HISTORY FRAME ---
history_frame = tk.Frame(window, bg="#f0f4f7", padx=15, pady=10)
history_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 0))

tk.Label(history_frame, text="Analysis History (Click to view):", font=header_font, bg="#f0f4f7").grid(row=0, column=0, sticky='w')
history_listbox = tk.Listbox(history_frame, font=label_font, height=6)
history_listbox.grid(row=1, column=0, sticky="nsew", pady=5)

history_frame.grid_rowconfigure(1, weight=1)
history_frame.grid_columnconfigure(0, weight=1)

# --- BUTTON FRAME ---
button_frame = tk.Frame(window, bg="#f0f4f7", pady=10)
button_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)

analyze_button = tk.Button(button_frame, text="Analyze Email", command=lambda: analyze_email(), font=button_font, bg="#4CAF50", fg="white", padx=10, pady=5)
analyze_button.pack(side=tk.LEFT, padx=10)

clear_button = tk.Button(button_frame, text="Clear All", command=lambda: clear_all(), font=button_font, bg="#f44336", fg="white", padx=10, pady=5)
clear_button.pack(side=tk.LEFT, padx=10)

load_button = tk.Button(button_frame, text="Load Email", command=lambda: load_email_file(), font=button_font, bg="#2196F3", fg="white", padx=10, pady=5)
load_button.pack(side=tk.LEFT, padx=10)

export_button = tk.Button(button_frame, text="Export Result", command=lambda: export_result(), font=button_font, bg="#FF9800", fg="white", padx=10, pady=5)
export_button.pack(side=tk.LEFT, padx=10)

# Make main window expandable
window.grid_rowconfigure(0, weight=2)
window.grid_rowconfigure(1, weight=1)
window.grid_rowconfigure(2, weight=1)
window.grid_rowconfigure(3, weight=0)
window.grid_columnconfigure(0, weight=1)

# ==== FUNCTION DEFINITIONS ====

def add_to_history(sender, subject, body, analysis_result):
    entry = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "analysis": analysis_result
    }
    history.append(entry)
    update_history_list()

def update_history_list():
    history_listbox.delete(0, tk.END)
    for i, entry in enumerate(history):
        display = f"{i+1}: {entry['subject'][:40]} - From: {entry['sender']}"
        history_listbox.insert(tk.END, display)

def load_history_entry(event=None):
    try:
        idx = history_listbox.curselection()[0]
        entry = history[idx]
        sender_entry.delete(0, tk.END)
        sender_entry.insert(0, entry['sender'])
        subject_entry.delete(0, tk.END)
        subject_entry.insert(0, entry['subject'])
        body_text.delete("1.0", tk.END)
        body_text.insert(tk.END, entry['body'])
        result_text.config(state=tk.NORMAL)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, entry['analysis'])
        result_text.config(state=tk.DISABLED)
        highlight_phishing_keywords()
        live_check()
    except IndexError:
        pass

def clear_all():
    sender_entry.delete(0, tk.END)
    subject_entry.delete(0, tk.END)
    body_text.delete("1.0", tk.END)
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    result_text.config(state=tk.DISABLED)
    risk_label.config(text="Risk: N/A", fg="black")

def analyze_email():
    sender = sender_entry.get()
    subject = subject_entry.get()
    body = body_text.get("1.0", tk.END)

    reasons = []

    domain = extract_domain(sender)
    if suspicious_domain(domain):
        reasons.append(f"Suspicious sender domain: {domain}")

    keywords_in_subject = contains_phishing_keywords(subject)
    keywords_in_body = contains_phishing_keywords(body)
    if keywords_in_subject or keywords_in_body:
        reasons.append(f"Phishing keywords found: {set(keywords_in_subject + keywords_in_body)}")

    suspicious_urls = suspicious_links(body)
    if suspicious_urls:
        reasons.append(f"Suspicious links detected: {suspicious_urls}")

    is_phishing_ml = predict_phishing_ml(subject, body)
    if is_phishing_ml:
        reasons.append("ML Model Prediction: Phishing Detected")
    else:
        reasons.append("ML Model Prediction: Email appears clean")

    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)

    phishing_signs = any("Phishing" in r for r in reasons)
    if phishing_signs:
        result_text.insert(tk.END, "Phishing Suspected!\nReasons:\n")
        for r in reasons:
            if "Phishing" in r:
                result_text.insert(tk.END, "- " + r + "\n")
        result_text.config(fg="red")
    else:
        result_text.insert(tk.END, "No suspicious signs detected. Email appears clean.\n")
        for r in reasons:
            if "Phishing" not in r:
                result_text.insert(tk.END, "- " + r + "\n")
        result_text.config(fg="green")

    result_text.config(state=tk.DISABLED)

    add_to_history(sender, subject, body, result_text.get("1.0", tk.END))

def load_email_file():
    filepath = filedialog.askopenfilename(
        title="Open Email File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not filepath:
        return
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        sender = ""
        subject = ""
        body_lines = []
        body_start = False

        for line in lines:
            stripped = line.strip()
            if stripped.lower().startswith("from:") and not sender:
                match = re.search(r'<([^>]+)>', stripped)
                if match:
                    sender = match.group(1).strip()
                else:
                    sender = stripped[5:].strip()
            elif stripped.lower().startswith("subject:") and not subject:
                subject = stripped[8:].strip()
                body_start = True
            elif body_start:
                body_lines.append(line.rstrip('\n'))

        body = "\n".join(body_lines).strip()

        sender_entry.delete(0, tk.END)
        sender_entry.insert(0, sender)
        subject_entry.delete(0, tk.END)
        subject_entry.insert(0, subject)
        body_text.delete("1.0", tk.END)
        body_text.insert(tk.END, body)
        messagebox.showinfo("Load Email", "Email loaded successfully.")
        highlight_phishing_keywords()
        live_check()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load file:\n{e}")

def export_result():
    result = result_text.get("1.0", tk.END).strip()
    if not result:
        messagebox.showwarning("Export Result", "No analysis result to export.")
        return
    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Analysis Result"
    )
    if not filepath:
        return
    try:
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(result)
        messagebox.showinfo("Export Result", f"Analysis result saved to:\n{filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file:\n{e}")

def live_check(event=None):
    subject = subject_entry.get()
    body = body_text.get("1.0", tk.END)
    if not subject.strip() and not body.strip():
        risk_label.config(text="Risk: N/A", fg="black")
        return

    is_phishing = predict_phishing_ml(subject, body)
    if is_phishing:
        risk_label.config(text="Risk: HIGH (Phishing Suspected)", fg="red")
    else:
        risk_label.config(text="Risk: LOW (Looks Safe)", fg="green")

def highlight_phishing_keywords(event=None):
    body_text.tag_remove("phish", "1.0", tk.END)
    body = body_text.get("1.0", tk.END).lower()

    for keyword in phishing_keywords:
        start = "1.0"
        while True:
            pos = body_text.search(keyword, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(keyword)}c"
            body_text.tag_add("phish", pos, end)
            start = end

    body_text.tag_config("phish", background="#ffcccc")

# === BUTTON BINDINGS (after functions) ===
history_listbox.bind("<<ListboxSelect>>", load_history_entry)
subject_entry.bind("<KeyRelease>", live_check)
body_text.bind("<KeyRelease>", lambda e: [live_check(), highlight_phishing_keywords()])
highlight_phishing_keywords()

window.mainloop()
