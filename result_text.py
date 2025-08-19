import tkinter as tk
from tkinter import scrolledtext

window = tk.Tk()

result_text = scrolledtext.ScrolledText(window, width=80, height=15)
result_text.pack()

def analyze_email():
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, "Hello from analyze_email!")
    result_text.config(state=tk.DISABLED)

button = tk.Button(window, text="Analyze", command=analyze_email)
button.pack()

window.mainloop()
