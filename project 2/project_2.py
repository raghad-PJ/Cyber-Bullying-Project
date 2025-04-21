import json
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

# --- Global Variables ---
keywords = ["stupid", "ugly", "hate", "kill", "dumb", "worthless", "loser", "idiot", "shut up", "nobody likes you"]
flagged_messages = []
user_warnings = {}
MAX_WARNINGS = 3
banned_users = set()

# --- Functions ---
def check_keywords(message):
    found = []
    for word in keywords:
        if word in message.lower():
            found.append(word)
    return found

def log_message(user, message, bad_words):
    entry = {
        "user": user,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "detected_keywords": bad_words
    }
    flagged_messages.append(entry)
    try:
        save_to_file("flagged_messages.json", flagged_messages)
    except Exception as e:
        messagebox.showerror("Error", f"Error saving flagged message: {e}")

def save_to_file(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Failed to save {filename}: {e}")

def generate_report():
    report = {}
    for entry in flagged_messages:
        for word in entry["detected_keywords"]:
            report[word] = report.get(word, 0) + 1
    try:
        save_to_file("report.json", report)
    except Exception as e:
        print("Error saving report:", e)
    return report

def process_message():
    user = username_entry.get().strip()
    msg = message_entry.get().strip()

    if not user or not msg:
        messagebox.showwarning("Input Error", "Both username and message are required.")
        return

    if user in banned_users:
        output_text.insert(tk.END, f"🚫 {user}, you are banned from using this app.\n\n")
        return

    if msg.lower() == "exit":
        show_final_report()
        return

    bad_words = check_keywords(msg)

    if bad_words:
        output_text.insert(tk.END, f"🚨 BEEP BOOP! Mean words detected! 🚨 Found: {bad_words}\n")
        output_text.insert(tk.END, "💾 Adding this to my 'naughty messages' collection!\n")
        log_message(user, msg, bad_words)

        user_warnings[user] = user_warnings.get(user, 0) + 1

        if user_warnings[user] >= MAX_WARNINGS:
            output_text.insert(tk.END, f"\n🚫 {user}, you've received 3 warnings. You are now banned from this app.\n\n")
            banned_users.add(user)
        else:
            warnings_left = MAX_WARNINGS - user_warnings[user]
            output_text.insert(tk.END, f"⚠ Warning {user_warnings[user]} of {MAX_WARNINGS}. Stop sending harmful messages.\n")
            output_text.insert(tk.END, f"You have {warnings_left} warning(s) left before you're banned.\n\n")
    else:
        output_text.insert(tk.END, "✅ Your message has been reviewed and found to be appropriate.\n\n")

    message_entry.delete(0, tk.END)

def show_final_report():
    report = generate_report()
    report_text = "📊 Final Report:\n"
    for word, count in report.items():
        report_text += f"- {word}: {count} times\n"
    messagebox.showinfo("Report", report_text)

# --- GUI Setup ---
def launch_gui():
    global username_entry, message_entry, output_text

    root = tk.Tk()
    root.title("Cybersecurity Detector AI")
    root.geometry("600x500")

    tk.Label(root, text="Username:").pack(pady=5)
    username_entry = tk.Entry(root, width=40)
    username_entry.pack()

    tk.Label(root, text="Message:").pack(pady=5)
    message_entry = tk.Entry(root, width=60)
    message_entry.pack()

    tk.Button(root, text="Submit Message", command=process_message).pack(pady=10)

    output_text = scrolledtext.ScrolledText(root, width=70, height=20, wrap=tk.WORD)
    output_text.pack(pady=10)

    root.mainloop()

# --- Entry Point ---
if __name__ == "__main__":
    launch_gui()
