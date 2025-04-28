import json
import os
import random
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
from PIL import Image, ImageTk
import tkinter.simpledialog as simpledialog

# --- Global Variables ---
keywords = ["stupid", "dumb", "idiot", "moron", "retard", "dumbass", "idiotic", "you're dumb",
  "ugly", "fat", "fatty", "pig", "cow", "ugliness",
  "crazy", "psycho", "mental", "freak", "invalid", "error of nature",
  "worthless", "you're nothing", "nobody cares", "nobody loves you",
  "loser", "nobody likes you", "you're trash", "hopeless", "go away", "get lost",
  "kill", "die", "go to hell", "burn in hell", "kill yourself",
  "shit", "bullshit", 
  "douche", "douchebag", "scumbag", "jerk",
  "scum", "trash", "disgusting", "creep", "weirdo", "worthless piece",
  "shut up", "suck", "hate"]

# New supportive messages to respond when no bad words are detected
positive_responses = [
    "✅ Your message looks good! Thank you for being respectful.",
    "✅ All clear! Keep up the positive communication.",
    "✅ Great job! Your message is appropriate and kind.",
    "✅ No issues detected. Thanks for keeping our space friendly!",
    "✅ Message approved! You're helping create a better environment."
]

# New warning messages
warning_messages = [
    "⚠ Please be more mindful of your language.",
    "⚠ That's not very kind. Try rephrasing your message.",
    "⚠ We encourage respectful communication here.",
    "⚠ Let's keep things friendly and constructive."
]

# App settings (simplified)
app_settings = {
    "theme": "light",
    "max_warnings": 3,
    "auto_save": True,
    "check_strictness": "normal"  # can be "strict", "normal", "relaxed"
}

flagged_messages = []
user_warnings = {}
banned_users = set()
message_history = []
MAX_HISTORY = 100  # Maximum number of messages to keep in history

# Global app variable
app = None

# --- Functions ---
def load_data():
    """Load saved data from files if they exist"""
    global flagged_messages, user_warnings, banned_users, app_settings
    
    # Try to load flagged messages
    try:
        if os.path.exists("flagged_messages.json"):
            with open("flagged_messages.json", "r") as f:
                flagged_messages = json.load(f)
    except Exception as e:
        print(f"Failed to load flagged_messages.json: {e}")
    
    # Try to load user warnings
    try:
        if os.path.exists("user_warnings.json"):
            with open("user_warnings.json", "r") as f:
                user_warnings = json.load(f)
    except Exception as e:
        print(f"Failed to load user_warnings.json: {e}")
    
    # Try to load banned users
    try:
        if os.path.exists("banned_users.json"):
            with open("banned_users.json", "r") as f:
                banned_users = set(json.load(f))
    except Exception as e:
        print(f"Failed to load banned_users.json: {e}")

def check_keywords(message):
    """Check if message contains any keywords based on strictness setting"""
    found = []
    
    # Adjust the matching based on strictness level
    if app_settings["check_strictness"] == "strict":
        # In strict mode, also check for partial word matches
        for word in keywords:
            if word in message.lower():
                found.append(word)
    elif app_settings["check_strictness"] == "normal":
        # In normal mode, check for whole words or phrases
        msg_lower = message.lower()
        for word in keywords:
            if word in msg_lower.split() or word in msg_lower:
                found.append(word)
    else:  # relaxed mode
        # In relaxed mode, only exact matches count
        msg_tokens = message.lower().split()
        for word in keywords:
            if word in msg_tokens:
                found.append(word)
                
    return found

def log_message(user, message, bad_words):
    """Log a flagged message"""
    entry = {
        "user": user,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "detected_keywords": bad_words
    }
    flagged_messages.append(entry)
    
    if app_settings["auto_save"]:
        try:
            save_to_file("flagged_messages.json", flagged_messages)
            save_to_file("user_warnings.json", user_warnings)
            save_to_file("banned_users.json", list(banned_users))
        except Exception as e:
            messagebox.showerror("Error", f"Error saving data: {e}")

def add_to_history(user, message, status):
    """Add a message to the history"""
    entry = {
        "user": user,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "status": status  # "approved", "flagged", or "banned"
    }
    message_history.append(entry)
    
    # Keep history size manageable
    if len(message_history) > MAX_HISTORY:
        message_history.pop(0)
    
    update_history_display()

def update_history_display():
    """Update the message history display"""
    global app
    if app and hasattr(app, 'history_text'):
        app.history_text.config(state=tk.NORMAL)
        app.history_text.delete(1.0, tk.END)
        
        for entry in message_history[-10:]:  # Show last 10 messages
            timestamp = entry["timestamp"]
            user = entry["user"]
            status_icon = "✅" if entry["status"] == "approved" else "🚨" if entry["status"] == "flagged" else "🚫"
            
            app.history_text.insert(tk.END, f"[{timestamp}] {status_icon} {user}: {entry['message'][:30]}...\n")
        
        app.history_text.config(state=tk.DISABLED)
        app.history_text.see(tk.END)  # Scroll to the end

def save_to_file(filename, data):
    """Save data to a file"""
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Failed to save {filename}: {e}")

def generate_report():
    """Generate a report of keyword occurrences"""
    report = {"keywords": {}, "users": {}}
    
    # Count keyword occurrences
    for entry in flagged_messages:
        for word in entry["detected_keywords"]:
            report["keywords"][word] = report["keywords"].get(word, 0) + 1
        
        # Count per user
        user = entry["user"]
        report["users"][user] = report["users"].get(user, 0) + 1
    
    try:
        save_to_file("report.json", report)
    except Exception as e:
        print("Error saving report:", e)
    
    return report

def clear_flagged_messages():
    """Clear all flagged messages after confirmation"""
    if messagebox.askyesno("Confirm", "Are you sure you want to clear all flagged messages?"):
        flagged_messages.clear()
        save_to_file("flagged_messages.json", flagged_messages)
        messagebox.showinfo("Success", "All flagged messages have been cleared")

def apply_theme():
    """Apply the selected theme"""
    global app
    if app is None:
        # Skip if app isn't initialized yet
        return
        
    if app_settings["theme"] == "dark":
        app.root.configure(bg="#2E2E2E")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2E2E2E")
        style.configure("TLabel", background="#2E2E2E", foreground="white")
        style.configure("TButton", background="#555555", foreground="white")
        
        # Update text widgets
        text_widgets = [app.output_text, app.history_text]
        for widget in text_widgets:
            widget.config(bg="#3E3E3E", fg="white", insertbackground="white")
    else:
        app.root.configure(bg="#F0F0F0")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#F0F0F0")
        style.configure("TLabel", background="#F0F0F0", foreground="black")
        style.configure("TButton", background="#E0E0E0", foreground="black")
        
        # Update text widgets
        text_widgets = [app.output_text, app.history_text]
        for widget in text_widgets:
            widget.config(bg="white", fg="black", insertbackground="black")

def process_message():
    """Process and analyze a submitted message"""
    global app
    user = app.username_entry.get().strip()
    msg = app.message_entry.get().strip()

    if not user or not msg:
        messagebox.showwarning("Input Error", "Both username and message are required.")
        return

    if user in banned_users:
        app.output_text.insert(tk.END, f"🚫 {user}, you are banned from using this app.\n\n")
        app.output_text.see(tk.END)
        add_to_history(user, msg, "banned")
        return

    if msg.lower() == "exit":
        show_final_report()
        return

    bad_words = check_keywords(msg)

    if bad_words:
        app.output_text.insert(tk.END, f"🚨 BEEP BOOP! Bad words detected! 🚨\n")
        app.output_text.insert(tk.END, f"Found: {', '.join(bad_words)}\n")
        app.output_text.insert(tk.END, "💾 Adding this to my 'naughty messages' collection!\n")
        
        log_message(user, msg, bad_words)
        add_to_history(user, msg, "flagged")

        user_warnings[user] = user_warnings.get(user, 0) + 1

        if user_warnings[user] >= app_settings["max_warnings"]:
            app.output_text.insert(tk.END, f"\n🚫 {user}, you've received {app_settings['max_warnings']} warnings. You are now banned from this app.\n\n")
            banned_users.add(user)
            save_to_file("banned_users.json", list(banned_users))
        else:
            warnings_left = app_settings["max_warnings"] - user_warnings[user]
            app.output_text.insert(tk.END, f"⚠ Warning {user_warnings[user]} of {app_settings['max_warnings']}. {random.choice(warning_messages)}\n")
            app.output_text.insert(tk.END, f"You have {warnings_left} warning(s) left before you're banned.\n\n")
    else:
        response = random.choice(positive_responses)
        app.output_text.insert(tk.END, f"{response}\n\n")
        add_to_history(user, msg, "approved")

    app.message_entry.delete(0, tk.END)
    app.output_text.see(tk.END)

def generate_history_statistics():
    """Generate statistics from the message history"""
    stats = {
        "total_messages": len(message_history),
        "approved_messages": 0,
        "flagged_messages": 0,
        "banned_messages": 0,
        "users": {},
        "active_hours": {}
    }
    
    for entry in message_history:
        # Count message types
        if entry["status"] == "approved":
            stats["approved_messages"] += 1
        elif entry["status"] == "flagged":
            stats["flagged_messages"] += 1
        elif entry["status"] == "banned":
            stats["banned_messages"] += 1
        
        # Count per user
        user = entry["user"]
        if user not in stats["users"]:
            stats["users"][user] = {"total": 0, "approved": 0, "flagged": 0, "banned": 0}
        
        stats["users"][user]["total"] += 1
        stats["users"][user][entry["status"]] += 1
        
        # Track activity hours
        hour = entry["timestamp"].split(":")[0]
        stats["active_hours"][hour] = stats["active_hours"].get(hour, 0) + 1
    
    return stats

def show_history_statistics():
    """Show statistics from the message history"""
    global app
    stats = generate_history_statistics()
    
    stats_window = tk.Toplevel(app.root)
    stats_window.title("Message History Statistics")
    stats_window.geometry("600x500")
    
    notebook = ttk.Notebook(stats_window)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Overview tab
    overview_frame = ttk.Frame(notebook)
    notebook.add(overview_frame, text="Overview")
    
    overview_text = scrolledtext.ScrolledText(overview_frame, width=70, height=20)
    overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    overview_text.insert(tk.END, "📊 Message History Statistics:\n\n")
    overview_text.insert(tk.END, f"Total Messages: {stats['total_messages']}\n")
    overview_text.insert(tk.END, f"✅ Approved Messages: {stats['approved_messages']} ({stats['approved_messages']/max(1, stats['total_messages'])*100:.1f}%)\n")
    overview_text.insert(tk.END, f"🚨 Flagged Messages: {stats['flagged_messages']} ({stats['flagged_messages']/max(1, stats['total_messages'])*100:.1f}%)\n")
    overview_text.insert(tk.END, f"🚫 Messages from Banned Users: {stats['banned_messages']} ({stats['banned_messages']/max(1, stats['total_messages'])*100:.1f}%)\n\n")
    
    overview_text.insert(tk.END, f"Number of Users: {len(stats['users'])}\n")
    overview_text.insert(tk.END, f"Currently Banned Users: {len(banned_users)}\n\n")
    
    if stats["active_hours"]:
        most_active_hour = max(stats["active_hours"].items(), key=lambda x: x[1])[0]
        overview_text.insert(tk.END, f"Most Active Hour: {most_active_hour}:00\n\n")
    
    # Users tab
    users_frame = ttk.Frame(notebook)
    notebook.add(users_frame, text="User Statistics")
    
    users_text = scrolledtext.ScrolledText(users_frame, width=70, height=20)
    users_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    users_text.insert(tk.END, "👤 Users Activity:\n\n")
    if stats["users"]:
        # Sort users by total message count
        sorted_users = sorted(stats["users"].items(), key=lambda x: x[1]["total"], reverse=True)
        for user, user_stats in sorted_users:
            users_text.insert(tk.END, f"• {user}:\n")
            users_text.insert(tk.END, f"  Total Messages: {user_stats['total']}\n")
            users_text.insert(tk.END, f"  ✅ Approved: {user_stats['approved']} ({user_stats['approved']/max(1, user_stats['total'])*100:.1f}%)\n")
            users_text.insert(tk.END, f"  🚨 Flagged: {user_stats['flagged']} ({user_stats['flagged']/max(1, user_stats['total'])*100:.1f}%)\n")
            users_text.insert(tk.END, f"  🚫 After Ban: {user_stats['banned']} ({user_stats['banned']/max(1, user_stats['total'])*100:.1f}%)\n")
            users_text.insert(tk.END, f"  Ban Status: {'🚫 Banned' if user in banned_users else '✅ Active'}\n\n")
    else:
        users_text.insert(tk.END, "No user activity recorded yet.\n")
    
    # Action buttons
    buttons_frame = ttk.Frame(stats_window)
    buttons_frame.pack(fill=tk.X, padx=10, pady=10)
    
    ttk.Button(buttons_frame, text="Close", command=stats_window.destroy).pack(side=tk.RIGHT, padx=5)

def show_final_report():
    """Show the final report of flagged keywords and users"""
    global app
    report = generate_report()
    
    report_window = tk.Toplevel(app.root)
    report_window.title("Cybersecurity Report")
    report_window.geometry("600x500")
    
    notebook = ttk.Notebook(report_window)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Keywords tab
    keywords_frame = ttk.Frame(notebook)
    notebook.add(keywords_frame, text="Keywords")
    
    keywords_text = scrolledtext.ScrolledText(keywords_frame, width=70, height=20)
    keywords_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    keywords_text.insert(tk.END, "📊 Keywords Report:\n\n")
    if report["keywords"]:
        # Sort keywords by frequency
        sorted_keywords = sorted(report["keywords"].items(), key=lambda x: x[1], reverse=True)
        for word, count in sorted_keywords:
            keywords_text.insert(tk.END, f"• '{word}': {count} time(s)\n")
    else:
        keywords_text.insert(tk.END, "No keywords detected in messages.\n")
    
    # Users tab
    users_frame = ttk.Frame(notebook)
    notebook.add(users_frame, text="Users")
    
    users_text = scrolledtext.ScrolledText(users_frame, width=70, height=20)
    users_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    users_text.insert(tk.END, "👤 Users Report:\n\n")
    if report["users"]:
        # Sort users by frequency
        sorted_users = sorted(report["users"].items(), key=lambda x: x[1], reverse=True)
        for user, count in sorted_users:
            users_text.insert(tk.END, f"• {user}: {count} flagged message(s)\n")
    else:
        users_text.insert(tk.END, "No users have sent flagged messages.\n")
    
    # Banned users tab
    banned_frame = ttk.Frame(notebook)
    notebook.add(banned_frame, text="Banned Users")
    
    banned_text = scrolledtext.ScrolledText(banned_frame, width=70, height=20)
    banned_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    banned_text.insert(tk.END, "🚫 Banned Users:\n\n")
    if banned_users:
        for user in banned_users:
            banned_text.insert(tk.END, f"• {user}\n")
    else:
        banned_text.insert(tk.END, "No users are currently banned.\n")
    
    # Action buttons
    buttons_frame = ttk.Frame(report_window)
    buttons_frame.pack(fill=tk.X, padx=10, pady=10)
    
    ttk.Button(buttons_frame, text="Clear Data", command=clear_flagged_messages).pack(side=tk.LEFT, padx=5)
    ttk.Button(buttons_frame, text="Close", command=report_window.destroy).pack(side=tk.RIGHT, padx=5)

# --- Main Application Class ---
class CyberSecurityApp:
    def __init__(self, root):
        self.root = root
        root.title("🛡 Cybersecurity Detector AI 2.0")
        root.geometry("800x600")
        root.minsize(600, 500)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Message Detector")
        
        # Create a title frame
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=10)
        
        title_label = ttk.Label(title_frame, text="Cybersecurity Message Detector", font=("Arial", 16, "bold"))
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Type your message to check if it's safe and friendly")
        subtitle_label.pack()
        
        # Create input frame
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(input_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = ttk.Entry(input_frame, width=30)
        self.username_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.message_entry = ttk.Entry(input_frame, width=50)
        self.message_entry.grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        input_frame.columnconfigure(1, weight=1)
        
        # Bind Enter key to submit
        self.message_entry.bind("<Return>", lambda event: process_message())
        
        # Create button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(button_frame, text="Submit Message", command=process_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Report", command=show_final_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="History Stats", command=show_history_statistics).pack(side=tk.LEFT, padx=5)
        
        # Create output frame with tabs
        output_notebook = ttk.Notebook(self.main_frame)
        output_notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Results tab
        results_frame = ttk.Frame(output_notebook)
        output_notebook.add(results_frame, text="Results")
        
        # Output text with colored background
        self.output_text = scrolledtext.ScrolledText(results_frame, width=70, height=15, wrap=tk.WORD, 
                                                    bg="#E6F7FF", fg="#00366D")  # Light blue background with dark blue text
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_text.insert(tk.END, "🤖 Welcome to the Cybersecurity Message Detector 2.0!\n")
        self.output_text.insert(tk.END, "I'm here to help keep communication safe and friendly.\n\n")
        self.output_text.insert(tk.END, "Type a message and press 'Submit' to check if it follows our community guidelines.\n\n")
        
        # History tab
        history_frame = ttk.Frame(output_notebook)
        output_notebook.add(history_frame, text="Message History")
        
        self.history_text = scrolledtext.ScrolledText(history_frame, width=70, height=15, wrap=tk.WORD, 
                                                    bg="#F7FFE6", fg="#366D00")  # Light green background with dark green text
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.history_text.insert(tk.END, "Recent messages will appear here.\n")
        self.history_text.config(state=tk.DISABLED)
        
        # Status bar
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        status_label = ttk.Label(status_frame, text="Ready to detect inappropriate messages", relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X, side=tk.LEFT, padx=10)
        
        keyword_count = ttk.Label(status_frame, text=f"Keywords monitored: {len(keywords)}", relief=tk.SUNKEN)
        keyword_count.pack(side=tk.RIGHT, padx=10)
        
        # Help tab
        self.help_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.help_frame, text="Help & Info")
        
        help_text = scrolledtext.ScrolledText(self.help_frame, width=70, height=20, wrap=tk.WORD, 
                                            bg="#FFF0F5", fg="#8B0000")  # Light pink background with dark red text
        help_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        help_content = """
        # 🛡 Cybersecurity Message Detector 2.0 - Help Guide
        
        ## What does this app do?
        This app helps detect and filter inappropriate messages by checking them against a list of keywords that might indicate harmful content.
        
        ## How to use:
        1. Enter your username in the "Username" field
        2. Type your message in the "Message" field
        3. Click "Submit Message" to check if your message is appropriate
        
        ## Warning System:
        - If your message contains inappropriate content, you'll receive a warning
        - After receiving 3 warnings, you will be banned from using the app
        - Bans are saved between sessions
        
        ## Features:
        - Real-time message checking
        - Message history tracking
        - Generate reports of flagged messages
        - History statistics generator
        
        ## Tips:
        - Be respectful and kind in your messages
        - If you're banned, you won't be able to send any more messages
        - Type "exit" in the message field to generate a final report

        ## About:
        Cybersecurity Message Detector 2.0 was created to help maintain a safe and friendly communication environment.
        """
        
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

# --- Entry Point ---
if __name__ == "__main__":
    # Load saved data
    load_data()
    
    # Create the main app window
    root = tk.Tk()
    app = CyberSecurityApp(root)
    
    # Start the app
    root.mainloop()
