import os
import time
import getpass
import psutil
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
import csv
import json
from fpdf import FPDF
import subprocess

root = tk.Tk()
root.title("System Transparency Log Viewer")
root.geometry("450x350")
root.configure(bg="#212121")
root.minsize(350, 300)
root.resizable(True, True)

title_font = tkfont.Font(family="Helvetica", size=16, weight="bold")
label_font = tkfont.Font(family="Arial", size=13, weight="bold")

dialog_open = False
auto_refresh = False
current_log_info = {}

def create_custom_dialog(title, content, is_scrollable=False, enable_export=False, is_log_view=False):
    global dialog_open
    if dialog_open:
        messagebox.showinfo("Window Already Open", "Please close the open window before opening another.")
        return

    dialog_open = True
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry("750x550")
    dialog.configure(bg="#333333")
    dialog.resizable(True, True)

    def on_close():
        global dialog_open, auto_refresh
        dialog_open = False
        auto_refresh = False
        dialog.destroy()

    dialog.protocol("WM_DELETE_WINDOW", on_close)

    frame_inner = tk.Frame(dialog, bg="#333333")
    frame_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    if is_scrollable:
        search_var = tk.StringVar()
        if is_log_view:
            search_entry = tk.Entry(frame_inner, textvariable=search_var, font=("Arial", 11),
                                    bg="#424242", fg="white", insertbackground="white", width=40)
            search_entry.pack(pady=5)

        log_text = scrolledtext.ScrolledText(
            frame_inner, wrap=tk.WORD, height=20,
            font=("Consolas", 10), bg="#1e1e1e", fg="white",
            insertbackground="white"
        )
        log_text.insert(tk.END, content)
        log_text.config(state=tk.DISABLED)
        log_text.pack(pady=5, fill=tk.BOTH, expand=True)

        def highlight_keywords():
            log_text.tag_remove("highlight", "1.0", tk.END)
            keyword = search_var.get()
            if not keyword:
                return
            start = "1.0"
            while True:
                start = log_text.search(keyword, start, stopindex=tk.END, nocase=True)
                if not start:
                    break
                end = f"{start}+{len(keyword)}c"
                log_text.tag_add("highlight", start, end)
                log_text.tag_config("highlight", background="#ff7043")
                start = end

        def on_search(*args):
            log_text.config(state=tk.NORMAL)
            log_text.delete("1.0", tk.END)
            logs = read_logs(current_log_info["path"], filter_keyword=search_var.get(),
                             max_lines=current_log_info["max_lines"])
            log_text.insert(tk.END, "\n".join(logs))
            highlight_keywords()
            log_text.config(state=tk.DISABLED)

        if is_log_view:
            search_var.trace_add("write", on_search)

        def export_logs():
            file_type = messagebox.askquestion("Export Format", "Choose the format:\nYes for CSV, No for JSON.")
            if file_type == "yes":
                export_to_csv(log_text.get("1.0", tk.END))
            else:
                export_to_json(log_text.get("1.0", tk.END))

        def export_to_csv(content):
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if file_path:
                lines = content.strip().split("\n")
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    for line in lines:
                        writer.writerow([line])
                messagebox.showinfo("Export Successful", f"Logs exported to CSV at '{file_path}'")

        def export_to_json(content):
            file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
            if file_path:
                lines = content.strip().split("\n")
                log_data = {"logs": lines}
                with open(file_path, "w", encoding="utf-8") as json_file:
                    json.dump(log_data, json_file, indent=4)
                messagebox.showinfo("Export Successful", f"Logs exported to JSON at '{file_path}'")

        def export_to_pdf(content):
            file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
            if file_path:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                lines = content.strip().split("\n")
                for line in lines:
                    pdf.multi_cell(0, 10, line)
                pdf.output(file_path)
                messagebox.showinfo("Export Successful", f"Logs exported to PDF at '{file_path}'")

        if is_log_view and enable_export:
            export_button = tk.Button(frame_inner, text="Export Logs", command=export_logs,
                                      font=("Arial", 10), bg="#4caf50", fg="white",
                                      activebackground="#388e3c")
            export_button.pack(pady=5)

        if is_log_view:
            refresh_var = tk.IntVar()

            def toggle_auto_refresh():
                global auto_refresh
                auto_refresh = bool(refresh_var.get())
                if auto_refresh:
                    refresh_logs()

            refresh_check = tk.Checkbutton(
                frame_inner, text="Auto-Refresh Logs", variable=refresh_var,
                bg="#333333", fg="white", activebackground="#333333",
                selectcolor="#333333", command=toggle_auto_refresh
            )
            refresh_check.pack(pady=3)

    else:
        label = tk.Label(frame_inner, text=content, font=("Arial", 11), bg="#333333",
                         fg="white", justify=tk.LEFT, anchor="w")
        label.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    close_button = tk.Button(
        dialog, text="Close", font=("Helvetica", 12), command=on_close,
        bg="#d32f2f", fg="white", activebackground="#b71c1c", activeforeground="white"
    )
    close_button.pack(pady=10)

def read_logs(file_path, filter_keyword=None, max_lines=100):
    if not file_path:
        return ["Invalid file path."]
    if not os.path.exists(file_path):
        return [f"Log file not found: {file_path}"]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            lines = file.readlines()[-max_lines:]
        if filter_keyword:
            lines = [line for line in lines if filter_keyword.lower() in line.lower()]
        return lines if lines else [f"No entries found in {file_path} with keyword '{filter_keyword}'"]
    except Exception as e:
        return [f"Error reading file: {e}"]

import subprocess

def read_command_output(command, max_lines=100, filter_keyword=None):
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        out, err = proc.communicate(timeout=5)
        if err:
            # Show error if dmesg fails (e.g., due to permissions)
            return [f"Error: {err.strip()}"]
        lines = out.strip().split('\n')[-max_lines:]
        if filter_keyword:
            lines = [line for line in lines if filter_keyword.lower() in line.lower()]
        return lines if lines else [f"No entries found with keyword '{filter_keyword}'" if filter_keyword else "No log entries found."]
    except Exception as e:
        return [f"Error running command: {e}"]

def show_kernel_logs():
    logs = read_command_output("dmesg --ctime", max_lines=150)
    # For demonstration, just print the logs
    print("\n".join(logs))

if _name_ == "_main_":
    show_kernel_logs()


def show_system_stats():
    user = getpass.getuser()
    all_users = psutil.users()
    user_process_count = {}
    for proc in psutil.process_iter(['username']):
        uname = proc.info['username']
        if uname:
            user_process_count[uname] = user_process_count.get(uname, 0) + 1
    cpu_percent = psutil.cpu_percent(interval=1)
    io1 = psutil.disk_io_counters()
    time.sleep(1)
    io2 = psutil.disk_io_counters()
    read_speed = (io2.read_bytes - io1.read_bytes) / 1024
    write_speed = (io2.write_bytes - io1.write_bytes) / 1024

    stats_text = f"""
Logged-in User: {user}
Total Users Logged In: {len(all_users)}
CPU Usage: {cpu_percent:.2f}%
Disk Read Speed: {read_speed:.2f} KB/s
Disk Write Speed: {write_speed:.2f} KB/s
Total Unique Users with Processes: {len(user_process_count)}
"""
    for uname, count in user_process_count.items():
        stats_text += f"Processes by {uname}: {count}\n"

    create_custom_dialog("System Stats", stats_text, is_scrollable=True,
                         enable_export=False, is_log_view=False)

def show_process_monitor():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except psutil.NoSuchProcess:
            pass

    processes = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:10]

    process_text = "Top 10 CPU Consuming Processes:\n\n"
    for proc in processes:
        process_text += f"PID: {proc['pid']} - {proc['name']} - CPU: {proc['cpu_percent']}% - Memory: {proc['memory_percent']}%\n"

    create_custom_dialog("Real-Time Process Monitor", process_text, is_scrollable=True, enable_export=False, is_log_view=False)

def show_logs(title, file_path, keyword=None, max_lines=100):
    global current_log_info
    current_log_info = {
        "title": title,
        "path": file_path,
        "keyword": keyword,
        "max_lines": max_lines
    }
    logs = read_logs(file_path, filter_keyword=keyword, max_lines=max_lines)
    log_content = "\n".join(logs)
    create_custom_dialog(title, log_content, is_scrollable=True, enable_export=True, is_log_view=True)

def show_auth_logs():
    file_path = "/var/log/auth.log"
    show_logs("Authentication Logs", file_path, max_lines=150)

def show_kernel_logs():
    logs = read_command_output("dmesg --ctime", max_lines=150)
    content = "\n".join(logs)
    create_custom_dialog("Kernel Logs (dmesg)", content, is_scrollable=True, enable_export=True, is_log_view=True)

def show_application_logs():
    apache_path = "/var/log/apache2/access.log"
    if not os.path.exists(apache_path):
        apache_path = "/var/log/httpd/access_log"
    if not os.path.exists(apache_path):
        messagebox.showinfo("Application Logs", "Apache log file not found on this system.")
        return
    show_logs("Application Logs - Apache Access", apache_path, max_lines=150)

def show_security_alerts():
    file_path = "/var/log/auth.log"
    keywords = ["warning", "error", "fail", "denied", "unauthorized"]
    all_lines = []
    if not os.path.exists(file_path):
        create_custom_dialog("Security Alerts", f"Log file not found: {file_path}", False, False, False)
        return
    try:
        with open(file_path, "r", encoding='utf-8', errors='replace') as f:
            for line in f:
                if any(keyword in line.lower() for keyword in keywords):
                    all_lines.append(line)
        if not all_lines:
            all_lines = ["No recent security alerts found."]
    except Exception as e:
        all_lines = [f"Error reading security alerts: {e}"]

    content = "".join(all_lines[-150:])
    create_custom_dialog("Security Alerts", content, is_scrollable=True, enable_export=True, is_log_view=True)

def show_cron_logs():
    cron_paths = ["/var/log/cron.log", "/var/log/cron", "/var/log/syslog"]
    path_found = None
    for p in cron_paths:
        if os.path.exists(p):
            path_found = p
            break
    if not path_found:
        messagebox.showinfo("Cron Job Logs", "Cron log file not found on this system.")
        return
    show_logs("Cron Job Logs", path_found, keyword="cron", max_lines=150)

def show_boot_logs():
    command = "journalctl -b --no-pager"
    logs = read_command_output(command, max_lines=200)
    if "Error" in logs[0] or not logs:
        boot_log_path = "/var/log/boot.log"
        if os.path.exists(boot_log_path):
            show_logs("System Boot Logs", boot_log_path, max_lines=150)
        else:
            messagebox.showinfo("Boot Logs", "No boot logs available on this system.")
    else:
        content = "\n".join(logs)
        create_custom_dialog("System Boot Logs", content, is_scrollable=True, enable_export=True, is_log_view=True)

def show_custom_log():
    file_path = filedialog.askopenfilename(title="Select a log file to open",
                                           filetypes=[("Log Files", ".log *.txt *.out"), ("All Files", ".*")])
    if not file_path:
        return
    show_logs(f"Custom Log - {os.path.basename(file_path)}", file_path, max_lines=200)

def show_failed_login_attempts():
    file_path = "/var/log/auth.log"
    if not os.path.exists(file_path):
        messagebox.showinfo("Failed Login Attempts", "Authentication log file not found.")
        return
    failed_keywords = ["failed", "invalid", "authentication failure", "error"]
    failed_lines = []
    try:
        with open(file_path, "r", encoding='utf-8', errors='replace') as f:
            for line in f:
                if any(keyword in line.lower() for keyword in failed_keywords):
                    failed_lines.append(line)
        if not failed_lines:
            failed_lines = ["No failed login attempts found in recent logs."]
    except Exception as e:
        failed_lines = [f"Error reading failed login attempts: {e}"]
    content = "".join(failed_lines[-150:])
    create_custom_dialog("Failed Login Attempts", content, is_scrollable=True, enable_export=True, is_log_view=True)

# Responsive Main Interface with center alignment and max width

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Container frame to center content horizontally and vertically
container_frame = tk.Frame(root, bg="#212121")
container_frame.grid(row=0, column=0, sticky="nsew")
container_frame.grid_rowconfigure(0, weight=1)
container_frame.grid_columnconfigure(0, weight=1)

# Canvas and Vertical Scrollbar inside container frame
canvas = tk.Canvas(container_frame, bg="#212121", highlightthickness=0)
vsb = tk.Scrollbar(container_frame, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=vsb.set)

vsb.grid(row=0, column=1, sticky="ns")
canvas.grid(row=0, column=0, sticky="nsew")

# Frame inside canvas to hold the actual content, with limited max width
scrollable_frame = tk.Frame(canvas, bg="#212121", width=400)
scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

def on_mousewheel(event):
    if os.name == 'nt':  # Windows
        delta = int(-1*(event.delta/120))
    else:  # MacOS or Linux
        delta = int(-1*(event.delta))
    canvas.yview_scroll(delta, "units")

canvas.bind_all("<MouseWheel>", on_mousewheel)
canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))  # linux scroll up
canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))   # linux scroll down

# Center the scrollable frame within the canvas horizontally
def resize_canvas(event):
    canvas_width = event.width
    desired_width = min(400, canvas_width)
    canvas.itemconfig(canvas_window, width=desired_width)

canvas.bind("<Configure>", resize_canvas)

tk.Label(
    scrollable_frame, text="System Transparency Log Viewer",
    font=title_font, bg="#212121", fg="#fbc02d"
).pack(pady=(20,10), fill='x')

def create_clickable_label(text, command):
    label = tk.Label(
        scrollable_frame, text=text, font=label_font,
        bg="#212121", fg="#64b5f6", cursor="hand2"
    )
    label.pack(pady=10, fill='x')

    def on_enter(e): label.config(fg="#90caf9", underline=1)
    def on_leave(e): label.config(fg="#64b5f6", underline=0)

    label.bind("<Enter>", on_enter)
    label.bind("<Leave>", on_leave)
    label.bind("<Button-1>", lambda e: command())

create_clickable_label("View System Logs",
                       lambda: show_logs("System Logs", "/var/log/syslog", max_lines=100))

create_clickable_label("View Sudo Logs",
                       lambda: show_logs("Sudo Logs", "/var/log/auth.log", keyword="sudo", max_lines=50))

create_clickable_label("View Authentication Logs", show_auth_logs)

create_clickable_label("View Kernel Logs (dmesg)", show_kernel_logs)

create_clickable_label("View Application Logs (Apache Access)", show_application_logs)

create_clickable_label("View Security Alerts", show_security_alerts)

create_clickable_label("View Cron Job Logs", show_cron_logs)

create_clickable_label("View System Boot Logs", show_boot_logs)

create_clickable_label("Open Custom Log File", show_custom_log)

create_clickable_label("View Failed Login Attempts", show_failed_login_attempts)

create_clickable_label("View System Stats", show_system_stats)

create_clickable_label("Real-Time Process Monitor", show_process_monitor)

create_clickable_label("Exit", root.destroy)

root.mainloop()
