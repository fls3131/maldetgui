import tkinter as tk
from tkinter import scrolledtext, filedialog, simpledialog, messagebox, Menu
from tkinter import ttk
import subprocess
import threading
import queue
import os
import signal

class MaldetGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Maldet Scanner GUI")
        self.root.configure(bg="#2E2E2E")

        # Set dark theme colors
        self.bg_color = "#2E2E2E"
        self.fg_color = "#FFFFFF"
        self.btn_bg = "#555555"
        self.btn_fg = "#FFFFFF"
        self.entry_bg = "#3E3E3E"
        self.entry_fg = "#FFFFFF"
        self.text_bg = "#1E1E1E"
        self.text_fg = "#00FF00"

        # Store sudo password
        self.sudo_password = None

        # Create menu
        self.menu = Menu(root, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        root.config(menu=self.menu)
        
        self.about_menu = Menu(self.menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        self.menu.add_cascade(label="About", menu=self.about_menu)
        self.about_menu.add_command(label="About Software", command=self.show_about)

        # GUI Elements
        self.label = tk.Label(root, text="Select Directory to Scan:", bg=self.bg_color, fg=self.fg_color)
        self.label.pack(pady=5)

        self.dir_entry = tk.Entry(root, width=50, bg=self.entry_bg, fg=self.entry_fg, insertbackground=self.fg_color)
        self.dir_entry.pack(pady=5)

        self.browse_btn = tk.Button(root, text="Browse", command=self.browse_directory, bg=self.btn_bg, fg=self.btn_fg)
        self.browse_btn.pack(pady=5)

        self.button_frame = tk.Frame(root, bg=self.bg_color)
        self.button_frame.pack(pady=5)

        self.scan_btn = tk.Button(self.button_frame, text="Start Scan", command=self.start_scan, bg=self.btn_bg, fg=self.btn_fg)
        self.scan_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = tk.Button(self.button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, bg=self.btn_bg, fg=self.btn_fg)
        self.stop_btn.grid(row=0, column=1, padx=5)

        self.save_btn = tk.Button(self.button_frame, text="Save Output", command=self.save_output, state=tk.DISABLED, bg=self.btn_bg, fg=self.btn_fg)
        self.save_btn.grid(row=0, column=2, padx=5)

        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='indeterminate')

        self.output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20, bg=self.text_bg, fg=self.text_fg, insertbackground=self.fg_color)
        self.output_text.pack(pady=10)

        self.queue = queue.Queue()
        self.running = False
        self.process = None
        self.scan_stopped = False

        self.root.after(100, self.process_queue)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About Software")
        about_window.configure(bg=self.bg_color)
        about_text = "Maldet Scanner GUI\nVersion 1.0\nDeveloped by Fabio Schmit\nContact: hostmaster@bithostel.com.br\nWebsite: https://bithostel.com.br\n\nThis tool provides a graphical interface for Maldet, allowing users to scan directories easily."
        tk.Label(about_window, text=about_text, padx=20, pady=20, justify=tk.LEFT, bg=self.bg_color, fg=self.fg_color).pack()

    def start_scan(self):
        directory = self.dir_entry.get().strip()
        if not directory:
            self.queue.put("Please select a directory first.\n")
            return

        if not self.sudo_password:
            self.sudo_password = self.prompt_sudo_password()
            if not self.sudo_password:
                self.queue.put("Sudo password required. Scan aborted.\n")
                return

        if not self.running:
            self.running = True
            self.scan_stopped = False
            self.queue.put(f"Starting scan on: {directory}\n")

            self.progress.pack(pady=5)
            self.progress.start(10)

            self.scan_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.save_btn.config(state=tk.DISABLED)

            threading.Thread(target=self.run_maldet, args=(directory,), daemon=True).start()

    def run_maldet(self, directory):
        command = ["sudo", "-S", "/usr/local/sbin/maldet", "-a", directory]
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid
            )
        except Exception as e:
            self.queue.put(f"Failed to start maldet: {e}\n")
            self.running = False
            self.root.after(0, self.reset_buttons)
            return

        self.process.stdin.write(self.sudo_password + "\n")
        self.process.stdin.flush()

        for line in iter(self.process.stdout.readline, ""):
            self.queue.put(line)
            if not self.running:
                break
        self.process.stdout.close()
        self.process.wait()

        if not self.scan_stopped:
            self.queue.put("\nScan completed.\n")

        self.running = False
        self.root.after(0, self.reset_buttons)

    def stop_scan(self):
        if self.process and self.running:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.queue.put("\nScan stopped by user.\n")
            self.scan_stopped = True
            self.running = False
            self.reset_buttons()

    def reset_buttons(self):
        self.progress.stop()
        self.progress.pack_forget()
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.NORMAL)

    def save_output(self):
        output_data = self.output_text.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(output_data)

    def prompt_sudo_password(self):
        return simpledialog.askstring("Sudo Password", "Enter your sudo password:", show='*')

    def process_queue(self):
        while not self.queue.empty():
            self.output_text.insert(tk.END, self.queue.get())
            self.output_text.see(tk.END)
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = MaldetGUI(root)
    root.mainloop()
