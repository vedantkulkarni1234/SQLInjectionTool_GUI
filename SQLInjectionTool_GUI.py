import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
from bs4 import BeautifulSoup
import re
import subprocess
import json
import csv
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import pickle
import os
from datetime import datetime
import threading

class InteractiveQueryBuilder:
    def __init__(self, master):
        self.master = master
        master.title("Interactive Query Builder")
        master.geometry("1000x800")

        # Database schema (example)
        self.schema = {
            "users": ["id", "username", "email"],
            "orders": ["id", "user_id", "product", "quantity"],
            "products": ["id", "name", "price"]
        }

        # Left panel for schema
        self.schema_frame = ttk.Frame(master)
        self.schema_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        ttk.Label(self.schema_frame, text="Database Schema").pack()
        self.schema_tree = ttk.Treeview(self.schema_frame)
        self.schema_tree.pack(expand=True, fill="both")

        self.populate_schema_tree()

        # Middle panel for query building and target URL configuration
        self.query_frame = ttk.Frame(master)
        self.query_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        ttk.Label(self.query_frame, text="Query Builder").pack()

        # Table selection
        ttk.Label(self.query_frame, text="Select Table:").pack()
        self.table_var = tk.StringVar()
        self.table_combo = ttk.Combobox(self.query_frame, textvariable=self.table_var, values=list(self.schema.keys()))
        self.table_combo.pack()
        self.table_combo.bind("<<ComboboxSelected>>", self.update_columns)
        self.add_help_button(self.query_frame, "Select the table you want to query from the dropdown.")

        # Column selection
        ttk.Label(self.query_frame, text="Select Columns:").pack()
        self.columns_listbox = tk.Listbox(self.query_frame, selectmode=tk.MULTIPLE)
        self.columns_listbox.pack()
        self.add_help_button(self.query_frame, "Select one or more columns to include in your query. Hold Ctrl to select multiple.")

        # Condition builder
        ttk.Label(self.query_frame, text="Add Condition:").pack()
        self.condition_frame = ttk.Frame(self.query_frame)
        self.condition_frame.pack()

        self.condition_column = ttk.Combobox(self.condition_frame)
        self.condition_column.grid(row=0, column=0)
        self.condition_operator = ttk.Combobox(self.condition_frame, values=["=", ">", "<", ">=", "<=", "LIKE"])
        self.condition_operator.grid(row=0, column=1)
        self.condition_value = ttk.Entry(self.condition_frame)
        self.condition_value.grid(row=0, column=2)
        ttk.Button(self.condition_frame, text="Add", command=self.add_condition).grid(row=0, column=3)
        self.add_help_button(self.condition_frame, "Build conditions for your query. Select a column, an operator, and enter a value.")

        # Conditions list
        self.conditions_listbox = tk.Listbox(self.query_frame)
        self.conditions_listbox.pack()

        # Query display
        self.query_text = tk.Text(self.query_frame, height=5)
        self.query_text.pack()

        # Build query button
        ttk.Button(self.query_frame, text="Build Query", command=self.build_query).pack()
        self.add_help_button(self.query_frame, "Click to generate the SQL query based on your selections.")

        # Target URL Configuration
        ttk.Label(self.query_frame, text="Target URL Configuration").pack(pady=(20, 5))
        
        # URL input
        ttk.Label(self.query_frame, text="Target URL:").pack()
        self.url_entry = ttk.Entry(self.query_frame, width=50)
        self.url_entry.pack()
        self.add_help_button(self.query_frame, "Enter the URL of the target website you want to test.")

        # HTTP Method selection
        ttk.Label(self.query_frame, text="HTTP Method:").pack()
        self.http_method_var = tk.StringVar()
        self.http_method_combo = ttk.Combobox(self.query_frame, textvariable=self.http_method_var, values=["GET", "POST"])
        self.http_method_combo.pack()
        self.add_help_button(self.query_frame, "Select the HTTP method to use for the request.")

        # Parameters input
        ttk.Label(self.query_frame, text="Parameters (key=value, one per line):").pack()
        self.params_text = tk.Text(self.query_frame, height=5, width=50)
        self.params_text.pack()
        self.add_help_button(self.query_frame, "Enter request parameters, one per line in key=value format.")

        # Configure SQLmap button
        ttk.Button(self.query_frame, text="Configure SQLmap", command=self.configure_sqlmap).pack(pady=10)
        self.add_help_button(self.query_frame, "Generate the SQLmap command based on your configuration.")

        # Automated Vulnerability Detection
        ttk.Label(self.query_frame, text="Automated Vulnerability Detection").pack(pady=(20, 5))
        self.scan_profile_var = tk.StringVar()
        self.scan_profile_combo = ttk.Combobox(self.query_frame, textvariable=self.scan_profile_var, 
                                               values=["Basic", "Time-based Blind", "Error-based", "Union-based"])
        self.scan_profile_combo.pack()
        self.add_help_button(self.query_frame, "Select a scan profile to determine the type of SQL injection to test for.")
        ttk.Button(self.query_frame, text="Start Automated Scan", command=self.start_automated_scan).pack(pady=10)
        self.add_help_button(self.query_frame, "Start the automated vulnerability scan using SQLmap.")

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.query_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=5, fill=tk.X)

        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self.query_frame, textvariable=self.status_var)
        self.status_label.pack(pady=5)

        # Custom Payloads and Tampering
        ttk.Label(self.query_frame, text="Custom Payloads and Tampering").pack(pady=(20, 5))
        ttk.Button(self.query_frame, text="Manage Custom Payloads", command=self.manage_custom_payloads).pack()
        self.add_help_button(self.query_frame, "Add or edit custom SQL injection payloads.")
        ttk.Button(self.query_frame, text="Manage Tamper Scripts", command=self.manage_tamper_scripts).pack()
        self.add_help_button(self.query_frame, "Manage scripts to modify payloads before sending them.")

        # Session Management
        ttk.Label(self.query_frame, text="Session Management").pack(pady=(20, 5))
        ttk.Button(self.query_frame, text="Save Session", command=self.save_session).pack()
        self.add_help_button(self.query_frame, "Save the current session for later use.")
        ttk.Button(self.query_frame, text="Load Session", command=self.load_session).pack()
        self.add_help_button(self.query_frame, "Load a previously saved session.")
        ttk.Button(self.query_frame, text="View Session History", command=self.view_session_history).pack()
        self.add_help_button(self.query_frame, "View the history of your scanning sessions.")

        # Right panel for detailed results
        self.results_frame = ttk.Frame(master)
        self.results_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

        ttk.Label(self.results_frame, text="Scan Results").pack()
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, width=50, height=30)
        self.results_text.pack(expand=True, fill="both")

        # Export Results buttons
        self.export_frame = ttk.Frame(self.results_frame)
        self.export_frame.pack(pady=10)
        ttk.Button(self.export_frame, text="Export as CSV", command=lambda: self.export_results("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.export_frame, text="Export as JSON", command=lambda: self.export_results("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.export_frame, text="Export as PDF", command=lambda: self.export_results("pdf")).pack(side=tk.LEFT, padx=5)
        self.add_help_button(self.export_frame, "Export the scan results in various formats.")

        # Configure grid
        master.grid_columnconfigure(0, weight=1)
        master.grid_columnconfigure(1, weight=1)
        master.grid_columnconfigure(2, weight=1)
        master.grid_rowconfigure(0, weight=1)

        # Custom payloads and tamper scripts
        self.custom_payloads = []
        self.tamper_scripts = []

        # Session management
        self.current_session = {}
        self.session_history = []

    def add_help_button(self, parent, help_text):
        help_button = tk.Button(parent, text="?", command=lambda: self.show_help(help_text), font=("Arial", 10, "bold"))
        help_button.pack(side="right", padx=(5, 0))  # Use pack instead of grid

    def show_help(self, help_text):
        messagebox.showinfo("Help", help_text)

    def populate_schema_tree(self):
        for table, columns in self.schema.items():
            node = self.schema_tree.insert("", "end", text=table)
            for column in columns:
                self.schema_tree.insert(node, "end", text=column)

    def update_columns(self, event):
        selected_table = self.table_var.get()
        self.columns_listbox.delete(0, tk.END)
        if selected_table in self.schema:
            for column in self.schema[selected_table]:
                self.columns_listbox.insert(tk.END, column)

    def add_condition(self):
        column = self.condition_column.get()
        operator = self.condition_operator.get()
        value = self.condition_value.get()
        if column and operator and value:
            condition = f"{column} {operator} '{value}'"
            self.conditions_listbox.insert(tk.END, condition)
            self.condition_column.delete(0, tk.END)
            self.condition_operator.set("")
            self.condition_value.delete(0, tk.END)

    def build_query(self):
        table = self.table_var.get()
        columns = [self.columns_listbox.get(idx) for idx in self.columns_listbox.curselection()]
        conditions = [self.conditions_listbox.get(idx) for idx in self.conditions_listbox.curselection()]
        if not table or not columns:
            messagebox.showwarning("Warning", "Please select a table and columns.")
            return

        query = f"SELECT {', '.join(columns)} FROM {table}"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        self.query_text.delete(1.0, tk.END)
        self.query_text.insert(tk.END, query)

    def configure_sqlmap(self):
        url = self.url_entry.get()
        method = self.http_method_var.get()
        params = self.params_text.get("1.0", tk.END).strip()
        if not url or not method:
            messagebox.showwarning("Warning", "Please enter the target URL and HTTP method.")
            return

        sqlmap_cmd = f"sqlmap -u {url} --method={method}"
        if params:
            sqlmap_cmd += f" --data='{params}'"
        
        # Optional: Add other SQLmap options here

        self.results_text.insert(tk.END, f"Generated SQLmap command:\n{sqlmap_cmd}\n")
        self.status_var.set("SQLmap command generated. Copy it to the terminal to run.")

    def start_automated_scan(self):
        scan_profile = self.scan_profile_var.get()
        if not scan_profile:
            messagebox.showwarning("Warning", "Please select a scan profile.")
            return

        self.progress_var.set(0)
        self.status_var.set("Starting automated scan...")
        threading.Thread(target=self.run_sqlmap_scan, args=(scan_profile,)).start()

    def run_sqlmap_scan(self, scan_profile):
        url = self.url_entry.get()
        method = self.http_method_var.get()
        params = self.params_text.get("1.0", tk.END).strip()

        sqlmap_cmd = f"sqlmap -u {url} --method={method} --risk=3 --level=5 --tamper=between"
        if params:
            sqlmap_cmd += f" --data='{params}'"

        if scan_profile == "Basic":
            sqlmap_cmd += " --technique=B"
        elif scan_profile == "Time-based Blind":
            sqlmap_cmd += " --technique=T"
        elif scan_profile == "Error-based":
            sqlmap_cmd += " --technique=E"
        elif scan_profile == "Union-based":
            sqlmap_cmd += " --technique=U"

        # Execute the SQLmap command and capture output
        process = subprocess.Popen(sqlmap_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        self.results_text.insert(tk.END, output.decode())
        if error:
            self.results_text.insert(tk.END, "\nErrors:\n" + error.decode())

        self.status_var.set("Automated scan completed.")
        self.progress_var.set(100)

    def manage_custom_payloads(self):
        # Open a new window to manage custom payloads
        self.custom_payloads_window = tk.Toplevel(self.master)
        self.custom_payloads_window.title("Manage Custom Payloads")
        self.custom_payloads_window.geometry("400x300")
        self.payloads_listbox = tk.Listbox(self.custom_payloads_window)
        self.payloads_listbox.pack(expand=True, fill="both")
        self.add_help_button(self.custom_payloads_window, "Manage custom SQL injection payloads.")

        # Load existing payloads
        for payload in self.custom_payloads:
            self.payloads_listbox.insert(tk.END, payload)

        # Add payload
        ttk.Label(self.custom_payloads_window, text="Add Payload:").pack()
        self.new_payload_entry = ttk.Entry(self.custom_payloads_window)
        self.new_payload_entry.pack()
        ttk.Button(self.custom_payloads_window, text="Add", command=self.add_custom_payload).pack()

        # Remove payload
        ttk.Button(self.custom_payloads_window, text="Remove", command=self.remove_custom_payload).pack()

    def add_custom_payload(self):
        payload = self.new_payload_entry.get()
        if payload:
            self.custom_payloads.append(payload)
            self.payloads_listbox.insert(tk.END, payload)
            self.new_payload_entry.delete(0, tk.END)

    def remove_custom_payload(self):
        selected_index = self.payloads_listbox.curselection()
        if selected_index:
            payload = self.payloads_listbox.get(selected_index)
            self.custom_payloads.remove(payload)
            self.payloads_listbox.delete(selected_index)

    def manage_tamper_scripts(self):
        # Open a new window to manage tamper scripts
        self.tamper_scripts_window = tk.Toplevel(self.master)
        self.tamper_scripts_window.title("Manage Tamper Scripts")
        self.tamper_scripts_window.geometry("400x300")
        self.scripts_listbox = tk.Listbox(self.tamper_scripts_window)
        self.scripts_listbox.pack(expand=True, fill="both")
        self.add_help_button(self.tamper_scripts_window, "Manage tamper scripts.")

        # Load existing scripts
        for script in self.tamper_scripts:
            self.scripts_listbox.insert(tk.END, script)

        # Add script
        ttk.Label(self.tamper_scripts_window, text="Add Script:").pack()
        self.new_script_entry = ttk.Entry(self.tamper_scripts_window)
        self.new_script_entry.pack()
        ttk.Button(self.tamper_scripts_window, text="Add", command=self.add_tamper_script).pack()

        # Remove script
        ttk.Button(self.tamper_scripts_window, text="Remove", command=self.remove_tamper_script).pack()

    def add_tamper_script(self):
        script = self.new_script_entry.get()
        if script:
            self.tamper_scripts.append(script)
            self.scripts_listbox.insert(tk.END, script)
            self.new_script_entry.delete(0, tk.END)

    def remove_tamper_script(self):
        selected_index = self.scripts_listbox.curselection()
        if selected_index:
            script = self.scripts_listbox.get(selected_index)
            self.tamper_scripts.remove(script)
            self.scripts_listbox.delete(selected_index)

    def save_session(self):
        session_name = filedialog.asksaveasfilename(defaultextension=".pkl", filetypes=[("Pickle Files", "*.pkl")])
        if session_name:
            with open(session_name, "wb") as f:
                pickle.dump(self.current_session, f)
            self.status_var.set(f"Session saved to {session_name}")

    def load_session(self):
        session_name = filedialog.askopenfilename(filetypes=[("Pickle Files", "*.pkl")])
        if session_name:
            with open(session_name, "rb") as f:
                self.current_session = pickle.load(f)
            self.status_var.set(f"Session loaded from {session_name}")

    def view_session_history(self):
        history_window = tk.Toplevel(self.master)
        history_window.title("Session History")
        history_window.geometry("400x300")
        history_listbox = tk.Listbox(history_window)
        history_listbox.pack(expand=True, fill="both")

        for session in self.session_history:
            history_listbox.insert(tk.END, session)

    def export_results(self, format_type):
        results = self.results_text.get("1.0", tk.END).strip()
        if format_type == "csv":
            file_name = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if file_name:
                with open(file_name, "w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow([results])
                self.status_var.set(f"Results exported to {file_name}")
        elif format_type == "json":
            file_name = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
            if file_name:
                with open(file_name, "w") as file:
                    json.dump({"results": results}, file, indent=4)
                self.status_var.set(f"Results exported to {file_name}")
        elif format_type == "pdf":
            file_name = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
            if file_name:
                c = canvas.Canvas(file_name, pagesize=letter)
                c.drawString(100, 750, results)
                c.save()
                self.status_var.set(f"Results exported to {file_name}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionTool(root)
    root.mainloop()
