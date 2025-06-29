#-------------------------------------------------------------------------------
# Name:        Software Inventory Manager
# Purpose:     To enable users to manage and track software product keys and
#              associated metadata for Windows operating systems.
#
# Author:      Dwayne Akeem Reid
#
# Created:     29/06/2025
# Copyright:   © ReforgedSystems OU 2025
# Licence:     MIT licence
#-------------------------------------------------------------------------------


import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import csv
import json

class SoftwareInventoryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Software Inventory Manager")
        self.root.geometry("1000x700")

        # Database setup
        self.conn = sqlite3.connect('software_inventory.db')
        self.create_table()

        # UI Setup
        self.setup_ui()

        # Load initial data
        self.load_data()

        # Configure resizing behavior
        self.configure_responsive_layout()

    def setup_ui(self):
        # Main container frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Input fields frame
        input_frame = ttk.LabelFrame(self.main_frame, text="Software Details", padding="10")
        input_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Labels
        ttk.Label(input_frame, text="Volume Name:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="Product Key:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="Operating System:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="Channel:").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="MD5:").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="SHA1:").grid(row=5, column=0, sticky="w", pady=2)
        ttk.Label(input_frame, text="SHA256:").grid(row=6, column=0, sticky="w", pady=2)

        # Entry fields
        self.volume_name = ttk.Entry(input_frame, width=40)
        self.product_key = ttk.Entry(input_frame, width=40)
        self.md5 = ttk.Entry(input_frame, width=40)
        self.sha1 = ttk.Entry(input_frame, width=40)
        self.sha256 = ttk.Entry(input_frame, width=40)

        self.volume_name.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.product_key.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        self.md5.grid(row=4, column=1, sticky="ew", padx=5, pady=2)
        self.sha1.grid(row=5, column=1, sticky="ew", padx=5, pady=2)
        self.sha256.grid(row=6, column=1, sticky="ew", padx=5, pady=2)

        # Combo boxes
        self.os_options = [
    # Windows 1.x
    "Windows 1.0",
    "Windows 1.01",
    "Windows 1.02",
    "Windows 1.03",
    "Windows 1.04",

    # Windows 2.x
    "Windows 2.0",
    "Windows 2.03",
    "Windows 2.10",
    "Windows 2.11",

    # Windows 3.x
    "Windows 3.0",
    "Windows 3.1",
    "Windows 3.11",
    "Windows for Workgroups 3.1",
    "Windows for Workgroups 3.11",

    # Windows 9x series
    "Windows 95",
    "Windows 95 OSR2",
    "Windows 98",
    "Windows 98 Second Edition",
    "Windows Me",

    # Windows NT series
    "Windows NT 3.1",
    "Windows NT 3.5",
    "Windows NT 3.51",
    "Windows NT 4.0 Workstation",
    "Windows NT 4.0 Server",
    "Windows 2000 Professional",
    "Windows 2000 Server",
    "Windows 2000 Advanced Server",
    "Windows 2000 Datacenter Server",

    # Windows XP
    "Windows XP Home",
    "Windows XP Professional",
    "Windows XP Media Center",
    "Windows XP Media Center 2004",
    "Windows XP Media Center 2005",
    "Windows XP Professional x64",
    "Windows XP Tablet PC Edition",
    "Windows XP Starter",
    "Windows XP Embedded",

    # Windows Server 2003
    "Windows Server 2003 Standard",
    "Windows Server 2003 Enterprise",
    "Windows Server 2003 Datacenter",
    "Windows Server 2003 Web Edition",
    "Windows Server 2003 Storage Server",
    "Windows Server 2003 Small Business Server",
    "Windows Server 2003 R2",

    # Windows Vista
    "Windows Vista Starter",
    "Windows Vista Home Basic",
    "Windows Vista Home Premium",
    "Windows Vista Business",
    "Windows Vista Enterprise",
    "Windows Vista Ultimate",

    # Windows Server 2008
    "Windows Server 2008 Standard",
    "Windows Server 2008 Enterprise",
    "Windows Server 2008 Datacenter",
    "Windows Server 2008 Web Server",
    "Windows Server 2008 Storage Server",
    "Windows Server 2008 Small Business Server",
    "Windows Server 2008 R2 Standard",
    "Windows Server 2008 R2 Enterprise",
    "Windows Server 2008 R2 Datacenter",
    "Windows Server 2008 R2 Web Server",

    # Windows 7
    "Windows 7 Starter",
    "Windows 7 Home Basic",
    "Windows 7 Home Premium",
    "Windows 7 Professional",
    "Windows 7 Enterprise",
    "Windows 7 Ultimate",

    # Windows 8
    "Windows 8",
    "Windows 8 Pro",
    "Windows 8 Enterprise",
    "Windows 8 RT",

    # Windows 8.1
    "Windows 8.1",
    "Windows 8.1 Pro",
    "Windows 8.1 Enterprise",
    "Windows 8.1 RT",
    "Windows 8.1 with Bing",

    # Windows Server 2012
    "Windows Server 2012 Foundation",
    "Windows Server 2012 Essentials",
    "Windows Server 2012 Standard",
    "Windows Server 2012 Datacenter",
    "Windows Server 2012 R2 Foundation",
    "Windows Server 2012 R2 Essentials",
    "Windows Server 2012 R2 Standard",
    "Windows Server 2012 R2 Datacenter",

    # Windows 10
    "Windows 10 Home",
    "Windows 10 Pro",
    "Windows 10 Enterprise",
    "Windows 10 Education",
    "Windows 10 Pro Education",
    "Windows 10 Enterprise LTSC",
    "Windows 10 Pro for Workstations",
    "Windows 10 Home Single Language",
    "Windows 10 Home in S Mode",
    "Windows 10 Pro in S Mode",
    "Windows 10 Enterprise in S Mode",
    "Windows 10 Education in S Mode",
    "Windows 10 IoT Core",
    "Windows 10 IoT Enterprise",
    "Windows 10 Mobile",
    "Windows 10 Mobile Enterprise",
    "Windows 10 Team",

    # Windows Server 2016
    "Windows Server 2016 Essentials",
    "Windows Server 2016 Standard",
    "Windows Server 2016 Datacenter",
    "Windows Server 2016 Storage Server",
    "Windows Server 2016 Hyper-V Server",

    # Windows Server 2019
    "Windows Server 2019 Essentials",
    "Windows Server 2019 Standard",
    "Windows Server 2019 Datacenter",
    "Windows Server 2019 Storage Server",
    "Windows Server 2019 Hyper-V Server",

    # Windows 11
    "Windows 11 Home",
    "Windows 11 Pro",
    "Windows 11 Enterprise",
    "Windows 11 Education",
    "Windows 11 Pro Education",
    "Windows 11 Enterprise LTSC",
    "Windows 11 Pro for Workstations",
    "Windows 11 Home Single Language",
    "Windows 11 SE",
    "Windows 11 IoT Enterprise",

    # Windows Server 2022
    "Windows Server 2022 Standard",
    "Windows Server 2022 Datacenter",
    "Windows Server 2022 Datacenter: Azure Edition",
    "Windows Server 2022 Storage Server",
    "Windows Server 2022 Hyper-V Server",

    # Windows Server 2025 (Released late 2024)
    "Windows Server 2025 Standard",
    "Windows Server 2025 Datacenter",
    "Windows Server 2025 Datacenter: Azure Edition",

    # Specialized/Embedded versions
    "Windows CE",
    "Windows Mobile",
    "Windows Phone 7",
    "Windows Phone 8",
    "Windows Phone 8.1",
    "Windows Embedded Compact",
    "Windows Embedded Standard",
    "Windows Embedded POSReady",
    "Windows Thin PC",
    "Windows MultiPoint Server",
    "Windows Storage Server",
    "Windows Home Server",
    "Windows Essential Business Server",
    "Windows Small Business Server"
        ]
        self.channel_options = [
    "Retail",
    "OEM",
    "Volume License",
    "MSDN",
    "Academic",
    "TechNet",
    "NFR (Not for Resale)",
    "Evaluation",
    "Beta",
    "RC (Release Candidate)",
    "RTM (Release to Manufacturing)",
    "COEM (Component OEM)",
    "System Builder",
    "DSP (Delivery Service Partner)",
    "FPP (Full Packaged Product)",
    "Select License",
    "Enterprise Agreement",
    "Open License",
    "Campus Agreement",
    "School Agreement",
    "Student Media",
    "Faculty License",
    "Developer License",
    "BizSpark",
    "Action Pack",
    "Partner License",
    "Internal Use License",
    "Refurbisher License",
    "Upgrade License",
    "Competitive Upgrade",
    "Product Key Card",
    "Digital Download",
    "Get Genuine Kit",
    "Windows Anytime Upgrade",
    "Express Upgrade",
    "Family Pack",
    "3-Pack License",
    "OEM Preinstallation Kit",
    "Channel Assembly",
    "White Box",
    "Educational Institutional",
    "Government License",
    "Non-Profit License",
    "Charity License",
    "Military License",
    "Embedded License",
    "Runtime License",
    "Royalty License",
    "MAK (Multiple Activation Key)",
    "KMS (Key Management Service)",
    "Active Directory-Based Activation"
]

        self.os_combo = ttk.Combobox(input_frame, values=self.os_options, state="readonly")
        self.channel_combo = ttk.Combobox(input_frame, values=self.channel_options, state="readonly")

        self.os_combo.grid(row=2, column=1, sticky="ew", padx=5, pady=2)
        self.channel_combo.grid(row=3, column=1, sticky="ew", padx=5, pady=2)

        # Button frame
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10, sticky="ew")

        self.add_btn = ttk.Button(button_frame, text="Add", command=self.add_record)
        self.update_btn = ttk.Button(button_frame, text="Update", command=self.update_record)
        self.delete_btn = ttk.Button(button_frame, text="Delete", command=self.delete_record)
        self.clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_form)
        self.copy_btn = ttk.Button(button_frame, text="Copy Selected", command=self.copy_to_clipboard)

        self.add_btn.pack(side=tk.LEFT, padx=5)
        self.update_btn.pack(side=tk.LEFT, padx=5)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        self.copy_btn.pack(side=tk.LEFT, padx=5)

        # Search frame
        search_frame = ttk.Frame(self.main_frame)
        search_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_btn = ttk.Button(search_frame, text="Search", command=self.search_data)
        self.search_btn.pack(side=tk.LEFT, padx=5)

        # Bind Enter key to search
        self.search_entry.bind('<Return>', lambda event: self.search_data())

        # Export buttons
        export_frame = ttk.Frame(self.main_frame)
        export_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        self.csv_btn = ttk.Button(export_frame, text="Export CSV", command=self.export_csv)
        self.xml_btn = ttk.Button(export_frame, text="Export XML", command=self.export_xml)
        self.txt_btn = ttk.Button(export_frame, text="Export TXT", command=self.export_txt)
        self.json_btn = ttk.Button(export_frame, text="Export JSON", command=self.export_json)

        self.csv_btn.pack(side=tk.LEFT, padx=5)
        self.xml_btn.pack(side=tk.LEFT, padx=5)
        self.txt_btn.pack(side=tk.LEFT, padx=5)
        self.json_btn.pack(side=tk.LEFT, padx=5)

        # Treeview (Data Grid)
        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)

        self.tree = ttk.Treeview(tree_frame, columns=(
            "id", "Volume Name", "Product Key", "Operating System", "Channel",
            "MD5", "SHA1", "SHA256", "Created Date"
        ), show="headings")

        # Configure columns
        self.tree.heading("id", text="ID")
        self.tree.heading("Volume Name", text="Volume Name")
        self.tree.heading("Product Key", text="Product Key")
        self.tree.heading("Operating System", text="Operating System")
        self.tree.heading("Channel", text="Channel")
        self.tree.heading("MD5", text="MD5")
        self.tree.heading("SHA1", text="SHA1")
        self.tree.heading("SHA256", text="SHA256")
        self.tree.heading("Created Date", text="Created Date")

        # Hide ID column
        self.tree.column("id", width=0, stretch=tk.NO)

        # Set column widths
        for col in self.tree["columns"][1:]:  # Skip ID column
            self.tree.column(col, width=120, anchor=tk.W)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout for tree and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Configure row/column weights for tree_frame
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)

    def configure_responsive_layout(self):
        # Configure grid weights for main frame
        self.main_frame.grid_rowconfigure(3, weight=1)  # Treeview row gets extra space
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Make all widgets expand with window
        for child in self.main_frame.winfo_children():
            child.grid_configure(padx=5, pady=5, sticky="nsew")

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS software_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                volume_name TEXT,
                product_key TEXT,
                operating_system TEXT,
                channel TEXT,
                md5_hash TEXT,
                sha1_hash TEXT,
                sha256_hash TEXT,
                created_date TEXT,
                modified_date TEXT
            )
        ''')

        # Create indexes
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_volume_name ON software_inventory(volume_name)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_product_key ON software_inventory(product_key)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_operating_system ON software_inventory(operating_system)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_channel ON software_inventory(channel)
        ''')

        self.conn.commit()

    def load_data(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, volume_name, product_key, operating_system, channel,
                   md5_hash, sha1_hash, sha256_hash, created_date
            FROM software_inventory
            ORDER BY id DESC
        ''')

        # Clear existing data
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new data
        for row in cursor.fetchall():
            self.tree.insert("", tk.END, values=row)

    def validate_input(self):
        if (not self.volume_name.get().strip() and
            not self.product_key.get().strip() and
            not self.os_combo.get() and
            not self.channel_combo.get() and
            not self.md5.get().strip() and
            not self.sha1.get().strip() and
            not self.sha256.get().strip()):
            messagebox.showwarning("Validation Error", "Please enter at least one field with valid data.")
            self.volume_name.focus()
            return False
        return True

    def clear_form(self):
        self.volume_name.delete(0, tk.END)
        self.product_key.delete(0, tk.END)
        self.os_combo.set('')
        self.channel_combo.set('')
        self.md5.delete(0, tk.END)
        self.sha1.delete(0, tk.END)
        self.sha256.delete(0, tk.END)
        self.volume_name.focus()

    def add_record(self):
        if not self.validate_input():
            return

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO software_inventory (
                volume_name, product_key, operating_system, channel,
                md5_hash, sha1_hash, sha256_hash, created_date, modified_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.volume_name.get().strip() or None,
            self.product_key.get().strip() or None,
            self.os_combo.get() or None,
            self.channel_combo.get() or None,
            self.md5.get().strip() or None,
            self.sha1.get().strip() or None,
            self.sha256.get().strip() or None,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        self.conn.commit()
        messagebox.showinfo("Success", "Record added successfully!")
        self.load_data()
        self.clear_form()

    def update_record(self):
        if not self.tree.selection():
            messagebox.showwarning("Warning", "Please select a record to update.")
            return

        if not self.validate_input():
            return

        selected_item = self.tree.selection()[0]
        record_id = self.tree.item(selected_item)['values'][0]

        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE software_inventory SET
                volume_name = ?,
                product_key = ?,
                operating_system = ?,
                channel = ?,
                md5_hash = ?,
                sha1_hash = ?,
                sha256_hash = ?,
                modified_date = ?
            WHERE id = ?
        ''', (
            self.volume_name.get().strip() or None,
            self.product_key.get().strip() or None,
            self.os_combo.get() or None,
            self.channel_combo.get() or None,
            self.md5.get().strip() or None,
            self.sha1.get().strip() or None,
            self.sha256.get().strip() or None,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            record_id
        ))

        self.conn.commit()
        messagebox.showinfo("Success", "Record updated successfully!")
        self.load_data()
        self.clear_form()

    def delete_record(self):
        if not self.tree.selection():
            messagebox.showwarning("Warning", "Please select a record to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this record?"):
            selected_item = self.tree.selection()[0]
            record_id = self.tree.item(selected_item)['values'][0]

            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM software_inventory WHERE id = ?', (record_id,))

            self.conn.commit()
            messagebox.showinfo("Success", "Record deleted successfully!")
            self.load_data()
            self.clear_form()

    def on_tree_select(self, event):
        if self.tree.selection():
            selected_item = self.tree.selection()[0]
            values = self.tree.item(selected_item)['values']

            self.volume_name.delete(0, tk.END)
            self.volume_name.insert(0, values[1] if values[1] else "")

            self.product_key.delete(0, tk.END)
            self.product_key.insert(0, values[2] if values[2] else "")

            self.os_combo.set(values[3] if values[3] else "")
            self.channel_combo.set(values[4] if values[4] else "")

            self.md5.delete(0, tk.END)
            self.md5.insert(0, values[5] if values[5] else "")

            self.sha1.delete(0, tk.END)
            self.sha1.insert(0, values[6] if values[6] else "")

            self.sha256.delete(0, tk.END)
            self.sha256.insert(0, values[7] if values[7] else "")

    def search_data(self):
        search_term = self.search_entry.get().strip()

        cursor = self.conn.cursor()
        if not search_term:
            cursor.execute('''
                SELECT id, volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                ORDER BY id DESC
            ''')
        else:
            cursor.execute('''
                SELECT id, volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                WHERE volume_name LIKE ? OR
                      product_key LIKE ? OR
                      operating_system LIKE ? OR
                      channel LIKE ? OR
                      md5_hash LIKE ? OR
                      sha1_hash LIKE ? OR
                      sha256_hash LIKE ?
                ORDER BY id DESC
            ''', (f"%{search_term}%",) * 7)

        # Clear existing data
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new data
        for row in cursor.fetchall():
            self.tree.insert("", tk.END, values=row)

    def copy_to_clipboard(self):
        if not self.tree.selection():
            messagebox.showwarning("Warning", "Please select a record to copy.")
            return

        selected_item = self.tree.selection()[0]
        values = self.tree.item(selected_item)['values']

        text = f"""Volume Name: {values[1] or ''}
Product Key: {values[2] or ''}
Operating System: {values[3] or ''}
Channel: {values[4] or ''}
MD5: {values[5] or ''}
SHA1: {values[6] or ''}
SHA256: {values[7] or ''}"""

        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Success", "Selected record copied to clipboard!")

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save as CSV"
        )

        if not file_path:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                ORDER BY id DESC
            ''')

            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                # Write headers
                writer.writerow([
                    "Volume Name", "Product Key", "Operating System", "Channel",
                    "MD5", "SHA1", "SHA256", "Created Date"
                ])
                # Write data
                writer.writerows(cursor.fetchall())

            messagebox.showinfo("Success", "Data exported to CSV successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to CSV: {e}")

    def export_xml(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml")],
            title="Save as XML"
        )

        if not file_path:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                ORDER BY id DESC
            ''')

            with open(file_path, 'w', encoding='utf-8') as xmlfile:
                xmlfile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                xmlfile.write('<SoftwareInventory>\n')

                for row in cursor.fetchall():
                    xmlfile.write('  <Software>\n')
                    xmlfile.write(f'    <VolumeName>{row[0] or ""}</VolumeName>\n')
                    xmlfile.write(f'    <ProductKey>{row[1] or ""}</ProductKey>\n')
                    xmlfile.write(f'    <OperatingSystem>{row[2] or ""}</OperatingSystem>\n')
                    xmlfile.write(f'    <Channel>{row[3] or ""}</Channel>\n')
                    xmlfile.write(f'    <MD5>{row[4] or ""}</MD5>\n')
                    xmlfile.write(f'    <SHA1>{row[5] or ""}</SHA1>\n')
                    xmlfile.write(f'    <SHA256>{row[6] or ""}</SHA256>\n')
                    xmlfile.write(f'    <CreatedDate>{row[7] or ""}</CreatedDate>\n')
                    xmlfile.write('  </Software>\n')

                xmlfile.write('</SoftwareInventory>\n')

            messagebox.showinfo("Success", "Data exported to XML successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to XML: {e}")

    def export_txt(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save as Text"
        )

        if not file_path:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                ORDER BY id DESC
            ''')

            with open(file_path, 'w', encoding='utf-8') as txtfile:
                for row in cursor.fetchall():
                    txtfile.write("=== Software Record ===\n")
                    txtfile.write(f"Volume Name: {row[0] or ''}\n")
                    txtfile.write(f"Product Key: {row[1] or ''}\n")
                    txtfile.write(f"Operating System: {row[2] or ''}\n")
                    txtfile.write(f"Channel: {row[3] or ''}\n")
                    txtfile.write(f"MD5: {row[4] or ''}\n")
                    txtfile.write(f"SHA1: {row[5] or ''}\n")
                    txtfile.write(f"SHA256: {row[6] or ''}\n")
                    txtfile.write(f"Created Date: {row[7] or ''}\n\n")

            messagebox.showinfo("Success", "Data exported to TXT successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to TXT: {e}")

    def export_json(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save as JSON"
        )

        if not file_path:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT volume_name, product_key, operating_system, channel,
                       md5_hash, sha1_hash, sha256_hash, created_date
                FROM software_inventory
                ORDER BY id DESC
            ''')

            # Convert to list of dictionaries
            columns = ["volume_name", "product_key", "operating_system", "channel",
                      "md5_hash", "sha1_hash", "sha256_hash", "created_date"]
            data = []

            for row in cursor.fetchall():
                record = {}
                for i, col in enumerate(columns):
                    record[col] = row[i] if row[i] else None
                data.append(record)

            # Write to JSON file
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=4, ensure_ascii=False)

            messagebox.showinfo("Success", "Data exported to JSON successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to JSON: {e}")

    def __del__(self):
        if hasattr(self, 'conn'):
            self.conn.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = SoftwareInventoryApp(root)
    root.mainloop()
