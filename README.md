# Software Inventory Manager - Documentation

## Overview

The **Software Inventory Manager** is a Python desktop application built using `tkinter` for GUI and `sqlite3` for local data persistence. It enables users to manage and track software product keys and associated metadata such as OS type, distribution channel, and hash values.

## Features

* Add, update, delete, and search software records
* Input fields for Volume Name, Product Key, OS, Channel, MD5, SHA1, SHA256
* Dropdowns with exhaustive lists of Windows versions and license types
* Data table (TreeView) with sorting and scrollbar support
* Export capabilities (CSV, XML, TXT, JSON)
* Copy selected record to clipboard
* Auto-creation of SQLite DB schema with indexing for fast search

## Requirements

* Python 3.6+
* Libraries:

  * tkinter (standard library)
  * sqlite3 (standard library)
  * csv, json (standard library)
  * datetime

## File Structure

* `main.py`: Main application script
* `software_inventory.db`: Auto-generated SQLite database file

## Application Layout

### 1. Software Details Input

Grouped in a labeled frame with:

* Text inputs: Volume Name, Product Key, MD5, SHA1, SHA256
* Combo boxes: Operating System, Channel
* Buttons: Add, Update, Delete, Clear, Copy Selected

### 2. Search

* Text input field and Search button
* Auto-search on Enter key press

### 3. Export

* Buttons: Export CSV, Export XML, Export TXT, Export JSON

### 4. Records Table

* TreeView widget with columns:

  * Volume Name, Product Key, OS, Channel
  * MD5, SHA1, SHA256, Created Date
* Scrollbars and column resizing

## Data Schema

Table: `software_inventory`

* `id`: INTEGER PRIMARY KEY
* `volume_name`: TEXT
* `product_key`: TEXT
* `operating_system`: TEXT
* `channel`: TEXT
* `md5_hash`, `sha1_hash`, `sha256_hash`: TEXT
* `created_date`, `modified_date`: TEXT

## Usage

* Run with `python main.py`
* Fill in software fields and click `Add`
* Select an item to `Update`, `Delete`, or `Copy`
* Use search to filter records
* Use export buttons to save data

## Notes

* Empty fields are stored as NULL in the database
* UI automatically resizes with the window
* Designed for desktop use on Windows/Linux

## License

This project is provided as-is for educational and internal use. Ensure any use of actual license keys complies with applicable software licensing terms.
