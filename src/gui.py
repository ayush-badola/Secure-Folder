import os, json, tempfile, subprocess, platform, io
from tkinter import messagebox, scrolledtext, filedialog, ttk
from PIL import Image, ImageTk
import customtkinter as ctk
from src.adaptive_encryptor import AdaptiveEncryptor
from src.file_monitor import FileMonitor
from src.config import MOUNT_PATH, STORE_PATH

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class SecureGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Secure Adaptive Encryption System")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)
        self.root.configure(fg_color="#f3f3f3")
        
        self.enc = None
        self.current_file_content = None
        self.current_filename = None
        self.file_monitor = None
        self.last_files = []
        self.password_cache = {}
        self.mount_path = MOUNT_PATH
        self.store_path = STORE_PATH
        
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.update_table()
        self.root.mainloop()

    def setup_directories(self):
        if self.mount_path: os.makedirs(self.mount_path, exist_ok=True)
        if self.store_path: os.makedirs(self.store_path, exist_ok=True)

    def setup_ui(self):
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        left_panel = ctk.CTkFrame(self.root, width=420, corner_radius=12, fg_color="#ffffff")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(16, 8), pady=12)
        left_panel.grid_propagate(False)
        
        right_panel = ctk.CTkFrame(self.root, corner_radius=12, fg_color="#ffffff")
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 16), pady=12)
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(1, weight=1)

        self.create_folder_section(left_panel)
        self.create_password_section(left_panel)
        self.create_file_section(left_panel)
        self.create_toolbar_section(right_panel)
        self.create_content_section(right_panel)

    def create_folder_section(self, parent):
        ctk.CTkLabel(parent, text="Folder Configuration", font=("Segoe UI", 14, "bold"), 
                    anchor="w", text_color="#000000").pack(fill="x", padx=12, pady=(8, 4))
        
        container = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        container.pack(fill="x", padx=8, pady=(0, 8))

        for label_text, entry_attr, browse_cmd in [
            ("Watch Folder:", "mount_entry", self.select_mount_folder),
            ("Storage Folder:", "store_entry", self.select_store_folder)
        ]:
            frame = ctk.CTkFrame(container, fg_color="#ffffff")
            frame.pack(fill="x", padx=6, pady=2)
            ctk.CTkLabel(frame, text=label_text, font=("Segoe UI", 11), anchor="w", text_color="#000000").pack(fill="x")
            btn_frame = ctk.CTkFrame(frame, fg_color="#ffffff")
            btn_frame.pack(fill="x", pady=2)
            entry = ctk.CTkEntry(btn_frame, placeholder_text=f"Select folder for {label_text.lower()}", 
                               font=("Segoe UI", 10), text_color="#000000", height=28)
            entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkButton(btn_frame, text="Browse", command=browse_cmd, fg_color="#0078D4", 
                         hover_color="#005a9e", corner_radius=6, font=("Segoe UI", 10), height=28, width=70).pack(side="right")
            setattr(self, entry_attr, entry)

        if self.mount_path: self.mount_entry.insert(0, self.mount_path)
        if self.store_path: self.store_entry.insert(0, self.store_path)

    def select_mount_folder(self):
        folder = filedialog.askdirectory(title="Select folder to watch for files to encrypt")
        if folder:
            self.mount_path = folder
            self.mount_entry.delete(0, "end")
            self.mount_entry.insert(0, folder)
            self.setup_directories()

    def select_store_folder(self):
        folder = filedialog.askdirectory(title="Select folder for encrypted files storage")
        if folder:
            self.store_path = folder
            self.store_entry.delete(0, "end")
            self.store_entry.insert(0, folder)
            self.setup_directories()

    def create_password_section(self, parent):
        ctk.CTkLabel(parent, text="Master Password", font=("Segoe UI", 14, "bold"), 
                    anchor="w", text_color="#000000").pack(fill="x", padx=12, pady=(4, 4))
        
        container = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        container.pack(fill="x", padx=8, pady=(0, 8))
        
        inner = ctk.CTkFrame(container, fg_color="#ffffff", corner_radius=6)
        inner.pack(fill="x", padx=6, pady=4)
        
        entry_frame = ctk.CTkFrame(inner, fg_color="#ffffff", corner_radius=6)
        entry_frame.pack(fill="x")
        
        self.password_entry = ctk.CTkEntry(entry_frame, placeholder_text="Enter master password", 
                                         show="*", font=("Segoe UI", 11), text_color="#000000", height=32)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(2, 6), pady=4)
        
        self.set_password_btn = ctk.CTkButton(entry_frame, text="Set Password & Start", 
                                            command=self.set_password_and_start, fg_color="#0078D4", 
                                            hover_color="#005a9e", corner_radius=8, height=32)
        self.set_password_btn.pack(side="right", padx=(0, 2), pady=4)
        
        self.password_status = ctk.CTkLabel(inner, text="No password set", font=("Segoe UI", 10), 
                                          anchor="w", text_color="#111111")
        self.password_status.pack(fill="x", padx=4, pady=(2, 0))

    def create_file_section(self, parent):
        ctk.CTkLabel(parent, text="Encrypted Files", font=("Segoe UI", 14, "bold"), 
                    anchor="w", text_color="#000000").pack(fill="x", padx=12, pady=(4, 4))
        
        table_container = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        table_container.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        
        style.configure("Explorer.Treeview", font=("Segoe UI", 10), background="#ffffff",
                        fieldbackground="#ffffff", foreground="#000000", rowheight=32, borderwidth=0)
        style.configure("Explorer.Treeview.Heading", font=("Segoe UI", 10, "bold"),
                        background="#e5e5e5", foreground="#000000", relief="flat")
        
        self.table = ttk.Treeview(table_container, columns=("Filename", "Mode", "PQC"), 
                                show="headings", style="Explorer.Treeview", selectmode="browse")
        self.table.heading("Filename", text="File Name")
        self.table.heading("Mode", text="Security Mode")
        self.table.heading("PQC", text="PQC Wrapped")
        self.table.column("Filename", width=200, anchor="w")
        self.table.column("Mode", width=90, anchor="center")
        self.table.column("PQC", width=70, anchor="center")
        self.table.pack(fill="both", expand=True, side="left", padx=(4,0), pady=4)
        
        vsb = ttk.Scrollbar(table_container, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0,4), pady=4)
        
        for tag, color in [("green", "#eaf7ea"), ("yellow", "#fffdfa"), ("red", "#fff0f0"), ("hover", "#e8f4ff")]:
            self.table.tag_configure(tag, background=color, foreground="#000000")
        
        self.table.bind("<Motion>", self._on_tree_motion)
        self.table.bind("<Leave>", self._on_tree_leave)
        self._last_hover = None
        
        self.mount_info_label = ctk.CTkLabel(parent, text=f"Place files in:\n{self.mount_path if self.mount_path else 'Select watch folder above'}", 
                    font=("Segoe UI", 10), anchor="w", text_color="#111111", justify="left")
        self.mount_info_label.pack(fill="x", padx=12, pady=(2, 8))

    def create_toolbar_section(self, parent):
        toolbar_frame = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        toolbar_frame.pack(fill="x", padx=12, pady=(8, 4))
        toolbar_frame.grid_columnconfigure(0, weight=1)
        
        button_container = ctk.CTkFrame(toolbar_frame, fg_color="#ffffff")
        button_container.grid(row=0, column=0, sticky="w", padx=8, pady=4)
        
        buttons = [
            ("Decrypt & View", self.decrypt_and_view, "#0b846b"),
            ("Export File", self.export_decrypted, "#1673a7"), 
            ("Open Externally", self.open_externally, "#d97706"),
            ("Try Different Password", self.try_different_password, "#5a5a5a"),
            ("Refresh", self.force_refresh, "#404040")
        ]
        
        for i, (text, command, color) in enumerate(buttons):
            btn = ctk.CTkButton(button_container, text=text, command=command, fg_color=color,
                              hover_color=self.darken_color(color), corner_radius=6,
                              font=("Segoe UI", 10), text_color="#ffffff", height=28)
            btn.grid(row=0, column=i, padx=2, pady=2)
        
        self.status_indicator = ctk.CTkLabel(toolbar_frame, text="● Ready", font=("Segoe UI", 10), 
                                           text_color="#0b846b", fg_color="#ffffff")
        self.status_indicator.grid(row=0, column=1, sticky="e", padx=8, pady=4)

    def darken_color(self, color):
        colors = {
            "#0b846b": "#08674f", "#1673a7": "#125d86", 
            "#d97706": "#a85c05", "#5a5a5a": "#404040", 
            "#404040": "#2a2a2a"
        }
        return colors.get(color, color)

    def create_content_section(self, parent):
        tab_frame = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=6)
        tab_frame.pack(fill="x", padx=12, pady=(4, 4))
        
        self.tab_buttons = {}
        for text, command in [("Text", self.show_text), ("Image", self.show_image), ("Info", self.show_info)]:
            btn = ctk.CTkButton(tab_frame, text=text, command=command, fg_color="#f0f0f0", 
                               hover_color="#e0e0e0", text_color="#000000", corner_radius=6, height=30)
            btn.pack(side="left", padx=(6,3) if text == "Text" else 3, pady=4)
            self.tab_buttons[text] = btn
        
        content_panel = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=8)
        content_panel.pack(fill="both", expand=True, padx=12, pady=(0,12))
        
        self.text_content = scrolledtext.ScrolledText(content_panel, wrap="word", font=("Consolas", 11), 
                                                     foreground="#000000", background="#ffffff", borderwidth=0)
        self.image_content = ctk.CTkFrame(content_panel, fg_color="#ffffff", corner_radius=6)
        self.image_label = ctk.CTkLabel(self.image_content, text="", image=None, compound="center")
        self.image_label.pack(expand=True, padx=6, pady=6)
        self.info_content = scrolledtext.ScrolledText(content_panel, wrap="word", font=("Consolas", 11),
                                                     foreground="#000000", background="#ffffff", borderwidth=0)
        
        self.initial_msg = ctk.CTkLabel(content_panel, text="Select a file and click 'Decrypt & View' to see content here.", 
                                       font=("Segoe UI", 12), text_color="#111111", fg_color="#ffffff")
        self.initial_msg.pack(fill="both", expand=True, padx=6, pady=6)

    def show_text(self): self._show_content(self.text_content, "Text")
    def show_image(self): self._show_content(self.image_content, "Image") 
    def show_info(self): self._show_content(self.info_content, "Info")

    def _show_content(self, widget, tab_name):
        for w in (self.text_content, self.image_content, self.info_content, self.initial_msg):
            try: w.pack_forget()
            except: pass
        widget.pack(fill="both", expand=True, padx=6, pady=6)
        for name, btn in self.tab_buttons.items():
            btn.configure(fg_color=("#0078D4" if name == tab_name else "#f0f0f0"), 
                         text_color=("#ffffff" if name == tab_name else "#000000"))

    def set_password_and_start(self):
        password = self.password_entry.get().strip()
        if not password: return messagebox.showerror("Error", "Please enter a password")
        if not self.mount_path or not self.store_path: return messagebox.showerror("Error", "Please select both folders")
        if self.mount_path == self.store_path: return messagebox.showerror("Error", "Folders cannot be the same")
        
        try:
            self.enc = AdaptiveEncryptor(password)
            self.start_file_monitor()
            self.set_password_btn.configure(state="disabled")
            self.password_entry.configure(state="disabled")
            self.password_status.configure(text="Password set - monitoring new files")
            self.status_indicator.configure(text="● Monitoring", text_color="#0b846b")
            messagebox.showinfo("Success", f"Password set and monitor started!\n\nPlace files in: {self.mount_path}")
        except Exception as e: messagebox.showerror("Error", f"Failed to initialize: {e}")

    def start_file_monitor(self):
        try: self.file_monitor = FileMonitor(self.mount_path, self.store_path, self.enc, lambda x: None)
        except Exception as e: messagebox.showerror("Monitor Error", f"Failed to start file monitor: {e}")

    def on_closing(self):
        if self.file_monitor:
            try: self.file_monitor.stop()
            except: pass
        self.root.destroy()

    def force_refresh(self):
        self.last_files = []
        self.update_table()

    def update_table(self):
        if not self.store_path or not os.path.exists(self.store_path):
            self.root.after(1000, self.update_table)
            return
        
        try: current_files = [f for f in os.listdir(self.store_path) if f.endswith(".enc") and not f.endswith(".meta")]
        except: 
            self.root.after(1000, self.update_table)
            return
        
        if current_files == self.last_files:
            self.root.after(1000, self.update_table)
            return
        
        self.last_files = current_files
        for item in self.table.get_children(): self.table.delete(item)
        
        for f in current_files:
            name = f.replace(".enc", "")
            meta_path = os.path.join(self.store_path, f + ".meta")
            if not os.path.exists(meta_path): continue
            try:
                with open(meta_path, "r") as meta_file: meta = json.load(meta_file)
                mode = meta.get("mode", "unknown")
                pqc = "Yes" if meta.get("pqc") else "No"
                row_id = self.table.insert("", "end", values=(name, mode.capitalize(), pqc))
                self.table.item(row_id, tags=(mode,))
            except: continue
        
        self.root.after(1000, self.update_table)

    def _on_tree_motion(self, event):
        row_id = self.table.identify_row(event.y)
        if row_id == self._last_hover: return
        if self._last_hover:
            vals = self.table.item(self._last_hover, "values")
            if vals: self.table.item(self._last_hover, tags=(vals[1].lower(),))
        if row_id and row_id not in self.table.selection(): self.table.item(row_id, tags=("hover",))
        self._last_hover = row_id

    def _on_tree_leave(self, event):
        if self._last_hover:
            vals = self.table.item(self._last_hover, "values")
            if vals: self.table.item(self._last_hover, tags=(vals[1].lower(),))
        self._last_hover = None

    def get_file_password(self, filename):
        if filename in self.password_cache: return self.password_cache[filename]
        if self.enc: return self.password_entry.get().strip()
        return None

    def decrypt_and_view(self):
        selected = self.table.selection()
        if not selected: return messagebox.showerror("Error", "Select a file first.")
        filename = self.table.item(selected[0])["values"][0]
        self.decrypt_file_with_password(filename)

    def decrypt_file_with_password(self, filename, password=None):
        if password is None:
            password = self.get_file_password(filename)
            if password is None: return self.try_different_password_for_file(filename)
        
        enc_path = os.path.join(self.store_path, filename + ".enc")
        meta_path = os.path.join(self.store_path, filename + ".enc.meta")
        
        if not os.path.exists(enc_path) or not os.path.exists(meta_path):
            return messagebox.showerror("Error", "File or metadata not found!")
        
        try:
            temp_enc = AdaptiveEncryptor(password)
            with open(enc_path, "rb") as f: ciphertext = f.read()
            with open(meta_path, "r") as f: meta = json.load(f)
            plaintext = temp_enc.decrypt_file(ciphertext, meta)
            self.current_file_content = plaintext
            self.current_filename = filename
            self.password_cache[filename] = password
            self.display_content(plaintext, filename)
            self.status_indicator.configure(text="● Decrypted", text_color="#0b846b")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt file: {str(e)}")
            if filename in self.password_cache: del self.password_cache[filename]
            self.status_indicator.configure(text="● Error", text_color="#e11d48")

    def try_different_password(self):
        selected = self.table.selection()
        if not selected: return messagebox.showerror("Error", "Select a file first.")
        filename = self.table.item(selected[0])["values"][0]
        self.try_different_password_for_file(filename)

    def try_different_password_for_file(self, filename):
        password = ctk.CTkInputDialog(text=f"Enter password for '{filename}':", title="Enter Password").get_input()
        if password is None: return
        if password == "":
            if self.enc: password = self.password_entry.get().strip()
            else: return messagebox.showerror("Error", "No current password set. Please enter a password.")
        self.decrypt_file_with_password(filename, password)

    def display_content(self, content: bytes, filename: str):
        self._show_content(self.text_content, "Text")
        self.clear_displays()
        self.update_info(content, filename)
        
        file_ext = os.path.splitext(filename)[1].lower()
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        text_exts = ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.md', '.py', '.js', '.css']
        
        if file_ext in image_exts:
            self.display_image(content, filename)
            self.show_image()
        elif file_ext in text_exts or self.is_text(content):
            self.display_text(content, filename)
            self.show_text()
        else:
            self.display_binary(content, filename)
            self.show_text()

    def clear_displays(self):
        for widget in [self.text_content, self.info_content]:
            try:
                widget.config(state="normal")
                widget.delete(1.0, "end")
            except: pass
        try:
            self.image_label.configure(image=None, text="")
            if hasattr(self.image_label, "image_ref"): del self.image_label.image_ref
        except: pass

    def update_info(self, content: bytes, filename: str):
        file_ext = os.path.splitext(filename)[1].lower()
        file_size = len(content)
        file_type = self.detect_file_type(content, file_ext)
        info = f"File: {filename}\nSize: {file_size:,} bytes\nType: {file_type}\nExtension: {file_ext}\n"
        info += f"Content Preview: {'Yes' if self.is_previewable(file_ext) else 'No (use Open Externally)'}\n"
        try:
            self.info_content.insert(1.0, info)
            self.info_content.config(state="disabled")
        except: pass

    def detect_file_type(self, content: bytes, file_ext: str) -> str:
        if len(content) < 4: return "Unknown"
        magic = content[:4]
        magic_map = {
            b'%PDF': "PDF Document", b'\x50\x4B\x03\x04': self._detect_office_file(file_ext),
            b'\xD0\xCF\x11\xE0': self._detect_old_office_file(file_ext), b'\x89PNG': "PNG Image",
            b'\xFF\xD8\xFF': "JPEG Image", b'GIF8': "GIF Image"
        }
        for pattern, file_type in magic_map.items():
            if magic.startswith(pattern): return file_type
        return "Text File" if self.is_text(content) else "Binary File"

    def _detect_office_file(self, file_ext):
        office_map = {'.pptx': 'PowerPoint', '.ppt': 'PowerPoint', '.docx': 'Word', 
                     '.doc': 'Word', '.xlsx': 'Excel', '.xls': 'Excel'}
        return f"{office_map.get(file_ext, 'ZIP')} Document"

    def _detect_old_office_file(self, file_ext):
        office_map = {'.ppt': 'PowerPoint', '.pps': 'PowerPoint', '.doc': 'Word', 
                     '.dot': 'Word', '.xls': 'Excel', '.xlt': 'Excel'}
        return f"{office_map.get(file_ext, 'OLE2')} Document"

    def is_previewable(self, file_ext: str) -> bool:
        previewable = ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.md',
                      '.py', '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        return file_ext in previewable

    def is_text(self, data: bytes):
        try: data.decode('utf-8'); return True
        except: return False

    def display_text(self, content: bytes, filename: str):
        try:
            text = content.decode('utf-8', errors='replace')
            if len(text) > 100000: text = text[:100000] + "\n\n...[Content truncated for display - use Export to save full file]..."
            self.text_content.insert(1.0, f"--- Content of {filename} ---\n\n{text}")
            self.text_content.config(state="disabled")
        except: self.display_binary(content, filename)

    def display_binary(self, content: bytes, filename: str):
        file_ext = os.path.splitext(filename)[1].lower()
        if self.is_previewable(file_ext): display_text = f"--- Binary Content of {filename} ---\n\nThis file appears to be binary but has a previewable extension."
        else: display_text = f"--- Binary File: {filename} ---\n\nThis file format cannot be displayed in the text viewer."
        data_to_dump = content[:1024] if len(content) > 10240 else content
        hex_dump = self.create_hex_dump(data_to_dump)
        display_text += f"\n\nHex dump ({len(data_to_dump)} of {len(content)} bytes):\n\n{hex_dump}"
        if len(content) > 10240: display_text += f"\n\n...[Truncated - full file is {len(content)} bytes]"
        self.text_content.insert(1.0, display_text)
        self.text_content.config(state="disabled")

    def create_hex_dump(self, data: bytes):
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(f'{i:08x}: {hex_part:<48} {ascii_part}')
        return '\n'.join(result)

    def display_image(self, content: bytes, filename: str):
        try:
            image = Image.open(io.BytesIO(content))
            img_width, img_height = image.size
            ratio = min(900 / img_width, 700 / img_height, 1.0)
            new_size = (int(img_width * ratio), int(img_height * ratio))
            image = image.resize(new_size, Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(image)
            self.image_label.configure(image=photo, text="")
            self.image_label.image_ref = photo
        except Exception as e:
            self.text_content.insert(1.0, f"Error displaying image: {str(e)}\n\nFile: {filename}\nSize: {len(content)} bytes")
            self.text_content.config(state="disabled")
            self.show_text()

    def open_externally(self):
        if not self.current_file_content: return messagebox.showerror("Error", "No file content to open. Please decrypt a file first.")
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=self.current_filename) as temp_file:
                temp_file.write(self.current_file_content)
                temp_path = temp_file.name
            if platform.system() == 'Windows': os.startfile(temp_path)
            elif platform.system() == 'Darwin': subprocess.run(['open', temp_path])
            else: subprocess.run(['xdg-open', temp_path])
            messagebox.showinfo("Success", f"Opening {self.current_filename} with default application...")
        except Exception as e: messagebox.showerror("Error", f"Failed to open file: {e}")

    def export_decrypted(self):
        if not self.current_file_content: return messagebox.showerror("Error", "No file content to export")
        save_path = filedialog.asksaveasfilename(title="Save decrypted file as...", initialfile=self.current_filename)
        if save_path:
            try:
                with open(save_path, "wb") as f: f.write(self.current_file_content)
                messagebox.showinfo("Success", f"File exported to:\n{save_path}")
            except Exception as e: messagebox.showerror("Error", f"Failed to save: {e}")

    def check_dependencies(self):
        """Check if all required dependencies are available"""
        missing_deps = []
        try:
            import customtkinter
        except ImportError:
            missing_deps.append("customtkinter")
    
        try:
            from PIL import Image, ImageTk
        except ImportError:
            missing_deps.append("Pillow")
    
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            missing_deps.append("cryptography")
    
        try:
            from argon2.low_level import hash_secret_raw, Type
        except ImportError:
            missing_deps.append("argon2-cffi")
    
        try:
            from watchdog.observers import Observer
        except ImportError:
            missing_deps.append("watchdog")
    
        return missing_deps

    def show_dependency_error(self, missing_deps):
        """Show error message for missing dependencies"""
        error_msg = f"Missing dependencies:\n\n" + "\n".join(f"• {dep}" for dep in missing_deps)
        error_msg += "\n\nPlease install using:\npip install " + " ".join(missing_deps)
        messagebox.showerror("Missing Dependencies", error_msg)

if __name__ == "__main__":
    SecureGUI()