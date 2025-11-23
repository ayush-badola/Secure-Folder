import os
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, encryptor, mount_path, store_path, status_callback=None):
        self.encryptor = encryptor
        self.mount_path = mount_path
        self.store_path = store_path
        self.status_callback = status_callback
        self.retry_count = 3
        self.retry_delay = 0.5

    def on_modified(self, event):
        if event.is_directory:
            return
        self.encrypt_with_retry(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self.encrypt_with_retry(event.src_path)

    def encrypt_with_retry(self, path):
        """Try to encrypt with retries for file locking issues"""
        for attempt in range(self.retry_count):
            try:
                if self.encrypt(path):
                    break
                else:
                    time.sleep(self.retry_delay)
            except Exception as e:
                if attempt < self.retry_count - 1:
                    print(f"Error on attempt {attempt + 1}, retrying...: {e}")
                    time.sleep(self.retry_delay)
                else:
                    print(f"Failed to encrypt {path} after {self.retry_count} attempts: {e}")
                    if self.status_callback:
                        self.status_callback(f"Failed to encrypt {os.path.basename(path)}")

    def encrypt(self, path):
        if self.encryptor is None:
            print("Encryptor not initialized.")
            return False
            
        filename = os.path.basename(path)
        print(f"Encrypting: {filename}")
        
        # Check if file still exists and is accessible
        if not os.path.exists(path):
            print(f"File {path} no longer exists")
            return False

        try:
            # Wait a moment for file to be completely written
            time.sleep(0.1)
            
            with open(path, "rb") as f:
                data = f.read()
                
            if len(data) == 0:
                print(f"File {filename} is empty, skipping")
                return False

            ciphertext, meta = self.encryptor.encrypt_file(data, filename)
            meta_path = os.path.join(self.store_path, filename + ".enc.meta")
            enc_path = os.path.join(self.store_path, filename + ".enc")
            
            # Write metadata first
            with open(meta_path, "w") as f:
                json.dump(meta, f)
            
            # Then write encrypted data
            with open(enc_path, "wb") as f:
                f.write(ciphertext)
            
            # Verify both files were written successfully
            if os.path.exists(meta_path) and os.path.exists(enc_path):
                try:
                    os.remove(path)
                    print(f"Successfully encrypted: {filename}")
                    if self.status_callback:
                        self.status_callback(f"Encrypted: {filename}")
                    return True
                except PermissionError as e:
                    print(f"Could not remove original file {filename}: {e}")
                    print("File was encrypted but original remains")
                    return True
            else:
                print(f"Error: Encrypted files not created properly for {filename}")
                return False
                
        except PermissionError as e:
            print(f"Permission denied reading {filename}: {e}")
            return False
        except Exception as e:
            print(f"Error processing file {filename}: {e}")
            return False

class FileMonitor:
    def __init__(self, mount_path, store_path, encryptor, status_callback=None):
        self.mount_path = mount_path
        self.store_path = store_path
        self.encryptor = encryptor
        self.status_callback = status_callback
        self.observer = None
        self.running = False
        
        # Create directories if they don't exist
        os.makedirs(mount_path, exist_ok=True)
        os.makedirs(store_path, exist_ok=True)

    def start(self):
        """Start the file monitor"""
        try:
            if self.observer:
                self.stop()

            event_handler = FileMonitorHandler(self.encryptor, self.mount_path, self.store_path, self.status_callback)
            self.observer = Observer()
            self.observer.schedule(event_handler, self.mount_path, recursive=False)
            self.observer.start()
            
            self.running = True
            if self.status_callback:
                self.status_callback("Running")
            print("File monitor started successfully!")
            
        except Exception as e:
            print(f"Error starting file monitor: {e}")
            if self.status_callback:
                self.status_callback("Error")
            raise

    def stop(self):
        """Stop the file monitor"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.running = False
        if self.status_callback:
            self.status_callback("Stopped")
        print("File monitor stopped.")