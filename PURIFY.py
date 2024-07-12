import os
import wmi
import time
import hashlib
import requests
from tkinter import *
from tkinter import ttk
from threading import Thread
import traceback
import winreg as reg

class USBDrive:
    def __init__(self, drive_letter):
        self.drive_letter = drive_letter
        self.files = []
        self.scan_drive()

    def scan_drive(self):
        self.files.clear()
        for root, dirs, files in os.walk(self.drive_letter):
            for file in files:
                file_path = os.path.join(root, file)
                self.files.append(file_path)

    def analyze_files(self, progress_callback):
        global malware_count
        malware_count = 0
        results = f"Files in {self.drive_letter}:\n"
        malware_report = "\nMalware Detected:\n"
        total_files = len(self.files)
        for index, file in enumerate(self.files):
            file_hash = get_file_hash(file)
            is_malware, data = check_malware_bazaar(file_hash)
            if is_malware:
                try:
                    malware_type = data['data'][0].get('file_type', 'Unknown')
                    malware_report += f"Malware: {file} \nType: {malware_type}\n"
                    self.delete_file(file)
                    malware_report += "Status: deleted.\n"
                    malware_count += 1
                except KeyError as e:
                    print(f"KeyError: {e} for file {file}")
                    traceback.print_exc()
            if is_suspicious(file):
                results += f"Suspicious file deleted. \nLocation: {file}\n\n"
                self.delete_file(file)
            # Update progress bar
            progress_callback((index + 1) / total_files * 100)

        if malware_count == 0:
            results += "No malware detected. The drive is clean.\n"
        else:
            results += malware_report
        results += "\nScan complete.\n"
        return results

    def delete_file(self, file_path):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"File {file_path} has been deleted.")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_malware_bazaar(file_hash):
    url = 'https://mb-api.abuse.ch/api/v1/'
    params = {
        'query': 'get_info',
        'hash': file_hash
    }
    response = requests.post(url, data=params)
    if response.status_code == 200:
        data = response.json()
        if data['query_status'] == 'ok':
            return True, data
        else:
            return False, None
    else:
        return False, None

def detect_usb_drives():
    c = wmi.WMI()
    drives = []
    for diskdrive in c.Win32_DiskDrive():
        if "USB" in diskdrive.InterfaceType:
            for partition in diskdrive.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    drives.append(logical_disk.Caption)
    return drives

def update_usb_drives():
    global usb_listbox, selected_drive, select_time
    usb_listbox.delete(0, END)
    usb_drives = detect_usb_drives()
    for drive in usb_drives:
        usb_listbox.insert(END, drive)
        if drive == selected_drive:
            index = usb_listbox.get(0, END).index(drive)
            usb_listbox.itemconfig(index, bg='gray', fg='black')
    window.after(1000, update_usb_drives)

def select_drive(event):
    global selected_drive, select_time, usb_listbox
    selected_index = usb_listbox.curselection()
    if selected_index:
        selected_drive = usb_listbox.get(selected_index[0])
        select_time = time.time()
        # Clear previous selection highlight
        for i in range(usb_listbox.size()):
            usb_listbox.itemconfig(i, bg='#2f2f2f', fg='white')
        # Highlight the selected drive
        usb_listbox.itemconfig(selected_index[0], bg='gray', fg='black')
        usb_listbox.selection_clear(0, END)  # Clear default selection

def scan_drive():
    global selected_drive, loading_frame, progress_var
    if selected_drive:
        if check_internet_connection():
            # Show loading overlay
            loading_frame.lift()
            loading_frame.grid(row=0, column=0, rowspan=3, columnspan=2, sticky="nsew")

            # Reset progress bar
            progress_var.set(0)

            # Start the scanning process in a new thread
            scan_thread = Thread(target=perform_scan)
            scan_thread.start()
        else:
            display_error("Cannot perform scanning.\nPlease connect to the internet to start scanning.")

def check_internet_connection():
    try:
        requests.get("http://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

def perform_scan():
    try:
        global selected_drive, loading_frame, progress_var
        usb_drive = USBDrive(selected_drive)
        results = usb_drive.analyze_files(update_progress)
        # Hide loading overlay and show results
        loading_frame.grid_forget()
        display_results(results)
    except Exception as e:
        print(f"Error during scan: {e}")
        traceback.print_exc()

def update_progress(value):
    progress_var.set(value)

def display_results(results):
    results_window = Toplevel(window)
    results_window.title("Scan Results")
    results_window.geometry("600x400")
    result_text = Text(results_window, font=('Bahnschrift', 12), bg='#2f2f2f', fg='white', wrap=WORD)
    result_text.pack(expand=True, fill=BOTH)
    result_text.insert(END, results)

def display_error(message):
    error_window = Toplevel(window)
    error_window.title("No internet connection")
    error_window.geometry("400x200")
    error_label = Label(error_window, text=message, font=('Bahnschrift', 12), fg='red')
    error_label.pack(expand=True, fill=BOTH)

def disable_autorun():
    try:
        # Open the registry key
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, reg.KEY_SET_VALUE)
        # Set the value to disable Autorun
        reg.SetValueEx(key, "NoDriveTypeAutoRun", 0, reg.REG_DWORD, 0xFF)
        reg.CloseKey(key)
        print("Autorun has been disabled.")
    except Exception as e:
        print(f"Error disabling Autorun: {e}")

def is_suspicious(file):
    # Define suspicious file types
    suspicious_extensions = ['.dll','.elf','.apk','.exe', '.bat', '.vbs', '.js', '.ps1']
    file_extension = os.path.splitext(file)[1].lower()
    return file_extension in suspicious_extensions

window = Tk()
window.title("PURIFY: A USB Drive Sanitizer")
window.geometry("1000x500")

# create all of the main containers
top_frame = Frame(window, bg='#cc5500', width=450, height=50, pady=3)
ctr_left = Frame(window, bg='black', width=250, height=190, padx=3, pady=3)
ctr_left_top = Frame(window, bg='grey', width=200, height=30, padx=3, pady=3)
ctr_right = Frame(window, bg='#2f2f2f', width=300, height=190, padx=3, pady=3)

# layout all of the main containers
window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(1, weight=1)

top_frame.grid(row=0, columnspan=2, sticky="ew")
ctr_left.grid(row=2, column=0, sticky="nsew")
ctr_left_top.grid(row=1, column=0, sticky="new")
ctr_right.grid(row=1, column=1, rowspan=2, sticky="nsew")

# label for top orange
model_label = Label(top_frame, text="PURIFY", bg="#cc5500", font=('Bebas', 20), fg="white")
model_label.grid(row=2, columnspan=3)

# label for grey kiri atas
label2 = Label(ctr_left_top, text="USB Drive Detected", font=('Bahnschrift', 12), bg='grey')
label2.grid(row=0)

ctr_right.grid_rowconfigure(2, weight=1)
ctr_right.grid_columnconfigure(2, weight=1)

# label for grey tengah
label3 = Label(ctr_right, text="Welcome to PURIFY!\n\nPlease make sure that device is connected to the Internet\n\nPlug in your USB drive and Get Started", font=('Bahnschrift', 14), bg='#2f2f2f', fg='white')
label3.grid(row=1, column=2)

usb_listbox = Listbox(ctr_left, font=('Bahnschrift', 12), bg='#2f2f2f', fg='white', selectbackground='#2f2f2f', selectforeground='white')
usb_listbox.grid(row=2, column=2)

# Bind click event to listbox item selection
usb_listbox.bind('<ButtonRelease-1>', select_drive)

scanButton = Button(ctr_right, text="Sanitize", command=scan_drive, font=('Bahnschrift', 14), bg='#2f2f2f', fg='white')
scanButton.grid(row=2, column=2)

# Create loading overlay frame
loading_frame = Frame(window, bg='#2f2f2f')
loading_label = Label(loading_frame, text="Scanning in progress...\nPlease wait.", font=('Bahnschrift', 20), fg='white', bg='#2f2f2f')
loading_label.place(relx=0.5, rely=0.5, anchor=CENTER)

# Create progress bar
progress_var = DoubleVar()
progress_bar = ttk.Progressbar(loading_frame, variable=progress_var, maximum=100)
progress_bar.place(relx=0.5, rely=0.6, anchor=CENTER, width=300)

# Initialize variables
selected_drive = None
select_time = 0

# Disable Autorun on startup
disable_autorun()

# Automatically update the list of USB drives every second
update_usb_drives()

window.mainloop()
