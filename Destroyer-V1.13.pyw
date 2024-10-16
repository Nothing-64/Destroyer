import tkinter as tk
from tkinter import filedialog, messagebox
import pyautogui
import pyperclip
import threading
import psutil
import pygetwindow as gw
import keyboard

typing_active = False
selected_image_path = None
start_hotkey = "f9"
stop_hotkey = "f10"

def paste_text(text):
    pyperclip.copy(text)
    pyautogui.hotkey("ctrl", "v")
    pyautogui.press("enter")
    pyautogui.press("enter")
    pyautogui.hotkey("ctrl", "a")
    pyautogui.press("backspace")

def upload_image():
    global selected_image_path
    if selected_image_path:
        try:
            corrected_path = selected_image_path.replace("/", "\\")
            pyperclip.copy(corrected_path)

            pyautogui.hotkey("ctrl", "shift", "u")
            
            pyautogui.hotkey("ctrl", "v")
            pyautogui.press("enter")
            pyautogui.press("enter")
            
        except Exception as e:
            messagebox.showerror("오류", f"이미지 전송 실패: {e}")
    else:
        messagebox.showinfo("알림", "선택한 이미지가 없습니다.")
def select_image():
    global selected_image_path
    file_path = filedialog.askopenfilename(
        title="이미지 선택",
        filetypes=[
            ("Image Files", "*.png;*.jpeg;*.jpg;*.gif;*.bmp;*.tiff;*.tif;*.webp;*.heif;*.heic;*.svg;*.cr2;*.nef;*.arw;*.rw2;*.orf;*.raf;*.pef;*.dng;*.ico")
        ]
    )
    if file_path:
        selected_image_path = file_path
        messagebox.showinfo("알림", f"선택된 이미지: {file_path}")

def activate_window(pid):
    try:
        process_name = None
        for proc in psutil.process_iter(["pid", "name"]):
            if proc.info["pid"] == pid:
                process_name = proc.info["name"]
                break
        
        if not process_name:
            messagebox.showerror("오류", "선택한 프로세스를 찾을 수 없습니다.")
            return
        
        windows = gw.getWindowsWithTitle("")
        for window in windows:
            window.activate()
            return
        
        messagebox.showerror("오류", "선택한 프로세스에 창이 없습니다.")
    except Exception as e:
        #messagebox.showerror("오류", f"문제가 발생했습니다: {e}")
        print(e)

def start_typing():
    global typing_active
    typing_active = True
    all_text = text_box.get("1.0", tk.END)
    
    selected_process = process_listbox.get(tk.ACTIVE)
    pid = int(selected_process.split()[0])
    activate_window(pid)

    def typing_thread():
        global typing_active
        text_lines = all_text.splitlines()
        
        while typing_active:
            if text_lines:
                for line in text_lines:
                    if line.strip():
                        paste_text(line)
                        if selected_image_path is None:
                            pyautogui.press("enter")
            
            if selected_image_path:
                upload_image()
    
    threading.Thread(target=typing_thread).start()

def stop_typing():
    global typing_active
    typing_active = False

def get_processes():
    processes = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            processes.append(f"{proc.info["pid"]} - {proc.info["name"]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def refresh_process_list():
    process_listbox.delete(0, tk.END)
    processes = get_processes()
    for process in processes:
        process_listbox.insert(tk.END, process)

def search_process():
    search_term = search_entry.get().lower()
    process_listbox.delete(0, tk.END)
    processes = get_processes()
    for process in processes:
        if search_term in process.lower():
            process_listbox.insert(tk.END, process)

def on_hotkey_start():
    start_typing()

def on_hotkey_stop():
    stop_typing()

def update_hotkey():
    global start_hotkey, stop_hotkey
    start_hotkey = start_hotkey_entry.get()
    stop_hotkey = stop_hotkey_entry.get()
    keyboard.unhook_all()
    keyboard.add_hotkey(start_hotkey, on_hotkey_start)
    keyboard.add_hotkey(stop_hotkey, on_hotkey_stop)
    messagebox.showinfo("알림", "핫키가 업데이트되었습니다.")

root = tk.Tk()
root.title("Discord Server Destroyer V1.13 - By nothing_64_")
root.geometry("850x500")

frame = tk.Frame(root)
frame.pack(pady=10, fill=tk.BOTH, expand=True)

tk.Label(frame, text="텍스트를 입력하세요:").pack()
text_box = tk.Text(frame, height=10, width=100, wrap=tk.WORD)
text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=text_box.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_box.config(yscrollcommand=scrollbar.set)

process_frame = tk.Frame(root)
process_frame.pack(pady=10, fill=tk.BOTH, expand=True)

process_scrollbar = tk.Scrollbar(process_frame, orient=tk.VERTICAL)
process_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

tk.Label(process_frame, text="프로세스를 선택하세요:").pack()

process_listbox = tk.Listbox(process_frame, height=10, width=100, yscrollcommand=process_scrollbar.set)
process_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
process_scrollbar.config(command=process_listbox.yview)

search_frame = tk.Frame(root)
search_frame.pack(pady=10, fill=tk.X)

tk.Label(search_frame, text="프로세스 검색:").pack(side=tk.LEFT, padx=5)

search_entry = tk.Entry(search_frame)
search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

search_button = tk.Button(search_frame, text="검색", command=search_process)
search_button.pack(side=tk.LEFT, padx=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=5)

start_button = tk.Button(button_frame, text="시작!", command=start_typing)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="중지", command=stop_typing)
stop_button.pack(side=tk.LEFT, padx=5)

image_button = tk.Button(button_frame, text="이미지 선택", command=select_image)
image_button.pack(side=tk.LEFT, padx=5)

hotkey_frame = tk.Frame(root)
hotkey_frame.pack(pady=10, fill=tk.X)

tk.Label(hotkey_frame, text="시작 핫키:").pack(side=tk.LEFT, padx=5)
start_hotkey_entry = tk.Entry(hotkey_frame, width=5)
start_hotkey_entry.insert(tk.END, start_hotkey)
start_hotkey_entry.pack(side=tk.LEFT, padx=5)

tk.Label(hotkey_frame, text="중지 핫키:").pack(side=tk.LEFT, padx=5)
stop_hotkey_entry = tk.Entry(hotkey_frame, width=5)
stop_hotkey_entry.insert(tk.END, stop_hotkey)
stop_hotkey_entry.pack(side=tk.LEFT, padx=5)

update_hotkey_button = tk.Button(hotkey_frame, text="핫키 업데이트", command=update_hotkey)
update_hotkey_button.pack(side=tk.LEFT, padx=5)

refresh_process_list()

keyboard.add_hotkey(start_hotkey, on_hotkey_start)
keyboard.add_hotkey(stop_hotkey, on_hotkey_stop)

root.mainloop()
