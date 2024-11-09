import tkinter as tk
import re
import os

color = "#7a73ff"

root = tk.Tk()
root.title("Security")
root.geometry("1600x800")
root.configure(bg=color)

ips = []

def read_network_activity(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
    return lines

def find_ips(lines):
    suspicious_ips = set()
    for line in lines:
        match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d+\.\d+\.\d+\.\d+),(.+)$', line)
        if match:
            timestamp, ip, command = match.groups()
            if 'rm -rf' in command or 'nc -e' in command:
                suspicious_ips.add(ip)
    return suspicious_ips

def detect():
    for widget in frame.winfo_children():
        widget.destroy()

    filename = 'network_activity.txt'
    label = tk.Label(frame, text="Detectarea activitatii retelei", bg="white")
    label.pack(anchor="w", padx=20, pady=10)

    lines = read_network_activity(filename)
    label = tk.Label(frame, text=f"{len(lines)} linii de activitate au fost citite\n", bg="white")
    label.pack(anchor="w", padx=20, pady=10)

    suspicious_ips = find_ips(lines)
    if suspicious_ips:
        label = tk.Label(frame, text="IP-urile suspecte sunt:", bg="white")
        label.pack(anchor="w", padx=20, pady=10)
        for ip in suspicious_ips:
            label = tk.Label(frame, text=ip, bg="white")
            label.pack(anchor="w", padx=20, pady=5)
    else:
        label = tk.Label(frame, text="IP-uri suspecte nu au fost gasite", bg="white")
        label.pack(anchor="w", padx=20, pady=10)

canvas = tk.Canvas(root, bg=color)
canvas.pack(expand=True, fill="both")

frame = tk.Frame(root, bg="white")
frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)

detect_button = tk.Button(root, text="Detect IP", padx=10, pady=5, fg="white", bg=color, command=detect)
detect_button.pack(side="bottom", pady=20)

root.mainloop()
