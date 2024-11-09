import tkinter as tk
from scapy.all import sniff, IP
import threading
 
bg_color = "#d3d3d3"
button_color = "#4f4f4f"
button_fg_color = "white"
 
root = tk.Tk()
root.title("Security")
root.geometry("1600x800")
root.configure(bg=bg_color)
 
ips = []
target_ips = []
 
def start_capture():
    for widget in frame.winfo_children():
        widget.destroy()
 
    label = tk.Label(frame, text="Capturarea pachetelor a început\n", bg="white")
    label.pack(anchor="w", padx=20, pady=10)
 
    sniffing_thread = threading.Thread(target=sniff_packets)
    sniffing_thread.start()
 
def sniff_packets():
    sniff(prn=packet_callback, filter="ip", timeout=30)
 
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_src not in ips:
            ips.append(ip_src)
            update_display(ip_src)
        if ip_dst == "10.0.2.4" and ip_src not in target_ips:
            target_ips.append(ip_src)
            update_display(ip_src, target=True)
 
def update_display(ip, target=False):
    if target:
        label = tk.Label(frame, text=f"IP detectat conectat la 10.0.2.4: {ip}", bg="white")
    else:
        label = tk.Label(frame, text=f"IP detectat: {ip}", bg="white")
    label.pack(anchor="w", padx=20, pady=5)
 
def show_target_ips():
    for widget in frame.winfo_children():
        widget.destroy()
 
    if target_ips:
        label = tk.Label(frame, text="IP-urile care încearcă să se conecteze la 10.0.2.4 sunt:", bg="white")
        label.pack(anchor="w", padx=20, pady=10)
        for ip in target_ips:
            label = tk.Label(frame, text=ip, bg="white")
            label.pack(anchor="w", padx=20, pady=5)
    else:
        label = tk.Label(frame, text="Niciun IP nu a încercat să se conecteze la 10.0.2.4", bg="white")
        label.pack(anchor="w", padx=20, pady=10)
 
canvas = tk.Canvas(root, bg=bg_color)
canvas.pack(expand=True, fill="both")
 
frame = tk.Frame(root, bg="white")
frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)
 
button_frame = tk.Frame(root, bg=bg_color)
button_frame.pack(side="bottom", pady=20)
 
capture_button = tk.Button(button_frame, text="Capturează Pachete", padx=10, pady=5, fg=button_fg_color, bg=button_color, command=start_capture)
capture_button.pack(side="left", padx=10)
 
target_button = tk.Button(button_frame, text="Afișează IP-uri țintă", padx=10, pady=5, fg=button_fg_color, bg=button_color, command=show_target_ips)
target_button.pack(side="left", padx=10)
 
root.mainloop()
