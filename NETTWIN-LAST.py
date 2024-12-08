import tkinter as tk 
from tkinter import ttk
import tkinter.font as tkfont
from tkinter import messagebox
import netifaces as ni
import ipaddress
import scapy.all as scapy
import socket
import subprocess
import pyshark
from collections import defaultdict
import os
import PIL
from PIL import Image,ImageTk
import networkx as nx
import matplotlib.pyplot as plt

max_delay = 0.10
max_traffic = 500

from matplotlib.backends.backend_tkagg import (
    FigureCanvasTkAgg, NavigationToolbar2Tk)
class ScrollFrame(tk.Frame):
    def __init__(self, master=None, scroll_speed=2,
                 hscroll=True, vscroll=True, **kwargs):        
        assert isinstance(scroll_speed, int), "`scroll_speed` must be an int"
        self.scroll_speed = scroll_speed
    
        self.master_frame = tk.Frame(master, bg="#0E0325")
        self.master_frame.pack(side="left", fill="both", expand=True)
        self.dummy_canvas = tk.Canvas(self.master_frame, **kwargs)
        super().__init__(self.dummy_canvas,bg="#0E0325")
        
        # Create the 2 scrollbars
        if vscroll:
            self.v_scrollbar = tk.Scrollbar(self.master_frame,
                                            orient="vertical",
                                            command=self.dummy_canvas.yview,bg="#0E0325")
            self.v_scrollbar.pack(side="right", fill="y")
            self.dummy_canvas.configure(yscrollcommand=self.v_scrollbar.set)
        if hscroll:
            self.h_scrollbar = tk.Scrollbar(self.master_frame,
                                            orient="horizontal",
                                            command=self.dummy_canvas.xview,bg="#0E0325")
            self.h_scrollbar.pack(side="bottom", fill="x")
            self.dummy_canvas.configure(xscrollcommand=self.h_scrollbar.set)
 
        # Bind to the mousewheel scrolling
        self.dummy_canvas.bind_all("<MouseWheel>", self.scrolling_windows,
                                   add=True)
        self.dummy_canvas.bind_all("<Button-4>", self.scrolling_linux, add=True)
        self.dummy_canvas.bind_all("<Button-5>", self.scrolling_linux, add=True)
        self.bind("<Configure>", self.scrollbar_scrolling, add=True)
 
        # Place `self` inside `dummy_canvas`
        self.dummy_canvas.create_window((10, 10), window=self, anchor="nw")
        # Place `dummy_canvas` inside `master_frame`
        self.dummy_canvas.pack(side="right", expand=True, fill="both")
 
        self.pack = self.master_frame.pack
        self.grid = self.master_frame.grid
        self.place = self.master_frame.place
        self.pack_forget = self.master_frame.pack_forget
        self.grid_forget = self.master_frame.grid_forget
        self.place_forget = self.master_frame.place_forget
 
    def scrolling_windows(self, event):
        assert event.delta != 0, "On Windows, `event.delta` should never be 0"
        y_steps = int(-event.delta/abs(event.delta)*self.scroll_speed)
        self.dummy_canvas.yview_scroll(y_steps, "units")
 
    def scrolling_linux(self, event):
        y_steps = self.scroll_speed
        if event.num == 4:
            y_steps *= -1
        self.dummy_canvas.yview_scroll(y_steps, "units")
 
    def scrollbar_scrolling(self, event):
        region = list(self.dummy_canvas.bbox("all"))
        region[2] = max(self.dummy_canvas.winfo_width(), region[2])
        region[3] = max(self.dummy_canvas.winfo_height(), region[3])
        self.dummy_canvas.configure(scrollregion=region)
 
    def resize(self, height=None, width=None):
    
        super().update()
        self.dummy_canvas.config(width=super().winfo_width())
        super().update()
        self.dummy_canvas.config(height=super().winfo_height())
        if height is not None:
            self.dummy_canvas.config(height=height)
        if width is not None:
            self.dummy_canvas.config(width=width)
    fit = resize

class FullScreenLoginSystem:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NetTwin Real-Time Network Twin & Monitoring")
     
        self.root.state('normal')
        
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        
        self.root.geometry(f"{self.screen_width}x{self.screen_height}")
        
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.create_styles()
        self.current_window = None
        self.is_logged_in = False
        self.devices = None
        self.create_pre_login_menu()

    def get_router_ip(self):
        """Get the IP address of the router (default gateway)."""
        gateway_info = ni.gateways()
        router_ip = gateway_info['default'][ni.AF_INET][0]  # Extract router IP (default gateway)
        return router_ip

    def get_network_range(self):
        """Get the network range from the active interface."""
        iface_name = ni.gateways()['default'][ni.AF_INET][1]  # Default network interface
        ip_info = ni.ifaddresses(iface_name)[ni.AF_INET][0]  # IPv4 info
        ip_address = ip_info['addr']
        subnet_mask = ip_info['netmask']
    
        # Calculate the network range using ipaddress
        network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
        return str(network)

    def scan_network(self,ip_range):
        """Scan the network for connected devices using ARP."""
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        devices = []
        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
        return devices

    def capture_traffic(self, duration, output_file):
        """Capture network traffic and save it to a PCAP file."""
        print(f"Capturing traffic for {duration} seconds...")
        packets = scapy.sniff(timeout=duration)
        scapy.wrpcap(output_file, packets)
        print(f"Traffic saved to {output_file}")

    def get_device_name(self,ip):
        """Get the hostname for a given IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"


    def ping_device(self, ip):
        """Ping the device to check connectivity status on Windows."""
        try:
            command = None
            # Test if os is linux
            if os.name == 'posix':
                command = ['ping', '-c', '1', ip]
            else:
                command = ['ping', '-n', '1', ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0  # Return True if the ping is successful (ping success)
        except Exception as e:
            return False  # Ping failed

    def analyze_pcap(self, pcap_file, scanned_ips):
        """Analyze PCAP file and create digital twins for devices that were scanned."""
        cap = pyshark.FileCapture(pcap_file)
        digital_twins = defaultdict(lambda: {
            'traffic_count': 0, 
            'delay': 0, 
            'connected_ips': set(), 
            'total_bytes': 0,
            'icmp_requests': 0,
            'icmp_replies': 0,
            'src_to_dst': defaultdict(int),  # Count traffic from source to destination
            'dst_to_src': defaultdict(int)   # Count traffic from destination to source
        })
        ip_last_seen = {}
        timestamps = []

        for packet in cap:
            try:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    # Only process packets where IP addresses were part of the scanned devices
                    if src_ip in scanned_ips or dst_ip in scanned_ips:
                        timestamp = float(packet.sniff_time.timestamp())
                        timestamps.append(timestamp)

                        # Process source and destination traffic
                        digital_twins[src_ip]['src_to_dst'][dst_ip] += 1
                        digital_twins[dst_ip]['dst_to_src'][src_ip] += 1

                        # Calculate delay between packets
                        for ip in (src_ip, dst_ip):
                            if ip in ip_last_seen:
                                delay = timestamp - ip_last_seen[ip]
                                digital_twins[ip]['delay'] += delay
                            ip_last_seen[ip] = timestamp

                            # Track traffic, connected IPs, and total bytes
                            digital_twins[ip]['traffic_count'] += 1
                            digital_twins[ip]['connected_ips'].add(dst_ip)
                            digital_twins[ip]['total_bytes'] += int(packet.length)

                        # ICMP analysis
                        if packet.highest_layer == "ICMP":
                            if packet.icmp.type == '8':  # ICMP request (ping)
                                digital_twins[src_ip]['icmp_requests'] += 1
                            elif packet.icmp.type == '0':  # ICMP reply
                                digital_twins[src_ip]['icmp_replies'] += 1

            except AttributeError:
                pass

        cap.close()

        # Calculate total delay
        total_delay = sum(j - i for i, j in zip(timestamps[:-1], timestamps[1:]))
        print(f"Total delay calculated: {total_delay:.2f} seconds")
        if total_delay > max_delay:
            #show alert 
            messagebox.showerror("Error Delay", "The network is too slow. delay is too high.")
       
        total_traffic = sum(digital_twins[ip]['total_bytes'] for ip in digital_twins)
        if total_traffic > max_traffic:
            messagebox.showerror("Error Traffic", "The network is too busy. traffic is too high.")

        if not digital_twins:
            print("No traffic data found in PCAP.")
        return digital_twins, total_delay   


    def create_styles(self):
        self.title_font = tkfont.Font(family="Times New Roman", size=24, weight="bold")
        self.subtitle_font = tkfont.Font(family="Times New Roman", size=16, weight="bold")
        self.header_font = tkfont.Font(family="Times New Roman", size=16, weight="bold")
        self.normal_font = tkfont.Font(family="Times New Roman", size=12)
        self.button_font = tkfont.Font(family="Times New Roman", size=12, weight="bold")

    def create_pre_login_menu(self):
        if self.current_window:
            self.current_window.destroy()

        # Main background
        self.current_window = tk.Frame(self.root, bg="#0E0325")
        self.current_window.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Left panel for logo and title
        left_panel = tk.Frame(self.current_window, bg="#E8FEFF", width=400)
        left_panel.place(relx=0, rely=0, relwidth=0.3, relheight=1)

        # Logo and title in left panel
        try:
            # Load logo image using Pillow (supports .png)
            logo_path = r"C:/Users/renad/OneDrive/سطح المكتب/logo2.jpg"
            logo_image = Image.open(logo_path)
            logo_image = ImageTk.PhotoImage(logo_image)

            # Display the logo in the left panel
            logo_label = tk.Label(left_panel, image=logo_image, bg="#E8FEFF")
            logo_label.image = logo_image  # Keep a reference to avoid garbage collection
            logo_label.place(relx=0.5, rely=0.4, anchor="center")
        except Exception as e:
            print(f"Error loading logo: {e}")
            # If logo fails to load, display placeholder text instead
            logo_label = tk.Label(left_panel, text="Logo Failed to Load", font=self.title_font, bg="#E8FEFF", fg="#0E0325")
            logo_label.place(relx=0.5, rely=0.4, anchor="center")

        # Right panel for menu options
        right_panel = tk.Frame(self.current_window, bg="#1e3a7c")
        right_panel.place(relx=0.3, rely=0, relwidth=0.7, relheight=1)

        # Menu container
        menu_frame = tk.Frame(right_panel, bg="#1e3a7c")
        menu_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Login Option
        login_frame = tk.Frame(menu_frame, bg="#1e3a7c", padx=20, pady=20)
        login_frame.pack(pady=20)

        login_title = tk.Label(login_frame,
                             text="Login",
                             font=self.header_font,
                             bg="#1e3a7c",
                             fg="#E8FEFF")
        login_title.pack()

        login_desc = tk.Label(login_frame,
                            text="Access your dashboard and monitoring tools",
                            font=self.normal_font,
                            bg="#1e3a7c",
                            fg="#E8FEFF")
        login_desc.pack(pady=5)

        login_btn = tk.Button(login_frame,
                            text="Login Now",
                            font=self.button_font,
                            bg="#0E0325",
                            fg="white",
                            command=self.create_login_page,
                            cursor="hand2",
                            relief="flat",
                            padx=30,
                            pady=10)
        login_btn.pack(pady=10)
        self.bind_hover_events(login_btn)

        # Separator
        separator = ttk.Separator(menu_frame, orient='horizontal')
        separator.pack(fill='x', pady=20)

        # About Us Option
        about_frame = tk.Frame(menu_frame, bg="#1e3a7c", padx=20, pady=20)
        about_frame.pack(pady=20)

        about_title = tk.Label(about_frame,
                             text="About Us",
                             font=self.header_font,
                             bg="#1e3a7c",
                             fg="#E8FEFF")
        about_title.pack()

        about_desc = tk.Label(about_frame,
                            text="Learn more about our services and technology",
                            font=self.normal_font,
                            bg="#1e3a7c",
                            fg="#E8FEFF")
        about_desc.pack(pady=5)

        about_btn = tk.Button(about_frame,
                            text="About Us",
                            font=self.button_font,
                            bg="#0E0325",
                            fg="white",
                            command=self.show_about_us_page,
                            cursor="hand2",
                            relief="flat",
                            padx=30,
                            pady=10)
        about_btn.pack(pady=10)
        self.bind_hover_events(about_btn)

    def bind_hover_events(self, button):
        button.bind("<Enter>", lambda e: self.on_hover(e, button))
        button.bind("<Leave>", lambda e: self.on_leave(e, button))

    def on_hover(self, event, button):
        button.configure(bg="#84b2e0", fg="#1e3a7c")

    def on_leave(self, event, button):
        button.configure(bg="#1e3a7c", fg="white")

    def create_login_page(self):
        response = messagebox.askyesno("Just a quick check", 
                                         "If this is the right network, go ahead and click ‘Agree.’ If not, feel free to switch networks before logging in")
        if not response:
            return  # If the user selects 'No', return and do not show the login page

        if self.current_window:
            self.current_window.destroy()

        # Set background color for all other pages
        self.current_window = tk.Frame(self.root, bg="#0E0325")
        self.current_window.place(relx=0, rely=0, relwidth=1, relheight=1)

        login_frame = tk.Frame(self.current_window, bg="#1e3a7c", padx=40, pady=40)
        login_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=650)

        title = tk.Label(login_frame, 
                         text="NetTwin", 
                         font=self.title_font, 
                         bg="#1e3a7c", 
                         fg="white")
        title.pack(pady=(0, 10))

        subtitle = tk.Label(login_frame, 
                            text="Real-Time Network Twin & Monitoring", 
                            font=self.subtitle_font, 
                            bg="#1e3a7c", 
                            fg="#84b2e0")
        subtitle.pack(pady=(0, 40))

        # Username entry
        username_label = tk.Label(login_frame, 
                                  text="Username", 
                                  font=self.normal_font, 
                                  bg="#1e3a7c", 
                                  fg="white")
        username_label.pack(anchor="w")
        
        self.username_entry = tk.Entry(login_frame, 
                                       font=self.normal_font,
                                       bg="#2d4477",
                                       fg="white",
                                       textvariable="admin",
                                       insertbackground="white")
        self.username_entry.insert(0,"admin")
      
        
        self.username_entry.pack(fill="x", pady=(5, 0))

        # Password entry
        password_label = tk.Label(login_frame, 
                                  text="Password", 
                                  font=self.normal_font, 
                                  bg="#1e3a7c", 
                                  fg="white")
        password_label.pack(anchor="w")
        
        self.password_entry = tk.Entry(login_frame, 
                                       font=self.normal_font,
                                       bg="#2d4477",
                                       fg="white",
                                       show="●",
                                       textvariable="admin123",
                                       insertbackground="white")
        
        self.password_entry.pack(fill="x", pady=(5, 0))
        self.password_entry.insert(0,"admin123")

        # Login button
        login_btn = tk.Button(login_frame, 
                              text="LOGIN", 
                              font=self.button_font,
                              bg="#84b2e0",
                              fg="black",
                              command=self.login,
                              cursor="hand2",
                              relief="flat",
                              padx=40,
                              pady=10)
        login_btn.pack(pady=30)

        # Back button
        back_btn = tk.Button(login_frame, 
                        text="← Back", 
                        font=self.button_font,
                        bg="#84b2e0",
                        fg="black",
                        command=self.create_pre_login_menu,
                        cursor="hand2",
                        relief="flat")
        back_btn.pack(anchor="nw", pady=(0, 20))

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if username == "admin" and password == "admin123":
            self.is_logged_in = True
            self.create_main_interface()
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password.")

    def create_main_interface(self):
        if self.current_window:
            self.current_window.destroy()

        self.current_window = tk.Frame(self.root, bg="#0E0325")
        self.current_window.place(relx=0, rely=0, relwidth=1, relheight=1)

        sidebar = tk.Frame(self.current_window, bg="#1e3a7c", width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        logo_frame = tk.Frame(sidebar, bg="#1e3a7c")
        logo_frame.pack(fill="x", pady=20)
        tk.Label(logo_frame, text="NetTwin", font=self.title_font, bg="#1e3a7c", fg="white").pack()
        tk.Label(logo_frame, text="Real-Time Network\n Twin & Monitoring", font=self.normal_font, bg="#1e3a7c", fg="#84b2e0").pack()

        # Sidebar Menu
        menu_items = [
            ("Home", self.show_home_page),
            ("Guidelines", self.show_guidelines_page),
            ("About Us", self.show_about_us_page),
            ("Digital Twin", self.show_digital_twin_page),
            ("Network", self.show_network_page),
            ("Logout", self.logout)
        ]

        for text, command in menu_items:
            btn = tk.Button(sidebar, 
                            text=text,
                            font=self.normal_font,
                            bg="#1e3a7c",
                            fg="white",
                            bd=0,
                            command=command,
                            cursor="hand2",
                            activebackground="#2d4477",
                            activeforeground="white",
                            width=20)
            btn.pack(pady=5)

        self.show_home_page()

    def show_home_page(self):
        self.clear_main_content()
        
        content = tk.Frame(self.current_window, bg="#0E0325")
        content.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        tk.Label(content, 
                 text="Hello and Welcome to NetTwin! Stay Connected and Informed with Real-Time Insights into Your Network's Performance!",
                 font=self.title_font,
                 bg="#0E0325",
                 fg="white",
                 wraplength=800).pack(pady=20)

    def show_digital_twin_page(self):
        self.clear_main_content()
        
        self.content = tk.Frame(self.current_window,bg="#0E0325")
        self.content.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        
        tk.Label(self.content, 
                 text="Digital Twin Overview",
                 font=self.title_font,
                 bg="#0E0325",
                 fg="white").pack()
        tk.Button(self.content, 
                  text="Display Digital Twin",
                  font=self.button_font,
                  bg="#84b2e0",
                  fg="black",
                  cursor="hand2",
                  relief="flat",
                  command=self.display_digital_twin).pack()
        
    def display_digital_twin(self):
        if not self.devices:
            messagebox.showerror("Error", "No devices found.")
            return
        
        pcap_file = "network_capture.pcap"
        scanned_ips = {device['ip'] for device in self.devices}
        digital_twins, total_delay = self.analyze_pcap(pcap_file=pcap_file,scanned_ips=scanned_ips)

        if not digital_twins:
            messagebox.showerror("Error", "No digital twins found.")
            return

        dt = ScrollFrame(self.content, bg="#84b2e0")
        dt.pack(expand=True,fill="both")
        label_bg = "#84b2e0"
        label_fg = "white"

        tk.Label(dt, 
                 text="Digital Twin Overview",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=0, column=0, columnspan=7, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="IP Address",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=0, columnspan=1, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="Traffic Count",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=1, columnspan=1, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="Delay (s)",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=2, columnspan=1, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="Connected IPs",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=3, columnspan=1, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="Total Bytes",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=4, columnspan=1, pady=1)
        
        tk.Label(dt, 
                 text="ICMP Requests",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=5, columnspan=1, pady=1,sticky="nswe")
        
        tk.Label(dt, 
                 text="ICMP Replies",
                  bg=label_bg,
                 fg=label_fg,
                 font=self.normal_font).grid(row=1, column=6, columnspan=1, pady=1,sticky="nswe")
        
        index = 2
        for ip, data in digital_twins.items():
            tk.Label(dt, 
                     text=ip,
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=0, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=data['traffic_count'],
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=1, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=data['delay'],
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=2, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=len(data['connected_ips']),
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=3, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=data['total_bytes'],
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=4, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=data['icmp_requests'],
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=5, columnspan=1, pady=1,sticky="nswe")
            tk.Label(dt, 
                     text=data['icmp_replies'],
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=6, columnspan=1, pady=1,sticky="nswe")
            index += 1
   
        # Display source to destination traffic
        for dst_ip, count in data['src_to_dst'].items():
            tk.Label(dt, 
                     text=f"From {ip} to {dst_ip}: {count} packets",
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=0, columnspan=7, pady=1,sticky="nswe")
            index += 1
        
        # Display destination to source traffic
        for src_ip, count in data['dst_to_src'].items():
            tk.Label(dt, 
                     text=f"From {src_ip} to {ip}: {count} packets",
                      bg=label_bg,
                 fg=label_fg,
                     font=self.normal_font).grid(row=index, column=0, columnspan=7, pady=1,sticky="nswe")
            index += 1
        rootFrame = tk.Frame(dt)
        rootFrame.grid(row=index + 1, column=0, columnspan=7,pady=10,sticky="nswe")
        self.draw_digital_twin(self.devices,digital_twins,self.router_ip,rootFrame)

      

    def show_network_page(self):
        self.clear_main_content()
        
        self.content = tk.Frame(self.current_window,bg="#0E0325")
        self.content.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        #Create an object of tkinter ImageTk
        #img = tk.PhotoImage(file="net.png")

        title = tk.Label(self.content, 
                 text="Network Details",
                 font=self.header_font,
                 bg="#0E0325",
                 fg="white")
        title.pack(expand=False,fill="both")


        btnBar = tk.Frame(self.content,bg="#0E0325")
        btnBar.pack(fill="both", expand=False)

       

        startScan = tk.Button(btnBar, 
                  text="Start Scan",
                  font=self.button_font,
                  bg="#84b2e0",
                  fg="black",
                  cursor="hand2",
                  relief="flat",
                  command=self.start_scanning)
        startScan.grid(column=0,row=0)

        caputer_trafic = tk.Button(btnBar, 
                  text="Capture Trafic",
                  font=self.button_font,
                  bg="#84b2e0",
                  fg="black",
                  cursor="hand2",
                  relief="flat",
                  command=self.capture_trafic)
        caputer_trafic.grid(column=1,row=0)

        #scan result
        self.network_grid = ScrollFrame(self.content,bg="#84b2e0")
        self.network_grid.pack(fill="both", expand=True, padx=5, pady=5)
        self.network_grid.grid_rowconfigure(0, weight=1)
        self.network_grid.grid_rowconfigure(1, weight=1)
        self.network_grid.grid_columnconfigure(0,weight=1)
        
       
       

    def capture_trafic(self):
        if(self.devices):
            bgColor = "#0E0325"
            fgColor = "white"
            scanned_ips = {device['ip'] for device in self.devices}
            pcap_file = "network_capture.pcap"
            self.capture_traffic(duration=30, output_file=pcap_file)
            digital_twins, total_delay = self.analyze_pcap(pcap_file, scanned_ips)
            info = tk.Frame(self.network_grid,bg=bgColor)
            info.grid(row=1, column=0, padx=1, pady=1,sticky="nwse")
            title = tk.Label(info, 
                 text="Network Summary",
                  bg=bgColor,
                 fg=fgColor,
                 font=self.header_font)
            title.grid(row=0, column=0, columnspan=1, padx=1, pady=1)

            if digital_twins:
                totalPackets = f"{sum(data['traffic_count'] for data in digital_twins.values())}"
                tpLbl = tk.Label(info,text="Total Packets", bg=bgColor,
                 fg=fgColor, font=self.normal_font)
                tpLbl.grid( row=1, column=0, columnspan=1, padx=1, pady=1)
                tpText= tk.Label(info,text=totalPackets, bg=bgColor,
                 fg=fgColor, font=self.normal_font)
                tpText.grid( row=1, column=1, columnspan=1, padx=1, pady=1)
                ttLbl = tk.Label(info,text="Total Traffic", bg="#0E0325",
                 fg="white", font=self.normal_font)
                ttLbl.grid( row=2, column=0, columnspan=1, padx=1, pady=1)
                ttText= tk.Label(info,text=f"{sum(data['total_bytes'] for data in digital_twins.values())} bytes", bg="#0E0325",
                 fg="white", font=self.normal_font)
                ttText.grid(row=2, column=1, columnspan=1, padx=1, pady=1)
                icrLbl = tk.Label(info,text="Total ICMP Requests", bg="#0E0325",
                 fg="white", font=self.normal_font)
                icrLbl.grid( row=3, column=0, columnspan=1, padx=1, pady=1)
                icrText= tk.Label(info,text=f"{sum(data['icmp_requests'] for data in digital_twins.values())}", bg="#0E0325",
                 fg="white", font=self.normal_font)
                icrText.grid( row=3, column=1, columnspan=1, padx=1, pady=1)
                icrLbl = tk.Label(info,text="Total ICMP Replies", bg="#0E0325",
                 fg="white", font=self.normal_font)
                icrLbl.grid( row=4, column=0, columnspan=1, padx=1, pady=1)
                icrText= tk.Label(info,text=f"{sum(data['icmp_replies'] for data in digital_twins.values())}", bg="#0E0325",
                 fg="white", font=self.normal_font)
                icrText.grid( row=4, column=1, columnspan=1, padx=1, pady=1)
                delayLbl = tk.Label(info,text="Total Delay", bg="#0E0325",
                 fg="white", font=self.normal_font)
                delayLbl.grid( row=5, column=0, columnspan=1, padx=1, pady=1)
                delayText= tk.Label(info,text=f"{total_delay:.2f} seconds", bg="#0E0325",
                 fg="white", font=self.normal_font)
                delayText.grid( row=5, column=1, columnspan=1, padx=1, pady=1)
                
                packetLabel  = tk.Label(info,text=f"Enter packet number to display (0 - {int(totalPackets) - 1})"
                                        ,bg=bgColor,fg=fgColor,font=self.normal_font)
                packetLabel.grid(row=6,column=0,padx=1,pady=1)
                packetEntry = tk.Entry(info,width=30)
                packetEntry.grid(row=7,column=0,padx=1,pady=1)

                
                def display_packet(packet_number,packInfo):
                    """Display details of a specific packet."""
                    packet_number = int(packet_number)
                    packets = scapy.rdpcap(pcap_file)
                    if 0 <= packet_number < len(packets):
                        packInfo.set(packets[packet_number].show(dump=True))
                    else:
                        packInfo.set("Invalid packet number.")
                
                packInfo = tk.StringVar()
                packetLabel  = tk.Label(info,textvariable=packInfo
                                        ,bg=bgColor,fg=fgColor,font=self.normal_font)
                packetLabel.grid(row=9,column=0,padx=1,pady=1)

                displayPktBtn = tk.Button(info,text="Display Packet",font=self.normal_font,command=lambda : display_packet(packetEntry.get(),packInfo))
                displayPktBtn.grid(row=8,column=0)


            else:
                res=tk.Label(info,text="No traffic data found in PCAP", bg="#0E0325",
                 fg="white", font=self.normal_font)
                res.grid(row=1, column=0, columnspan=1, padx=1, pady=1)

    def start_scanning(self):
        self.router_ip = self.get_router_ip()  # Get the router IP
        network_range = self.get_network_range()  # Get the network range
        print(f"Scanning network range: {network_range} (Router IP: {self.router_ip})")

        print("Scanning for devices on the network...")
        self.devices = self.scan_network(network_range)

        # display devices in a grid
    
        for widget in self.network_grid.winfo_children():
            widget.destroy()
      
        
        ng = tk.Frame(self.network_grid,bg="#84b2e0")
        ng.grid(row=0,column=0,sticky="nesw")
        ng.grid_columnconfigure(0,weight=1)
        ng.grid_columnconfigure(1,weight=1)
        ng.grid_columnconfigure(2,weight=1)
        ng.grid_columnconfigure(3,weight=1)
        ng.grid_columnconfigure(4,weight=1)

        tk.Label(ng, 
                 text=f"#",
                  bg="#0E0325",
                 fg="white",
                 font=self.normal_font).grid(row=0, column=0, padx=1, pady=1,sticky="nesw")
        tk.Label(ng, 
                 text=f"IP",
                  bg="#0E0325",
                 fg="white",
                 font=self.normal_font).grid(row=0, column=1, padx=1, pady=1,sticky="nesw")
        tk.Label(ng, 
                 text=f"MAC",
                  bg="#0E0325",
                 fg="white",
                 font=self.normal_font).grid(row=0, column=2, padx=1, pady=1,sticky="nesw")
        tk.Label(ng, 
                 text=f"NAME",
                  bg="#0E0325",
                 fg="white",
                 font=self.normal_font).grid(row=0, column=3, padx=1, pady=1,sticky="nesw")
        tk.Label(ng, 
                 text=f"PING STATUS",
                  bg="#0E0325",
                 fg="white",
                 font=self.normal_font).grid(row=0, column=4, padx=1, pady=1,sticky="nesw")
       

        for i, device in enumerate(self.devices, start=1):
            device_name = self.get_device_name(device['ip'])
            ping_status = "Ping successful" if self.ping_device(device['ip']) else "Ping not successful"
            row = i + 1
            tk.Label(ng, 
                     text=f"#{i}",
                      bg="#0E0325",
                      fg="white",
                     font=self.normal_font).grid(row=row, column=0, padx=1, pady=1,sticky="nesw")
            tk.Label(ng,
                      bg="#0E0325",
                 fg="white", 
                     text=f"{device['ip']}",
                     font=self.normal_font).grid(row=row, column=1, padx=1, pady=1,sticky="nesw")
            tk.Label(ng, 
                     text=f"{device['mac']}",
                      bg="#0E0325",
                 fg="white",
                     font=self.normal_font).grid(row=row, column=2, padx=1, pady=1,sticky="nesw")
            tk.Label(ng, 
                     text=f"{device_name}",
                      bg="#0E0325",
                 fg="white",
                     font=self.normal_font).grid(row=row, column=3, padx=1, pady=1,sticky="nesw")
            tk.Label(ng, 
                     text=f"{ping_status}",
                      bg=( "green" if ping_status.lower() == "ping successful" else "red"),
                 fg="white",
                     font=self.normal_font).grid(row=row, column=4, padx=1, pady=1,sticky="nesw")
                
    def draw_digital_twin(self,devices,digital_twins, router_ip, rootFrame):
        """Draw digital twin of the network based on devices_info, with router in the center."""
    
        devices_info = {device['ip']: {
                "traffic": digital_twins[device['ip']]['traffic_count'],
                "delay": digital_twins[device['ip']]['delay'],
                "connected_ips": set(digital_twins[device['ip']]['connected_ips'])  # Use actual connected devices
            } for device in devices}
        
        icons = {
                    "router": "C:/Users/renad/OneDrive/سطح المكتب/router.jpg",
                    "pc": "C:/Users/renad/OneDrive/سطح المكتب/pc.jpg",
                    "phone": "C:/Users/renad/OneDrive/سطح المكتب/phone.jpg",
                }
         # Load images
        images = {k: PIL.Image.open(fname) for k, fname in icons.items()}

        G = nx.Graph()
        # Add the router node in the center
        G.add_node(router_ip,image=images["router"])

        # Add nodes for devices and connect them to the router
        for device_ip in devices_info:
            if(device_ip == router_ip):
                continue
            G.add_node(device_ip,image=images["pc"])
            G.add_edge(router_ip, device_ip)  # Connect all devices to the router

        # Draw the graph
        pos = nx.spring_layout(G, seed=42)
        #plt.figure(figsize=(8, 6))
        fig, ax = plt.subplots()
        #nx.draw(G, pos, with_labels=True, node_size=3000, font_size=10, font_weight="bold")
        nx.draw_networkx_edges( G, pos=pos, ax=ax, arrows=True, arrowstyle="-", min_source_margin=15, min_target_margin=15,)
        plt.title(f"Network Graph with Router ({router_ip}) in the Center")

        # Transform from data coordinates (scaled between xlim and ylim) to display coordinates
        tr_figure = ax.transData.transform
        # Transform from display to figure coordinates
        tr_axes = fig.transFigure.inverted().transform

        # Select the size of the image (relative to the X axis)
        icon_size = (ax.get_xlim()[1] - ax.get_xlim()[0]) * 0.025
        icon_center = icon_size / 2.0

        # Add the respective image to each node
        for n in G.nodes:
            xf, yf = tr_figure(pos[n])
            xa, ya = tr_axes((xf, yf))
            # get overlapped axes and plot icon
            a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
            a.imshow(G.nodes[n]["image"])
            a.text(0, 0, n, fontsize=10, ha="center", va="center")
            a.axis("off")
        
        canvas = FigureCanvasTkAgg(figure=fig, master=rootFrame)  # A tk.DrawingArea.
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def show_guidelines_page(self):
        self.clear_main_content()
        
        self.title_font = ("Times New Roman", 26, "bold")  # Larger title font in Times New Roman
        self.normal_font = ("Times New Roman", 18)

        content = tk.Frame(self.current_window, bg="#0E0325")
        content.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        guidelines = [
            "1. Ensure you are connected to a Wi-Fi network.",
            "2. By clicking start, you agree to display network information.",
            "3. Continuing implies acceptance of the program's terms and conditions.",
        ]
        
        tk.Label(content, 
                 text="Guidelines",
                 font=self.title_font,
                 bg="#0E0325",
                 fg="white").pack(pady=20)

        for guideline in guidelines:
            tk.Label(content, 
                     text=guideline, 
                     font=self.normal_font, 
                     bg="#0E0325",
                     fg="white").pack(anchor="w", padx=20)

    def show_about_us_page(self):
        if self.current_window:
            self.current_window.destroy()

        self.current_window = tk.Frame(self.root, bg="#0E0325")
        self.current_window.place(relx=0, rely=0, relwidth=1, relheight=1)

        about_frame = tk.Frame(self.current_window, bg="#1e3a7c", padx=40, pady=40)
        about_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=600)

        # Back button
        back_btn = tk.Button(about_frame, 
                        text="← Back", 
                        font=self.button_font,
                        bg="#84b2e0",
                        fg="black",
                        command=self.handle_about_us_back,
                        cursor="hand2",
                        relief="flat")
        back_btn.pack(anchor="nw", pady=(0, 20))

        # About Us content
        title = tk.Label(about_frame, 
                    text="About Us", 
                    font=self.title_font, 
                    bg="#1e3a7c", 
                    fg="#84b2e0")
        title.pack(pady=(0, 20))

        about_text = """NetTwin is a cutting-edge network monitoring and digital twin platform 
that provides real-time visualization and analysis of network infrastructure. 
Our solution helps organizations maintain optimal network performance and security."""

        about_label = tk.Label(about_frame, 
                          text=about_text, 
                          font=self.normal_font,
                          bg="#1e3a7c", 
                          fg="white",
                          wraplength=700,
                          justify="center")
        about_label.pack(pady=20)

    def handle_about_us_back(self):
        """Handle back button click based on login state"""
        if self.is_logged_in:
            self.create_main_interface()
        else:
            self.create_pre_login_menu()

    def clear_main_content(self):
        for widget in self.current_window.winfo_children():
            if widget != self.current_window.winfo_children()[0]:  # Keep the sidebar
                widget.destroy()

    def logout(self):
        self.is_logged_in = False
        self.create_pre_login_menu()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = FullScreenLoginSystem()
    app.run()