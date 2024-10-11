import socket
import threading
from queue import Queue

class PortScanner:
    def __init__(self, target, start_port, end_port):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports_tcp = []
        self.open_ports_udp = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def scan_port(self, port):
        # TCP port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  #Timeout
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports_tcp.append(port)
                print(f"TCP Port {port} is open")

    def scan_udp_port(self, port):
        # UDP port
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)  #Timeout
            try:
                sock.sendto(b'', (self.target, port))
                # Port açıksa yanıt dönecek
                sock.recvfrom(1024)
                with self.lock:
                    self.open_ports_udp.append(port)
                print(f"UDP Port {port} is open")
            except socket.error:
                pass  # Port kapalıysa yanıt yok

    def process_queue(self):
        """Process the queue for port scanning."""
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)  # TCP scan
            self.queue.task_done()

    def tcp_scan(self):
        """Scan TCP ports."""
        print(f"Scanning TCP ports from {self.start_port} to {self.end_port}...")
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        threads = []
        for _ in range(100):  # a
            thread = threading.Thread(target=self.process_queue)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    def udp_scan(self):
        """Scan UDP ports."""
        print(f"Scanning UDP ports from {self.start_port} to {self.end_port}...")
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        threads = []
        for _ in range(100):  
            thread = threading.Thread(target=self.process_udp_queue)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    def process_udp_queue(self):
        # UDP için sırayla tarıyor. İşlenmemiş port olduğu sürece döngü devam ediyor.
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_udp_port(port)  # UDP
            self.queue.task_done()

    def print_results(self):
        # Sonuçları ekrana yazdırıyor.
        print("\nScan complete.")
        if self.open_ports_tcp:
            print(f"Open TCP ports: {', '.join(map(str, self.open_ports_tcp))}")
        else:
            print("No open TCP ports found.")

        if self.open_ports_udp:
            print(f"Open UDP ports: {', '.join(map(str, self.open_ports_udp))}")
        else:
            print("No open UDP ports found.")

if __name__ == "__main__":
    target = input("Enter the destination IP address or domain name you want to scan to: ")
    port_range = input("Enter the port range you want to scan (Example: 1-1000): ")

    # Port aralığını oluştur
    try:
        start_port, end_port = map(int, port_range.split('-'))
        scanner = PortScanner(target, start_port, end_port)
        
        # TCP taraması
        scanner.tcp_scan()
        
        # UDP taraması
        scanner.udp_scan()
        
        # Geçersiz aralık girilirse bu hata verilecek
        scanner.print_results()
    except ValueError:
        print("[Error] Please enter a valid port range.")
    except Exception as e:
        print(f"[Error] {e}") # Farklı bir hata durumunda Error yazacak
