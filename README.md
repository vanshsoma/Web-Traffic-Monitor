# 🐍 Web Traffic Monitor

This is a simple packet sniffer built using Python and Scapy.  
It allows you to monitor network traffic between a specific target IP and gateway on a chosen network protocol.

---

## 🚀 How to Use

1. Download sniffer.py  
2. Run it like this:

```bash
python sniffer.py -i Wi-Fi -t <target_ip> -g <gateway_ip> -p <aruguments>
```

3. For more arugments run: 

```bash
python sniffer.py --help
```

4. For interfaces run:

```bash
python sniffer.py -l
```
## Note:
Ensure that both the sniffer and the target device (sniffee) are connected to the same network.
