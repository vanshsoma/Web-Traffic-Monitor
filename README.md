This is a simple packet sniffer built using python and scapy.
It allows you to monitor network traffic between a specific target IP and gateway on a chosen network protocol.

How to use:
  Download the file (sniffer.py)
  and run it like this 
    python sniffer.py -i Wi-Fi(or whatever interface u are on) -t <target_ip> -g <target_gateway> <and arguments>
    use the command "python sniffer.py --help" to see all the arguments 
Note:
  Make sure the target and user are on same internet.
  If you wanna see what interfaces are available run this command
  "python sniffer.py -l"
