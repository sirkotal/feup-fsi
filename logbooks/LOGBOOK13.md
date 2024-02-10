# LOGBOOK 13

In this lab, we learned how to use packet sniffing and spoofing tools like Wireshark and Scapy. The goal was to not just use the tools but also write sniffer and spoofing programs, giving us some experience and a deeper understanding of the tech behind these security threats.

## Environment Setup

To set up this lab we used three machines that were connected to the same LAN - one in each container. Firstly, it was necessary to run the command ```docker-compose up``` inside the *Labsetup* folder that contains the *docker-compose.yml* file.
After this, with the ```dockps``` command, followed by ```docksh```, we opened a terminal for each machine.


## Task 1: Using Scapy to Sniff and Spoof Packets

### Task 1A : Sniffing Packets

Initially, we were told there two ways of using Scapy; this was because, although Wireshark is the most popular sniffing tool, it is hard to use it as a building block to construct other tools. We decided to utilize the second way (the interactive mode of Python) as follows.

![Scapy](images/logbook-13/scapy.png)

After this, we would turn to the task's objective - to learn how to use Scapy to perform packet sniffing in Python programs.

A sample code was given, but it was necessary to adapt it to a different interface name that could be reached by doing ```ifconfig```, as described in Environment Setup.

```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="br-729a3c2fe4f4", filter="icmp", prn=print_pkt)
```

The following commands allowed us to reach the objective.

```bash
chmod a+x sniffer.py
sniffer.py
```

After pinging from Host A to Host B, when we went to the terminal of seed-attacker we found packets captured. We also verified tat to sniff packets we need root priviledges.

### Task 1B : Sniffing Packets

We were then asked to set the following filters and demonstrate our sniffer program again:

- ***Capture only the ICMP packet***.

```python
#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
    if pkt[ICMP] is not None:
        print("ICMP Packet\n")
        pkt.show()

pkt = sniff(iface='br-729a3c2fe4f4', filter='icmp', prn=print_pkt)
```
This Python script listens on the specified network interface for incoming ICMP packets; whenever an ICMP packet is captured, the script prints detailed information about that specific packet.

- ***Capture any TCP packet that comes from a particular IP and with a destination port number 23***.

```python
#!/usr/bin/env

from scapy.all import *

def print_tcp_pkt(pkt):
    if pkt[TCP] is not None:
        if pkt[IP].src.startswith('128.230.') and pkt[TCP].dport == 23:
            print("TCP Packet from 128.230.0.0/16 to port 23:")
            pkt.show()

pkt = sniff(iface='br-729a3c2fe4f4', filter='tcp port 23', prn=print_tcp_pkt)
```
This Python script listens on a specific network interface for TCP packets. When a TCP packet arrives from an IP address within the 128.230.0.0/16 subnet and whose destination is port 23, detailed information about that specific packet is displayed.

- ***Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to.***

```python
#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-729a3c2fe4f4', filter='dst net 128.230.0.0/16', prn=print_pkt)
```
This Python script listens on the specified network interface for incoming packets destined for the IP 128.230.0.0/16. When a packet matching this condition is captured, the script showcases detailed information about that packet.

## Task 2: Spoofing ICMP Packets

On this task, the objective was to spoof IP packets with an arbitrary source IP address.

We utilized the following commands:

![commands](images/logbook-13/commands.png)

Opening Wireshark, we verified that we could send a request to the pretended destination and got an answer back.

![Wireshark](images/logbook-13/wireshark.png)

We then tried to do the same but from an arbitrary source with the commands below:

![commands](images/logbook-13/commands-src.png)

## Task 3: Traceroute

Using Scapy, the task involved estimating the distance between our VM and a selected destination. To achieve this, we sent packets with varying Time-To-Live (TTL) values, receiving ICMP error messages from routers, and incremented TTL; the tool identified the route, providing an estimated result. 

To automate this process we developed the following code.

```python
from scapy.all import *

a = IP()
a.dst = '1.2.3.4'
b = ICMP()

for i in range(1,100):
    a.ttl = i
    send(a/b)
```

![traceroute](images/logbook-13/traceroute.png)

## Task 4: Sniffing and-then Spoofing

On the final task, we combined sniffing and spoofing techniques using Scapy. We had a VM monitoring a LAN, responding with a spoofed ICMP echo reply upon detecting any echo request from the user's container. Results from pinging three IPs illustrate how the technique falsely indicated a target's liveliness, regardless of its actual status.

```python
from scapy.all import *

def send_packet(pkt):

	if(pkt[2].type == 8):
		src=pkt[1].src
		dst=pkt[1].dst
		seq = pkt[2].seq
		id = pkt[2].id
		load=pkt[3].load

		print(f"Request: src {src} \t dst {dst}")
		print(f"Reply  : src {dst} \t dst {src}\n")
		reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
		send(reply,verbose=0)

pkt = sniff(iface='br-729a3c2fe4f4', filter='icmp', prn=send_packet)
```

By using the code above and pinging the hosts that were given, we got a response in ```1.2.3.4``` and ```8.8.8.8```.
```10.9.0.99``` giving ```Destination Host Unreachable``` can be justified by the ARP protocol - the process was unsuccessful in mapping the IP address to a corresponding MAC address.
