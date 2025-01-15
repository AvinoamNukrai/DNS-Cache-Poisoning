# DNS-Cache-Poisoning
BIND9 DNS Cache Poisoning Attack

DNS cache poisoning aims to make a DNS resolver return an incorrect response so that
users who resolve names to addresses through this DNS server and then connect to the IP
addresses returned from it are directed to the wrong IP address. We do that by inserting false
information into the DNS resolver cache.


An example of a DNS cache poisoning attack is “BIND9 DNS Cache Poisoning” by
Amit Klein in 2007. In the paper, he shows that one can predict up to 10 values for the next
transaction ID (from now on we will refer to it as “TXID”) when the TXID is even, and because the UDP source port
is static in BIND 9.4.1, it suffices to predict the TXID and by
that spoof DNS answers and poison the cache.


General:
The attack aims to manipulate the DNS resolution process by exploiting weak transaction ID (TXID) randomness, allowing the attacker to inject malicious DNS responses. The attack is carried out through two coordinated components: an authoritative name server and an attacker client.

Implementation: 

The server code (attack_server.c) acts as the attacker’s authoritative DNS server. It listens for incoming DNS requests on port 53 and extracts the TXID and source port from each request. For even TXIDs, the server forwards the TXID and port to the attacker’s client via a UDP message, which is used to craft spoofed responses. For odd TXIDs, the server responds with an attacker-controlled subdomain to avoid suspicion. The server creates DNS CNAME records dynamically based on the TXID, either pointing to a legitimate domain or to a subdomain under the attacker’s control.

The client code (attack_client.c) initiates the attack by sending an initial DNS query to the target DNS server. After receiving the TXID and port information from the server, the client calculates potential TXID candidates using bitwise operations to predict valid IDs. It then crafts raw DNS packets with spoofed responses containing a fake IP address (6.6.6.6) and sends them to the target server using a raw socket. By sending multiple responses with different TXID values, the client increases the chances of matching a valid TXID and successfully poisoning the target server’s DNS cache.

In summary, the server and client work together to exploit TXID prediction, with the server forwarding critical TXID and port information to the client, which then uses this data to inject fake DNS responses and redirect users to a malicious IP address.


The Packet Crafting: 

The client creates raw DNS response packets by manually constructing the IP and UDP headers, setting the predicted TXIDs and a fake IP address (6.6.6.6). It includes the DNS response sections (question, answer, and authority) to make the packet appear legitimate. The client uses a raw socket to send multiple spoofed packets to the target server, attempting to poison its cache by injecting the fake IP associated with a domain name.


The TXID Prediction:

The server extracts the TXID from incoming DNS requests and sends it to the attacker’s client via a UDP message. The client uses bitwise shifts and XOR operations on the received TXID to generate a list of possible TXID candidates. This list is used to craft spoofed DNS responses that have a high chance of matching the actual TXID used by the target server. The Implementation is as described at Amit algorithm. 



A Simple Implementation Diagram:


![WhatsApp Image 2025-01-12 at 10 05 46](https://github.com/user-attachments/assets/875888ba-f9f3-4ac9-ba99-befe637410f6)



Reference - Amit Klein, “BIND9 DNS Cache Poisoning”, 2007. 
