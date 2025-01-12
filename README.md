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


**A Simple Implementation Diagram:
**

![WhatsApp Image 2025-01-12 at 10 05 46](https://github.com/user-attachments/assets/875888ba-f9f3-4ac9-ba99-befe637410f6)



Reference - Amit Klein, “BIND9 DNS Cache Poisoning”, 2007. 
