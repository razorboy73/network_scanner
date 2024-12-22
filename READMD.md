Network_Scanner
● Discover all devices on the network.
● Display their IP address.
● Display their MAC address.


Goal → Discover clients on network. Setps:
1. Create arp request directed to broadcast MAC asking for IP.
2. Send packet and receive response.
3. Parse the response.
4. Print result.

Goal → Discover clients on network.
Setps:
1. Create arp request directed to broadcast MAC asking for IP.
Two main parts:
➔ Use ARP to ask who has target IP.
➔ Set destination MAC to broadcast MAC.


Design

Field to capture ip address we wnt to find
Field to capture mac broadcast address of requesting computere

Interface 
show the deatils of ARP request
show the details of the broadcast request
Show the details of the arp_request_broadcast
show the details of the answered.summary ()
want to display the ip address and MAC address from answered.summary ().  Additionally if you can dispply the mac vender and hostname