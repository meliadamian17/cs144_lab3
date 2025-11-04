# CSCD85 - Assignment 3

## Group Members

### Damian Melia
#### Contributions
- Implemented all functionality related to the ARP Cache
- Functions Implemented:
    - ``` sr_arpcache_sweepreqs() ``` - sr_arpcachce.c
    - ``` sr_send_arp_request() ``` - sr_router.c
    - ``` sr_send_icmp_t3() ``` - sr_router.c
    - ``` handle_arpreq() ``` - sr_router.c  

### Gursimar Singh
#### Contributions
- Implemented all functionality related to ARP packet handling and helper utilities
- Functions Implemented:
    - ``` iface_from_list() ``` - sr_router.c
    - ``` routing_match() ``` - sr_router.c
    - ``` swap_eth_addr() ``` - sr_router.c
    - ``` reply_to_arp() ``` - sr_router.c
    - ``` arp_reply_handler() ``` - sr_router.c

### Prithvi Ajay
#### Contributions
- Implemented all functionality related to IP packet handling and ICMP message generation
- Functions Implemented:
    - ``` icmp_echo_reply() ``` - sr_router.c
    - ``` generate_imcp_error() ``` - sr_router.c
    - ``` valid_ip_not_for_me() ``` - sr_router.c
    - ``` ip_handler() ``` - sr_router.c
    - ``` sr_handlepacket() ``` - sr_router.c

## Description and Documentation for Implemented Functions

This section documents the functions that implement the required and missing functionalities in the starter code. The implementation addresses all requirements for a simple router with static routing, ARP handling, and ICMP message generation.

### ARP Cache Management Functions

#### `sr_arpcache_sweepreqs()` - sr_arpcache.c
**Purpose**: Called every second by the ARP cache timeout thread to check all pending ARP requests and handle resending or timeout logic.

**Implementation Details**:
- Iterates through all ARP requests in the cache's request queue
- For each request, calls `handle_arpreq()` to check if:
  - More than 1 second has passed since last send → resend ARP request
  - 5 attempts have been made → send ICMP Host Unreachable and destroy request

**Required Functionality**: Implements ARP request retry mechanism (5 attempts before timeout) and maintains packet queue during ARP resolution.

---

### ARP Request Handling Functions

#### `sr_send_arp_request()` - sr_router.c
**Purpose**: Constructs and sends an ARP request packet to resolve an IP address to a MAC address.

**Implementation Details**:
- Allocates memory for Ethernet + ARP headers
- Sets Ethernet header:
  - Destination MAC: broadcast address (0xff)
  - Source MAC: interface MAC address
  - Ethertype: ARP (0x0806)
- Sets ARP header:
  - Hardware type: Ethernet
  - Protocol type: IP
  - Operation: ARP request
  - Source IP/MAC: router's interface
  - Target IP: the IP to resolve
  - Target MAC: zeros (unknown)
- Sends packet and frees memory

**Required Functionality**: Enables ARP resolution for next-hop addresses during IP forwarding.

#### `handle_arpreq()` - sr_router.c
**Purpose**: Handles the timing and retry logic for ARP requests. Called by `sr_arpcache_sweepreqs()`.

**Implementation Details**:
- Checks if at least 1 second has passed since last ARP request send
- If 5 or more attempts have been made:
  - Sends ICMP Host Unreachable (type 3, code 1) to all queued packets
  - Destroys the ARP request entry
- Otherwise:
  - Sends a new ARP request using `sr_send_arp_request()`
  - Updates timestamp and increments retry counter

**Required Functionality**: Implements ARP retry mechanism (5 attempts) and sends ICMP Host Unreachable when ARP fails after maximum retries.

#### `reply_to_arp()` - sr_router.c
**Purpose**: Generates and sends an ARP reply when the router receives an ARP request for one of its interfaces.

**Implementation Details**:
- Swaps Ethernet source/destination addresses using `swap_eth_addr()`
- Modifies ARP header:
  - Changes operation from request to reply
  - Sets target MAC to sender's MAC
  - Sets target IP to sender's IP
  - Sets sender MAC/IP to router's interface
- Sends the reply packet

**Required Functionality**: Enables the router to respond to ARP requests, allowing hosts to discover the router's MAC address.

#### `arp_reply_handler()` - sr_router.c
**Purpose**: Processes incoming ARP replies by updating the ARP cache and forwarding queued packets.

**Implementation Details**:
- Extracts sender MAC and IP from ARP reply
- Inserts mapping into ARP cache using `sr_arpcache_insert()`
- If packets were queued for this IP:
  - Updates Ethernet headers of all queued packets with resolved MAC address
  - Sends all queued packets
  - Destroys the ARP request entry

**Required Functionality**: Completes ARP resolution process and forwards packets that were waiting for MAC address resolution.

---

### Helper Utility Functions

#### `iface_from_list()` - sr_router.c
**Purpose**: Searches the router's interface list to find an interface by name.

**Implementation Details**:
- Iterates through linked list of interfaces (`sr->if_list`)
- Compares interface names using `strcmp()`
- Returns pointer to matching interface or NULL if not found

**Required Functionality**: Enables lookup of interface information by name for packet forwarding.

#### `routing_match()` - sr_router.c
**Purpose**: Finds a routing table entry matching a destination IP address.

**Implementation Details**:
- Iterates through routing table linked list to find the longest prefix
- Compares destination IP with longest till now
- Returns longest prefix entry or NULL if no match found

**Required Functionality**: Enables IP forwarding by finding the appropriate routing table entry for a destination.

#### `swap_eth_addr()` - sr_router.c
**Purpose**: Swaps Ethernet source and destination addresses in a packet for reply generation.

**Implementation Details**:
- Copies source MAC to destination MAC
- Sets source MAC to router's interface MAC address

**Required Functionality**: Utility function for generating reply packets (ICMP echo replies/errors).

#### `router_interface_check` - sr_router.c
**Purpose**: Determines whether an incoming IP packet is addressed to one of the router’s own interfaces.

**Implementation Details**:
- Iterates over the linked list of interfaces
- Compares to find if any of the interface's address was the destination address
- Returns the matched interface or NULL if packet was not destined to the router

**Required Functionality**: Enables router to check if IP packet belongs to it

---

### ICMP Message Generation Functions

#### `sr_send_icmp_t3()` - sr_router.c
**Purpose**: Generates and sends ICMP Type 3 error messages (Destination Unreachable).

**Implementation Details**:
- Allocates memory for Ethernet + IP + ICMP Type 3 headers
- Constructs Ethernet header:
  - Destination: original packet's source MAC
  - Source: router's interface MAC
- Constructs IP header:
  - Source: router's interface IP
  - Destination: original packet's source IP
  - Protocol: ICMP
  - TTL: 64
  - Computes IP checksum
- Constructs ICMP Type 3 header:
  - Type and code as specified (e.g., 3,1 for Host Unreachable)
  - Copies original IP header into ICMP data field
  - Computes ICMP checksum
- Sends packet and frees memory

**Required Functionality**: Sends ICMP error messages for various unreachable conditions (Host Unreachable, Net Unreachable, Port Unreachable).

#### `icmp_echo_reply()` - sr_router.c
**Purpose**: Generates and sends an ICMP echo reply (ping response) when the router receives an ICMP echo request.

**Implementation Details**:
- Modifies the received packet in-place:
  - Swaps Ethernet addresses
  - Swaps IP source/destination addresses
  - Sets IP TTL to 64
  - Recomputes IP checksum
- Modifies ICMP header:
  - Changes type from 8 (echo request) to 0 (echo reply)
  - Sets code to 0
  - Recomputes ICMP checksum
- Sends the modified packet

**Required Functionality**: Enables the router to respond to ping requests, allowing connectivity testing.

#### `generate_imcp_error()` - sr_router.c
**Purpose**: Generates ICMP error messages with specified type and code values.

**Implementation Details**:
- Allocates memory for new ICMP error packet
- Copies original Ethernet and IP headers
- Swaps Ethernet addresses
- Constructs new IP header:
  - Source: router's interface IP
  - Destination: original packet's source IP
  - Protocol: ICMP
  - TTL: 64
  - Computes IP checksum
- Constructs ICMP Type 3 header:
  - Type and code as specified
  - Copies original IP header (first 28 bytes) into ICMP data
  - Computes ICMP checksum
- Sends packet and frees memory

**Required Functionality**: Generates ICMP error messages for various error conditions (Net Unreachable, Port Unreachable, Time Exceeded).

**Note**: This function and `sr_send_icmp_t3()` do the same thing but were implemented independently with slightly different API but they could be combined into one.

---

### IP Packet Forwarding Functions

#### `valid_ip_not_for_me()` - sr_router.c
**Purpose**: Handles IP packet forwarding when the packet is not destined for the router itself.

**Implementation Details**:
- Looks up routing table entry using `routing_match()`
- If no route found:
  - Sends ICMP Net Unreachable (type 3, code 0)
- If route found:
  - Looks up next-hop MAC address in ARP cache
  - If MAC found:
    - Updates Ethernet header with next-hop MAC
    - Updates source MAC to router's interface MAC
    - Forwards packet
  - If MAC not found:
    - Queues packet in ARP request queue
    - Calls `handle_arpreq()` to initiate ARP resolution

**Required Functionality**: Implements IP forwarding logic with ARP resolution and error handling for unreachable networks.

#### `ip_handler()` - sr_router.c
**Purpose**: Main handler for IP packets, routing them to appropriate handlers based on destination and type.

**Implementation Details**:
- Checks if packet is destined for router (`ip_dst == iface_info->ip`):
  - If ICMP echo request (protocol 1): calls `icmp_echo_reply()`
  - If TCP/UDP (protocol 16/17): sends ICMP Port Unreachable (type 3, code 3)
  - Otherwise: logs unknown type
- If packet is for another host:
  - Checks TTL: if TTL == 1, sends ICMP Time Exceeded (type 11, code 0)
  - Otherwise: calls `valid_ip_not_for_me()` for forwarding

**Required Functionality**: Routes IP packets appropriately, handles packets for router, implements TTL checking, and generates appropriate ICMP errors.

#### `sr_handlepacket()` - sr_router.c
**Purpose**: Main entry point for packet processing. Called whenever the router receives a packet.

**Implementation Details**:
- Validates packet and interface parameters
- Looks up receiving interface using `iface_from_list()`
- Determines packet type by examining Ethernet header:
  - **ARP packets** (`ethertype_arp`):
    - If ARP request: calls `reply_to_arp()`
    - If ARP reply: calls `arp_reply_handler()`
  - **IP packets** (`ethertype_ip`):
    - Calls `ip_handler()` for processing
  - **Other types**: Discards packet

**Required Functionality**: Implements the main packet processing logic, routing packets to appropriate handlers based on protocol type.

## Test Cases

Follow these instructions to get started : 

1. Start VM
2. cd cs144\_lab3
3. ./config.sh
4. ./run_pox.sh
5. In a different terminal, ./run_mininet.sh
6. In another terminal, cd router ; make ; ./sr

Now we can start sending packets, the following test cases serve as examples :

### Router Functionality

#### Test 1: Client connects to Router

**Command:** `client ping -c 3 10.0.1.1`

**Expectation:**
The router should reply to ICMP echo requests directed at its eth3 interface, confirming local interface reachability and proper ARP handling.

**Output:**

```
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=67.9 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=41.3 ms
64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=77.9 ms

--- 10.0.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 41.300/62.369/77.884/15.443 ms
```

#### Test 2: Client pings Server1

**Command:** `client ping -c 3 server1`

**Expectation:**
ICMP echo packets from the client should be forwarded through the router to server1, which should return echo replies routed back correctly through the same interface.

**Output:**

```
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=138 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=63 time=119 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=63 time=80.0 ms

--- 192.168.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 79.958/112.174/137.756/24.057 ms
```

#### Test 3: Client pings Router’s other interface

**Command:** `client ping -c 3 172.64.3.1`

**Expectation:**
The router should directly respond to pings targeting its eth2 interface IP, confirming the interface is reachable and operational.

**Output:**

```
PING 172.64.3.1 (172.64.3.1) 56(84) bytes of data.
64 bytes from 172.64.3.1: icmp_seq=1 ttl=64 time=57.2 ms
64 bytes from 172.64.3.1: icmp_seq=2 ttl=64 time=58.5 ms
64 bytes from 172.64.3.1: icmp_seq=3 ttl=64 time=74.7 ms

--- 172.64.3.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2010ms
rtt min/avg/max/mdev = 57.226/63.454/74.662/7.941 ms
```

#### Test 4: Client traceroutes Router

**Command:** `client traceroute -n 10.0.1.1`

**Expectation:**
Traceroute should show the router as a single hop away, indicating successful ICMP Time Exceeded handling for packets with low TTL values.

**Output:**

```
traceroute to 10.0.1.1 (10.0.1.1), 30 hops max, 60 byte packets
 1  10.0.1.1  64.286 ms  73.767 ms  111.505 ms
```

#### Test 5: Client traceroutes Server2

**Command:** `client traceroute -n 172.64.3.10`

**Expectation:**
The router should decrement TTL values and generate Time Exceeded messages as packets traverse toward server2, confirming correct hop-by-hop processing.

**Output:**

```
traceroute to 172.64.3.10 (172.64.3.10), 30 hops max, 60 byte packets
 1  10.0.1.1  40.139 ms  66.200 ms  116.766 ms
 2  * * *
 3  * * *
 4  * * *
 5  * 172.64.3.10  408.595 ms  416.858 ms
```

#### Test 6: Server2 traceroutes Server1

**Command:** `server2 traceroute -n 192.168.2.2`

**Expectation:**
Traceroute packets from server2 should be routed through the router to reach server1, verifying inter-network communication between different router interfaces.

**Output:**

```
nohup: appending output to 'nohup.out'
traceroute to 192.168.2.2 (192.168.2.2), 30 hops max, 60 byte packets
 1  172.64.3.1  34.490 ms  93.180 ms  85.198 ms
 2  * * *
 3  * * *
 4  * * *
 5  * 192.168.2.2  388.670 ms  394.452 ms
```

#### Test 7: Client downloads file from Server1

**Command:** `client wget http://192.168.2.2`

**Expectation:**
The router should properly route TCP traffic for the HTTP request and response, enabling successful file retrieval from server1.

**Output:**

```
--2025-11-03 16:05:29--  http://192.168.2.2/
Connecting to 192.168.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 161 [text/html]
Saving to: ‘index.html.7’

index.html.7          0%[                    ]       0  --index.html.7        100%[===================>]     161  --.-KB/s    in 0s      

2025-11-03 16:05:29 (953 KB/s) - ‘index.html.7’ saved [161/161]
```

#### Test 8: Client pings unavailable host

**Command:** `client ping -c 3 192.168.2.5`

**Expectation:**
Since a subnet containing the destination host does not exist, the router should respond with ICMP Destination Net Unreachable.

**Output:**

```
PING 192.168.2.5 (192.168.2.5) 56(84) bytes of data.
From 10.0.1.1 icmp_seq=1 Destination Net Unreachable
From 10.0.1.1 icmp_seq=2 Destination Net Unreachable
From 10.0.1.1 icmp_seq=3 Destination Net Unreachable

--- 192.168.2.5 ping statistics ---
3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2003ms
```

### ARP Cache Tests

#### Test 1: Ping Server2 two times in a row

**Command 1:** `client ping -c 3 server2`

**Command 2:** `client ping -c 3 server2`

**Instructions:** Execute Command 2 right after Command 1 finishes

**Expectation:**
Since we are caching the ARP reply we expect the second ping to have a shorter RTT.

**Output for Command 1:**
```
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=151 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=63 time=45.2 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=63 time=152 ms

--- 192.168.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2006ms
rtt min/avg/max/mdev = 45.241/116.070/151.997/50.085 ms
```

**Output for Command 2:**
```
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=60.0 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=63 time=54.5 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=63 time=132 ms

--- 192.168.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 54.469/82.096/131.862/35.261 ms
```

Clearly the avg for the second set of pings (82ms) < avg for the first set of pings (116ms).

#### Test 2 : Traceroute Server1 two times in a row

**Command 1:** `client traceroute -c 3 server2`

**Command 2:** `client traceroute -c 3 server2`

**Instructions:** Execute Command 2 right after Command 1 finishes

**Expectation:**
Since we are caching the ARP reply we expect the second traceroute to resolved much faster.

**Output for Command 1:**

```
traceroute to 192.168.2.2 (192.168.2.2), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  41.975 ms  77.099 ms  85.511 ms
 2  * * *
 3  * * *
 4  * * *
 5  * 192.168.2.2 (192.168.2.2)  397.205 ms  402.764 ms
```

**Output for Command 2:**
```
traceroute to 192.168.2.2 (192.168.2.2), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  30.515 ms *  88.913 ms
 2  192.168.2.2 (192.168.2.2)  232.857 ms  266.345 ms  279.143 ms
```

The second traceroute completes much earlier because of the caching.


