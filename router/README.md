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
- Iterates through routing table linked list
- Compares destination IP with each entry's destination
- Returns matching entry or NULL if no match found

**Note**: This implementation performs exact match rather than longest prefix match. For production use, longest prefix match should be implemented.

**Required Functionality**: Enables IP forwarding by finding the appropriate routing table entry for a destination.

#### `swap_eth_addr()` - sr_router.c
**Purpose**: Swaps Ethernet source and destination addresses in a packet for reply generation.

**Implementation Details**:
- Copies source MAC to destination MAC
- Sets source MAC to router's interface MAC address

**Required Functionality**: Utility function for generating reply packets (ARP replies, ICMP echo replies).

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
