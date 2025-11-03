/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arp_request
 * Scope:  Local
 *
 * Sends an ARP request for the given IP address on the specified interface.
 *
 *---------------------------------------------------------------------*/
void sr_send_arp_request(struct sr_instance* sr, uint32_t tip, struct sr_if* iface)
{
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* packet = (uint8_t*)malloc(len);
    
    /* Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* Broadcast */
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);
    
    /* ARP header */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN); /* Target MAC unknown */
    arp_hdr->ar_tip = tip;
    
    /* Send the packet */
    sr_send_packet(sr, packet, len, iface->name);
    free(packet);
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_t3
 * Scope:  Local
 *
 * Sends an ICMP type 3 (destination unreachable) message.
 * Code 1 = Host Unreachable, Code 0 = Net Unreachable, Code 3 = Port Unreachable
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp_t3(struct sr_instance* sr, uint8_t* packet, 
                     unsigned int len, uint8_t icmp_type, uint8_t icmp_code, 
                     struct sr_if* iface)
{
    sr_ethernet_hdr_t* orig_eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* orig_ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Allocate new packet */
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* reply = (uint8_t*)malloc(reply_len);
    
    /* Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)reply;
    memcpy(eth_hdr->ether_dhost, orig_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);
    
    /* IP header */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src = iface->ip;
    ip_hdr->ip_dst = orig_ip_hdr->ip_src;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    /* ICMP header */
    sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    icmp_hdr->icmp_sum = 0;
    
    /* Copy original IP header + 8 bytes of payload */
    memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);
    
    /* Calculate ICMP checksum */
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    
    /* Send the packet */
    sr_send_packet(sr, reply, reply_len, iface->name);
    free(reply);
}

/*---------------------------------------------------------------------
 * Method: handle_arpreq
 * Scope:  Local
 *
 * Handles sending ARP requests and ICMP host unreachable messages
 * for a given ARP request entry.
 *
 *---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req)
{
    time_t now = time(NULL);
    
    /* Check if we need to send/resend ARP request */
    if (difftime(now, req->sent) >= 1.0) {
        if (req->times_sent >= 5) {
            /* Send ICMP host unreachable to all waiting packets */
            struct sr_packet* pkt = req->packets;
            while (pkt) {
                /* Get the outgoing interface for the ICMP reply */
                sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(pkt->buf);
                sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
                
                /* Find interface to send ICMP reply back */
                struct sr_if* iface = sr_get_interface(sr, pkt->iface);
                if (iface) {
                    /* Send ICMP type 3, code 1 (Host Unreachable) */
                    sr_send_icmp_t3(sr, pkt->buf, pkt->len, 3, 1, iface);
                }
                pkt = pkt->next;
            }
            /* Destroy the ARP request */
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            /* Send ARP request */
            /* Need to find the outgoing interface for this request */
            struct sr_packet* pkt = req->packets;
            if (pkt) {
                struct sr_if* iface = sr_get_interface(sr, pkt->iface);
                if (iface) {
                    sr_send_arp_request(sr, req->ip, iface);
                }
            }
            
            /* Update request metadata */
            req->sent = now;
            req->times_sent++;
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

}/* end sr_ForwardPacket */

