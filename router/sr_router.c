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

void sr_init(struct sr_instance *sr)
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

void sr_send_arp_request(struct sr_instance *sr, uint32_t tip, struct sr_if *iface)
{
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(len);

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* Broadcast */
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    /* ARP header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN); /* Target MAC unknown */
    arp_hdr->ar_tip = tip;

    sr_send_packet(sr, packet, len, iface->name);
    free(packet);
}

void sr_send_icmp_t3(struct sr_instance *sr, uint8_t *packet,
                     unsigned int len, uint8_t icmp_type, uint8_t icmp_code,
                     struct sr_if *iface)
{
    sr_ethernet_hdr_t *orig_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *orig_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *reply = (uint8_t *)malloc(reply_len);

    /* Ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)reply;
    memcpy(eth_hdr->ether_dhost, orig_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    /* IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
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
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    icmp_hdr->icmp_sum = 0;

    memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);

    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

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
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
    time_t now = time(NULL);

    if (difftime(now, req->sent) >= 1.0)
    {
        if (req->times_sent >= 5)
        {
            /* Send ICMP host unreachable to all waiting packets */
            struct sr_packet *pkt = req->packets;
            while (pkt)
            {

                struct sr_if *iface = sr_get_interface(sr, pkt->iface);
                if (iface)
                {
                    sr_send_icmp_t3(sr, pkt->buf, pkt->len, 3, 1, iface);
                }
                pkt = pkt->next;
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
        else
        {
            /* Send ARP request */
            struct sr_packet *pkt = req->packets;
            if (pkt)
            {
                struct sr_if *iface = sr_get_interface(sr, pkt->iface);
                if (iface)
                {
                    sr_send_arp_request(sr, req->ip, iface);
                }
            }

            req->sent = now;
            req->times_sent++;
        }
    }
}

struct sr_if *iface_from_list(struct sr_instance *sr, char *interface)
{
    struct sr_if *list = sr->if_list;
    while (strcmp(list->name, interface) != 0)
    {
        list = list->next;
        if (list == NULL)
            return NULL;
    }
    return list;
}

struct sr_rt *longest_prefix_match(struct sr_instance *sr,
                                   uint32_t dst)
{
    struct sr_rt *entry = sr->routing_table;
    struct sr_rt *longest_match = NULL;
    uint32_t longest_mask = 0;

    while (entry)
    {
        uint32_t masked_dst = dst & entry->mask.s_addr;
        uint32_t masked_entry = entry->dest.s_addr & entry->mask.s_addr;

        /* check if same masked ip but more specific ip */
        if (masked_dst == masked_entry && entry->mask.s_addr > longest_mask)
        {
            longest_mask = entry->mask.s_addr;
            longest_match = entry;
        }

        entry = entry->next;
    }

    return longest_match;
}

void swap_eth_addr(uint8_t *packet)
{
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
    uint8_t tmp_address[ETHER_ADDR_LEN];

    memcpy(tmp_address, ehdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, tmp_address, ETHER_ADDR_LEN);
}

void reply_to_arp(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  char *interface,
                  struct sr_if *iface_info)
{
    swap_eth_addr(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = arp_hdr->ar_sip;
    memcpy(arp_hdr->ar_sha, iface_info->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface_info->ip;

    sr_send_packet(sr, packet, len, interface);
}

void icmp_echo_reply(struct sr_instance *sr,
                     uint8_t *packet,
                     unsigned int len,
                     char *interface,
                     struct sr_if *iface_info)
{
    uint8_t *hdr = packet;

    swap_eth_addr(hdr);

    hdr += sizeof(sr_ethernet_hdr_t);

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)hdr;
    iphdr->ip_ttl = 64;
    iphdr->ip_sum = 0;
    iphdr->ip_dst = iphdr->ip_src;
    iphdr->ip_src = iface_info->ip;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    hdr += sizeof(sr_ip_hdr_t);

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)hdr;
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;

    unsigned int len_remaining = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

    icmp_hdr->icmp_sum = cksum(icmp_hdr, len_remaining);

    sr_send_packet(sr, packet, len, interface);

    return;
}

void generate_imcp_error(struct sr_instance *sr,
                         uint8_t *packet,
                         unsigned int len,
                         char *interface,
                         struct sr_if *iface_info,
                         uint8_t type, uint8_t code)
{
    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    uint8_t *new_packet = calloc(1, new_len);
    uint8_t *hdr = new_packet;

    memcpy(hdr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    swap_eth_addr(hdr);

    hdr += sizeof(sr_ethernet_hdr_t);

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)hdr;
    iphdr->ip_ttl = 64;
    iphdr->ip_sum = 0;
    iphdr->ip_p = 1;
    iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    iphdr->ip_dst = iphdr->ip_src;
    iphdr->ip_src = iface_info->ip;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    hdr += sizeof(sr_ip_hdr_t);

    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)hdr;
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    memcpy(icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);

    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, new_packet, new_len, interface);
    free(new_packet);

    return;
}

void valid_ip_not_for_me(struct sr_instance *sr,
                         uint8_t *packet,
                         unsigned int len,
                         char *interface,
                         struct sr_if *iface_info)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_rt *match = longest_prefix_match(sr, ip_hdr->ip_dst);

    if (match == NULL)
    {
        generate_imcp_error(sr, packet, len, interface, iface_info, 3, 0);
    }
    else
    {
        struct sr_if *out_iface = sr_get_interface(sr, match->interface);

        struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), match->dest.s_addr);

        if (entry != NULL)
        {
            memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            sr_send_packet(sr, packet, len, out_iface->name);

            free(entry);
        }
        else
        {
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, out_iface->name);

            handle_arpreq(sr, req);
        }
    }
}

struct sr_if *router_interface_check(struct sr_instance *sr, uint32_t dst)
{
    struct sr_if *iface_entry = sr->if_list;

    while (iface_entry)
    {
        if (iface_entry->ip == dst)
        {
            return iface_entry;
        }
        iface_entry = iface_entry->next;
    }

    return NULL;
}

void ip_handler(struct sr_instance *sr,
                uint8_t *packet,
                unsigned int len,
                char *interface,
                struct sr_if *iface_info)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    uint16_t received_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = received_sum;

    /* drop the packet if checksum is wrong */
    if (received_sum != checksum)
    {
        return;
    }

    struct sr_if *router_iface = router_interface_check(sr, ip_hdr->ip_dst);

    if (router_iface)
    {
        if (ip_hdr->ip_p == 1)
        {
            icmp_echo_reply(sr, packet, len, interface, router_iface);
        }
        else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17)
        {
            generate_imcp_error(sr, packet, len, interface, router_iface, 3, 3);
        }
        else
        {
            printf("unknown type");
        }
    }
    else
    {
        if (ip_hdr->ip_ttl == 1)
        {
            generate_imcp_error(sr, packet, len, interface, iface_info, 11, 0);
        }
        else
        {
            valid_ip_not_for_me(sr, packet, len, interface, iface_info);
        }
    }
}

void arp_reply_handler(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (req)
    {
        struct sr_packet *pkt = req->packets;
        while (pkt)
        {
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

            struct sr_if *iface = sr_get_interface(sr, pkt->iface);
            memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

            sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));

            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            sr_send_packet(sr, pkt->buf, pkt->len, iface->name);

            pkt = pkt->next;
        }

        sr_arpreq_destroy(&(sr->cache), req);
    }
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    struct sr_if *iface_info = iface_from_list(sr, interface);

    if (ethertype(packet) == ethertype_arp)
    {
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        if (ntohs(arp_hdr->ar_op) == arp_op_request)
        {
            reply_to_arp(sr, packet, len, interface, iface_info);
            return;
        }
        else
        {
            arp_reply_handler(sr, packet, len, interface);
        }
    }
    else if (ethertype(packet) == ethertype_ip)
    {
        ip_handler(sr, packet, len, interface, iface_info);
        return;
    }
    else
    {
        return;
    }

} /* end sr_ForwardPacket */