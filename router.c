#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"

#define MAC 6
#define IPv4 4
#define TTL_SIZE 64
#define IP_PROTO 1
#define MAX_ARP_CACHE_SIZE 300
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806
#define MAX_TABLE_LEN 100000 // nr max de intrari in tabela de rutare
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define TIME_EXCEEDED 11
#define TIME_EXCEEDED_CODE 0
#define DEST_UNREACHABLE 3
#define DEST_UNREACHABLE_CODE 0
#define IP_BEGIN sizeof(struct ether_header)
#define ARP_BEGIN sizeof(struct ether_header)
#define ICMP_BEGIN sizeof(struct ether_header) + sizeof(struct iphdr)
#define ICMP_DATA sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)
#define ICMP_SIZE_64 sizeof(struct iphdr) + 8

struct route_table_entry *table;
int table_len;

struct arp_table_entry *arp_table;
int arp_table_len;

queue global_queue;
int global_queue_len;

struct queue_packet
{
	char *info;
	size_t len;
	int interface;
	uint32_t next_hop;
};

int comparator(const void *a, const void *b)
{
	if (ntohl(((struct route_table_entry *)a)->prefix) > ntohl(((struct route_table_entry *)b)->prefix))
		return 1;

	if (ntohl(((struct route_table_entry *)a)->prefix) == ntohl(((struct route_table_entry *)b)->prefix))
	{
		if (ntohl(((struct route_table_entry *)a)->mask) > ntohl(((struct route_table_entry *)b)->mask))
			return 1;
	}
	return -1;
}

struct route_table_entry *get_best_route_bsearch(uint32_t daddr)
{
	int left = 0;
	int right = table_len - 1;
	int mid;
	struct route_table_entry *best_route = NULL;
	while (left <= right)
	{
		mid = left + (right - left) / 2;
		if ((daddr & table[mid].mask) == table[mid].prefix)
		{
			if (!best_route)
			{
				best_route = &table[mid];
			}
			else
			{
				if (ntohl(table[mid].mask) > ntohl(best_route->mask))
				{
					best_route = &table[mid];
				}
			}
		}
		if (ntohl(table[mid].prefix) <= ntohl(daddr))
		{
			left = mid + 1;
		}
		else
		{
			right = mid - 1;
		}
	}
	return best_route;
}
void arp_request(int interface, char *buf, size_t len)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ARP_BEGIN);

	arp_hdr->op = htons(ARPOP_REPLY);

	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(interface));

	memcpy(arp_hdr->tha, arp_hdr->sha, MAC);
	get_interface_mac(interface, arp_hdr->sha);

	memcpy(eth_hdr->ether_dhost, arp_hdr->tha, MAC);
	get_interface_mac(interface, eth_hdr->ether_shost);

	send_to_link(interface, buf, len);
}

void handle_icmp(int interface, char *buf, uint8_t type, uint8_t code, size_t *len)
{
	// this can either act as an echo request or it can reply with the corresponding error type&code
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_BEGIN);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ICMP_BEGIN);

	icmp_hdr->type = type;
	icmp_hdr->code = code;

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	int icmp_size = ICMP_SIZE_64;
	memcpy(buf + ICMP_DATA, ip_hdr, icmp_size);
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = htons(TTL_SIZE);
	ip_hdr->protocol = IP_PROTO;
	ip_hdr->tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC);
	get_interface_mac(interface, eth_hdr->ether_shost);

	*len = ICMP_DATA;
	send_to_link(interface, buf, *len);
}

void forward_packet(int interface, char *buf, size_t len)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_BEGIN);

	// check if checksums match
	uint16_t checksum_recv = ip_hdr->check;
	ip_hdr->check = 0;
	if (checksum_recv != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
	{
		printf("Checksums don't match\n");
		return;
	}

	// check if ttl expired
	if (ip_hdr->ttl <= 1)
	{
		// send Time excedeed type 11 code 0
		handle_icmp(interface, buf, TIME_EXCEEDED, TIME_EXCEEDED_CODE, &len);
		return;
	}

	ip_hdr->ttl--;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// get the next best route
	struct route_table_entry *best_route = get_best_route_bsearch(ip_hdr->daddr);
	// printf("Best route: %d\n", best_route->next_hop);

	if (!best_route)
	{
		// send destination unreachable type 3 code 0
		handle_icmp(interface, buf, DEST_UNREACHABLE, DEST_UNREACHABLE_CODE, &len);
		return;
	}

	int found_arp = 0;
	// retain the mac address of the next hop if we find a valid one
	uint8_t *mac = malloc(MAC);
	for (int k = 0; k < arp_table_len; k++)
	{
		if (arp_table[k].ip == best_route->next_hop)
		{
			found_arp = 1;
			memcpy(mac, arp_table[k].mac, MAC);
			break;
		}
	}

	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	if (found_arp == 0)
	{
		struct queue_packet *current = malloc(sizeof(struct queue_packet));
		// insert packet in queue
		current->len = len;
		current->info = malloc(len);
		current->interface = best_route->interface;
		current->next_hop = best_route->next_hop;
		memcpy(current->info, buf, len);
		queue_enq(global_queue, current);
		global_queue_len++;

		struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + ARP_BEGIN);

		arp_hdr->htype = htons(1);
		arp_hdr->ptype = htons(IP_TYPE);
		arp_hdr->hlen = MAC;
		arp_hdr->plen = IPv4;
		arp_hdr->op = htons(ARPOP_REQUEST);

		get_interface_mac(best_route->interface, arp_hdr->sha);

		arp_hdr->spa = inet_addr(get_interface_ip(interface));

		memset(arp_hdr->tha, 0, MAC);
		arp_hdr->tpa = best_route->next_hop;

		memset(eth_hdr->ether_dhost, 0xff, MAC);
		eth_hdr->ether_type = htons(ARP_TYPE);

		uint16_t send_size = sizeof(struct ether_header) + sizeof(struct arp_header);

		send_to_link(best_route->interface, (char *)eth_hdr, send_size);
		return;
	}
	memcpy(eth_hdr->ether_dhost, mac, MAC);
	free(mac);
	send_to_link(best_route->interface, buf, len);
}

void handle_ip_packet(int interface, char *buf, size_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_BEGIN);
	/* Convert Internet host address from numbers-and-dots notation in CP
	into binary data in network byte order.  */
	// Check if it's a echo request, if it is we reply if not keeps forwarding
	if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
	{
		handle_icmp(interface, buf, 0, 0, &len);
	}
	else
	{
		forward_packet(interface, buf, len);
	}
}

void arp_reply(int interface, char *buf, size_t len)
{
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ARP_BEGIN);

	// add the mac address to the arp table
	arp_table[arp_table_len].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, MAC);
	arp_table_len++;

	struct ether_header *current_eth;
	struct queue_packet *current;

	int packets_removed = 0;

	for (int i = 0; i < global_queue_len; i++)
	{
		current = (struct queue_packet *)queue_deq(global_queue);
		current_eth = (struct ether_header *)current->info;

		if (current->next_hop == arp_hdr->spa)
		{
			memcpy(current_eth->ether_dhost, arp_hdr->sha, MAC);

			send_to_link(current->interface, (char *)current_eth, current->len);

			free(current->info);
			free(current);
			packets_removed++;
		}
		else
		{
			queue_enq(global_queue, current);
		}
	}

	global_queue_len -= packets_removed;
}

void handle_arp_packet(int interface, char *buf, size_t len)
{
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ARP_BEGIN);
	if (arp_hdr->op == htons(ARPOP_REQUEST))
	{
		arp_request(interface, buf, len);
	}
	else if (arp_hdr->op == htons(ARPOP_REPLY))
	{
		arp_reply(interface, buf, len);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	table = malloc(MAX_TABLE_LEN * sizeof(struct route_table_entry));
	table_len = read_rtable(argv[1], table);
	qsort(table, table_len, sizeof(struct route_table_entry), comparator);

	global_queue = queue_create();
	global_queue_len = 0;

	arp_table_len = 0;

	arp_table = malloc(MAX_ARP_CACHE_SIZE * sizeof(struct arp_table_entry));

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ntohs(eth_hdr->ether_type) == IP_TYPE)
		{
			handle_ip_packet(interface, buf, len);
		}
		else if (ntohs(eth_hdr->ether_type) == ARP_TYPE)
		{
			handle_arp_packet(interface, buf, len);
		}
	}

	free(table);
	free(arp_table);
}