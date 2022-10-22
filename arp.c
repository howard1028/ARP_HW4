#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type){
	packet->ea_hdr.ar_hrd = type;
}
void set_prot_type(struct ether_arp *packet, unsigned short int type){
	packet->ea_hdr.ar_pro = type;
}
void set_hard_size(struct ether_arp *packet, unsigned char size){
	packet->ea_hdr.ar_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size){
	packet->ea_hdr.ar_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code){
	packet->ea_hdr.ar_op = code;
}


void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{}

char* get_target_protocol_addr(struct ether_arp *packet) //get target ip addr
{
	struct in_addr recv_addr;
	memcpy(&recv_addr,packet->arp_tpa,4); //arp_tpa : arp target ip addr,抓ether_arp後面target ip addr
	return inet_ntoa(recv_addr);
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	struct in_addr send_addr;
	memcpy(&send_addr,packet->arp_spa,4); 
	return inet_ntoa(send_addr);
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
}
