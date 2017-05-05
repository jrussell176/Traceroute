#include "Traceroute.h"

Traceroute::Traceroute() {
	id = GetCurrentProcessId();
	sin_size = sizeof(struct sockaddr_in);

	for (int i = 0; i < info_arr_size; i++) {
		info_arr[i] = NULL;
	}

	if (initializeSocket() != STATUS_OK) {
		exit(-1);
	}
}

DWORD Traceroute::trace(char *host_or_ip) {
	
	DWORD IP = inet_addr(host_or_ip);
	sendICMPPacket(IP, 2);
	printf("Sent Packet\n");
	recvICMPPacket();
	return STATUS_OK;
}

DWORD Traceroute::initializeSocket() {
	//Create a socket
	/*
	* Pulled from HW instructions
	*/
	/* ready to create a socket */
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		// do some cleanup
		//...
		// then exit
		//exit(-1);
		return SOCKET_CREATE_FAILED;
	}

	return STATUS_OK;

}

/*
* Taken from CSCE 463 HW4 PDF, with modifications
*/
DWORD Traceroute::sendICMPPacket(DWORD IP, int ttl) {
	// buffer for the ICMP header
	u_char send_buf[MAX_ICMP_SIZE]; /* IP header is not present here */
	
	ICMPHeader *icmp = (ICMPHeader *)send_buf;

	// set up the echo request
	// no need to flip the byte order
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;

	// set up ID/SEQ fields as needed
	icmp->id = id;
	icmp->seq = ttl;
	// initialize checksum to zero
	icmp->checksum = 0;

	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes
	icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);

	// need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
	// name in multicast headers – do not use it!
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
	{
		printf("setsockopt failedwith %d\n", WSAGetLastError());
		closesocket(sock);
		// some cleanup
		exit(-1);
	}

	//Initialize the server sockaddr
	//struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.S_un.S_addr = IP;

	// Send the packet
	if (sendto(sock, (const char *) icmp, packet_size, 0, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {

		printf("Error in sendto: %d\n", WSAGetLastError());
		return SEND_FAILED;
	}

	return STATUS_OK;
}

/*
* Taken from HW instructions
* With modifications
*/

DWORD Traceroute::recvICMPPacket() {
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	// receive from the socket into rec_buf
	printf("Trying to recv the packet\n");
	fd_set fd;
	FD_ZERO(&fd); // clear the set
	FD_SET(sock, &fd); // add your socket to the set
	if (sock == SOCKET_ERROR) {
		printf("socket error in recv()\n");
		return FAILED_RECV;
	}
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000000;
	int available = select(0, &fd, NULL, NULL, &timeout);
	struct sockaddr_in response;
	int response_size = sizeof(response);
	int recv_pkt_size = 0;

	if (available == SOCKET_ERROR) {
		printf("select() error occurred\n");
		return FAILED_RECV;
	}
	else if (available == 0) {
		printf("select() timed out\n");
		return FAILED_RECV;
	}
	else if (available > 0) {
		if ((recv_pkt_size = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0,(struct sockaddr*)&response, &response_size)) == SOCKET_ERROR) {
			printf("Error while receiving: %d", WSAGetLastError());
			return FAILED_RECV;
		}
		printf("Recv'ed the packet\n");
	}
	else {
		printf("Unknown error in select()\n");
	}
	


	//...
	// check if this is TTL_expired; make sure packet size >= 56 bytes
	if (recv_pkt_size < 56) {
		printf("Received too small of a packet\n");
		return FAILED_RECV;
	}

	printf("router_icmp_hrd->code: %s\n", router_icmp_hdr->code);
	//TODO Figure out correct code to use
	if (router_icmp_hdr->type == ICMP_TTL_EXPIRE && router_icmp_hdr->code == NULL)
	{
		if (orig_ip_hdr->proto == IPPROTO_ICMP)
		{
			// check if process ID matches
			if (orig_icmp_hdr->id == id)
			{
				// take router_ip_hdr->source_ip and
				// initiate a DNS lookup
				dnsLookUp(router_ip_hdr->source_ip);
			}
		}
	}


	return STATUS_OK;
}

DWORD Traceroute::dnsLookUp(u_long source_ip) {

	printf("DNS Lookup");
	return STATUS_OK;
}