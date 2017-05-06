#include "Traceroute.h"

Traceroute::Traceroute() {
	id = GetCurrentProcessId();
	sin_size = sizeof(struct sockaddr_in);

	for (int i = 0; i < MAX_HOPS; i++) {
		info_arr[i] = NULL;
	}

	if (initializeSocket() != STATUS_OK) {
		exit(-1);
	}



}

DWORD Traceroute::startThreads() {

	
	
	
	for (int i = 0; i < MAX_HOPS; i++) {

		ThreadData *threadData = new ThreadData();

		threadData->mutex;
		threadData->traceroute_completed = false;
		threadData->host_name = NULL;
		threadData->ip_to_lookup = NULL;

		thread_data_arr[i] = threadData;

		handles[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)reverseDNSLookupFunction, thread_data_arr[i], 0, NULL);
	}
	

	return STATUS_OK;
}


DWORD Traceroute::trace(char *host_or_ip) {
	
	DWORD IP = inet_addr(host_or_ip);
	startThreads();
	
	//Send the initial set of packets
	for (int i = 0; i < MAX_HOPS; i++) {
		sendICMPPacket(IP,i);
	}
	printf("Sent Packet\n");
	recvICMPPackets();
	closeAllThreads();
	retrieveHostNames();
	printResults();
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

DWORD Traceroute::recvICMPPackets() {
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
	timeout.tv_usec = 100000;

	int available = 0;
	struct sockaddr_in response;
	int response_size = 0;
	int recv_pkt_size = 0;

	//TODO: handle for different ICMP codes
	bool inspect_packet = true;
	while (true) {
		inspect_packet = true;

		available = select(0, &fd, NULL, NULL, &timeout);
		response_size = sizeof(response);

		if (available == SOCKET_ERROR) {
			printf("select() error occurred\n");
			inspect_packet = false;
		}
		else if (available == 0) {
			printf("select() timed out\n");
			break;
		}
		else if (available > 0) {
			if ((recv_pkt_size = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &response_size)) == SOCKET_ERROR) {
				printf("Error while receiving: %d\n", WSAGetLastError());
				inspect_packet = false;
			}
			printf("Recv'ed the packet\n");
		}
		else {
			printf("Unknown error in select()\n");
			inspect_packet = false;
		}

		//...
		// check if this is TTL_expired; make sure packet size >= 56 bytes
		if (recv_pkt_size < 56) {
			printf("Received too small of a packet\n");
			inspect_packet = false;
		}

		//printf("router_icmp_hrd->code: %s\n", router_icmp_hdr->code);
		//TODO Figure out correct code to use
		//TODO end when we've reached the destination
		if (inspect_packet) {
			if (router_icmp_hdr->type == ICMP_TTL_EXPIRE /*&& router_icmp_hdr->code == NULL*/)
			{
				if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == id)
					{
						// take router_ip_hdr->source_ip and
						// initiate a DNS lookup
						dnsLookUp(router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						//inet_ntop();
					}
				}
			}
		}
	}
	return STATUS_OK;
}

DWORD Traceroute::dnsLookUp(u_long source_ip,u_short seq) {

	//Create the info for the response
	ICMPResponseInfo *new_info = new ICMPResponseInfo();
	new_info->success = true;
	new_info->ip = source_ip;
	new_info->number_of_attempts++;
	new_info->time = 0;
	new_info->host_name = "hostname.com";

	info_arr[seq] = new_info;
	
	/*
	* Modified solution from http://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
	*/
	//Convert the u_long ip into a string
	struct in_addr temp_addr;
	temp_addr.S_un.S_addr = source_ip;

	char *ip_str = inet_ntoa(temp_addr);
	
	//Start the lookup for the thread
	WaitForSingleObject(thread_data_arr[seq]->mutex, INFINITE);
	thread_data_arr[seq]->ip_to_lookup = ip_str;
	ReleaseMutex(thread_data_arr[seq]->mutex);

	//Unnecessary, the thread will modifiy the host name for us
	/*
	bool cont = true;
	while (true) {
		WaitForSingleObject(thread_data_arr[seq]->mutex, INFINITE);
		if (thread_data_arr[seq]->host_name != NULL) {
			new_info->host_name = thread_data_arr[seq]->host_name;
			cont = false;
		}
		ReleaseMutex(thread_data_arr[seq]->mutex);
	}
	*/

	

	return STATUS_OK;
}

DWORD Traceroute::closeAllThreads() {

	//Singal all the threads to close
	for (int i = 0; i < MAX_HOPS; i++) {
		WaitForSingleObject(thread_data_arr[i]->mutex, INFINITE);
		thread_data_arr[i]->traceroute_completed = true;
		ReleaseMutex(thread_data_arr[i]->mutex);
	}

	for (int i = 0; i < MAX_HOPS; i++)
	{
		WaitForSingleObject(handles[i], INFINITE);
		CloseHandle(handles[i]);
	}

	return STATUS_OK;

}

void Traceroute::retrieveHostNames() {
	for (int i = 0; i < MAX_HOPS; i++) {
		WaitForSingleObject(thread_data_arr[i]->mutex, INFINITE);
		if (info_arr[i] != NULL) {
			info_arr[i]->host_name = thread_data_arr[i]->host_name;
		}
		ReleaseMutex(thread_data_arr[i]->mutex);
	}
}

//TODO wait for all the threads to close
void Traceroute::printResults() {

	//TODO: Limit this to end on the last ICMP packet
	for (int i = 0; i < MAX_HOPS; i++) {
		if (info_arr[i] == NULL) {
			printf("%d *\n",i);
		}
		else {
			printf("%d %s (%d) %.3f ms (%d)\n", i, info_arr[i]->host_name, info_arr[i]->ip,info_arr[i]->time,info_arr[i]->number_of_attempts);
		}
	}

	return;
}