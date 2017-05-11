#include "Traceroute.h"

Traceroute::Traceroute() {
	id = GetCurrentProcessId();
	sin_size = sizeof(struct sockaddr_in);

	initializeInfoArr();

	longest_trace = 0;
	total_number_of_ips = 0;
	ip_for_longest_trace = 0;

	for (int j = 0; j < MAX_HOPS; j++) {
		hop_counts[j] = 0;
	}

	for (int i = 0; i < 40; i++) {
		trace_times[i] = 0;
	}

	if (initializeSocket() != STATUS_OK) {
		exit(-1);
	}



}

void Traceroute::initializeInfoArr() {
	for (int i = 0; i < MAX_HOPS; i++) {
		ICMPResponseInfo *new_info = new ICMPResponseInfo();
		new_info->success = false;
		new_info->number_of_attempts = 0;
		new_info->time_sent = 0;
		new_info->host_name = "hostname.com";
		new_info->error_message = "";


		info_arr[i] = new_info;
	}
}

DWORD Traceroute::startThreads() {

	
	
	
	for (int i = 0; i < MAX_HOPS; i++) {

		ThreadData *threadData = new ThreadData();

		threadData->mutex = CreateMutex(NULL,0,NULL);
		threadData->traceroute_completed = false;
		threadData->host_name = "";
		threadData->ip_to_lookup = "";

		thread_data_arr[i] = threadData;

		handles[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)reverseDNSLookupFunction, threadData, 0, NULL);
	}
	

	return STATUS_OK;
}

//If a host is entered it is converted
//If it is an ip it is just left alone
char *convertHostToIP(char *host_or_ip) {
	// first assume that the string is an IP address
	/*
	* Take or HW1
	*/
	struct hostent *remote;
	struct sockaddr_in server;
	DWORD potential_ip = inet_addr(host_or_ip);
	if (potential_ip == INADDR_NONE) //It is not an IP
	{
		try {
			remote = gethostbyname(host_or_ip);
		}
		catch (int e) {
			printf("gethostbyname failed");
			return NULL;
		}
		// if not a valid IP, then do a DNS lookup
		//if ((remote = gethostbyname(str)) == NULL)
		if (remote == NULL)
		{
			//printf("Invalid string: neither FQDN, nor IP address\n");
			return NULL;
		}
		else { // take the first IP address and copy into sin_addr
			//printf("Copy over\n");
			memcpy((char *)&(server.sin_addr), remote->h_addr, remote->h_length);
		}
	}
	else {
		return host_or_ip;
	}

	host_or_ip = inet_ntoa(server.sin_addr);
	return host_or_ip;
}

DWORD Traceroute::trace(char *host_or_ip) {
	
	host_or_ip = convertHostToIP(host_or_ip);
	DWORD IP = inet_addr(host_or_ip);
	printf("Tracerouting to %s...\n",host_or_ip);
	pc = PreciseCounter();
	pc.startCounter();
	double start_time = pc.getCounter();
	startThreads();
	sendFirstWaveOfPackets(IP);
	recvICMPPackets(false);
	closeAllThreads();
	retrieveHostNames();
	handleRetx(IP,false);
	printResults();
	printf("\nTotal execution time : %f ms\n",(pc.getCounter() - start_time));
	//while (1);
	return STATUS_OK;
}

DWORD Traceroute::traceBatchMode(std::vector<char*> vec) {
	int i = 0;
	int num_of_sucessful_pings = 0;
	
	//Initialize the trace times
	double send_time = 0;
	double trace_time = 0;
	pc = PreciseCounter();
	pc.startCounter();
	while(num_of_sucessful_pings < 10 && i < vec.size()){
		//printf("\n\nNum of sucessfulk pings: %d\n\n", num_of_sucessful_pings);
		//printf("IP: %s\n",vec[i]);

		vec[i] = convertHostToIP(vec[i]);
		initializeInfoArr();
		DWORD IP = inet_addr(vec[i]);
		
		//startThreads();
		send_time = pc.getCounter();
		sendFirstWaveOfPackets(IP);
		recvICMPPackets(true);
		trace_time = pc.getCounter() - send_time;
		trace_times_vec.push_back(pc.getCounter() - send_time);
		//trace_times[i] = 
		//closeAllThreads();
		//retrieveHostNames();
		//handleRetx(IP, true);
		//printResults();
		if (gatherStatisticsAboutTrace()) {
			num_of_sucessful_pings++;
		}
		i++;
		//while (1);
	}
	printStatistics();
	//printf("Num of successful traces: %d\n", num_of_sucessful_pings);
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
		//printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
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
	info_arr[ttl]->time_sent = pc.getCounter();
	if (sendto(sock, (const char *) icmp, packet_size, 0, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {

		printf("Error in sendto: %d\n", WSAGetLastError());
		return SEND_FAILED;
	}

	return STATUS_OK;
}

DWORD Traceroute::sendFirstWaveOfPackets(DWORD IP) {
	//Send the initial set of packets
	for (int i = 0; i < MAX_HOPS; i++) {
		sendICMPPacket(IP, i);
	}
	return STATUS_OK;
}


/*
* Taken from HW instructions
* With modifications
*/

DWORD Traceroute::recvICMPPackets(bool batchMode) {
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	// receive from the socket into rec_buf
	//printf("Trying to recv the packet\n");
	//fd_set fd;
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

	bool inspect_packet = true;
	while (true) {
		inspect_packet = true;

		available = select(0, &fd, NULL, NULL, &timeout);
		response_size = sizeof(response);

		if (available == SOCKET_ERROR) {
			printf("select() error occurred: %d\n",WSAGetLastError);
			inspect_packet = false;
		}
		else if (available == 0) {
			//printf("select() timed out\n");
			break;
		}
		else if (available > 0) {
			if ((recv_pkt_size = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &response_size)) == SOCKET_ERROR) {
				printf("Error while receiving: %d\n", WSAGetLastError());
				inspect_packet = false;
			}
			//printf("Recv'ed the packet\n");
		}
		else {
			printf("Unknown error in select()\n");
			inspect_packet = false;
		}

		//...
		// check if this is TTL_expired; make sure packet size >= 56 bytes
		//TODO: Figure out why these replies are so small
		if (recv_pkt_size < 56) {
			//printf("Received too small of a packet: %d\n",recv_pkt_size);
			//inspect_packet = false;
		}

		//printf("router_icmp_hrd->code: %s\n", router_icmp_hdr->code);

		if (inspect_packet) {
			if (router_icmp_hdr->type == ICMP_TTL_EXPIRE /*&& router_icmp_hdr->code == '0'*/) //TTL expired response
			{
				if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[orig_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[orig_icmp_hdr->seq]->time_sent;

						// take router_ip_hdr->source_ip and
						// initiate a DNS lookup
						//printf("\nRecv a TTL expire\n");
						info_arr[orig_icmp_hdr->seq]->success = true;
						info_arr[orig_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[orig_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						}
						
						//inet_ntop();
					}
				}
			}
			else if (router_icmp_hdr->type == ICMP_ECHO_REPLY /*&& router_icmp_hdr->code == '0'*/) //Echo Reply response
			{
				//printf("\n\nGot the final reply\n\n");
				if (router_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (router_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[router_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[router_icmp_hdr->seq]->time_sent;

						// take router_ip_hdr->source_ip and
						// initiate a DNS lookup
						info_arr[router_icmp_hdr->seq]->success = true;
						info_arr[router_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[router_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, router_icmp_hdr->seq);
						}
						
						info_arr[router_icmp_hdr->seq]->final_destination = true;
						//inet_ntop();
					}
				}
			}
			else {
				if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					//printf("Here\n");
					// check if process ID matches
					if (orig_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[orig_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[orig_icmp_hdr->seq]->time_sent;

						// initiate a DNS lookup
						info_arr[orig_icmp_hdr->seq]->success = true;
						info_arr[orig_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[orig_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						}
						
						info_arr[orig_icmp_hdr->seq]->unexpected_code = true;

						//Add the error message
						//char error_message[25];
						//printf("Unexpected type/code: Type: %x Code: %x\n", router_icmp_hdr->type, router_icmp_hdr->code);
						//info_arr[orig_icmp_hdr->seq]->error_message = error_message;

						char error_message[50];
						sprintf(error_message, "Unexpected type/code: Type: %c Code: %c", router_icmp_hdr->type, router_icmp_hdr->code);
						info_arr[orig_icmp_hdr->seq]->error_message = error_message;
					}
				}
			}
		}
	}
	return STATUS_OK;
}

DWORD Traceroute::calculateRTO(std::stack<int> stk) {
	int new_rto = 0;
	int seq = 0;
	while (stk.size() > 0) {
		int seq = stk.top();
		stk.pop();

		//Get the below time
		double below_time = 0;
		if (((seq - 1) >= 0) && (info_arr[seq - 1]->success == true)) {
			below_time = info_arr[seq - 1]->RTT;
		}

		//Get the above time
		double above_time = 0;
		while ((seq < (MAX_HOPS - 1)) && !info_arr[seq]->final_destination) {
			if (info_arr[seq + 1]->success) {
				above_time = info_arr[seq]->RTT;
				break;
			}
			seq++;
		}

		if (below_time != 0 && above_time != 0) { //Use the average * 2
			new_rto = below_time + above_time;
		}
		else if (below_time == 0 && above_time != 0){ //Double the above time
			new_rto = above_time * 2;
		}
		else { //Use the default
			new_rto = INITIAL_PROBE_TIMEOUT;
		}

		info_arr[seq]->RTO = new_rto;
	}
	
	//printf("")
	
	return STATUS_OK;
}

DWORD Traceroute::handleRetx(DWORD IP,bool batchMode) {
	//printf("\nRetX\n");
	/*
	* Based off pseudo code from Piazza Reponse: https://piazza.com/class/iy0nxnbxdsf6m9?cid=210
	*/
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	// receive from the socket into rec_buf
	//printf("Trying to recv the packet\n");
	//fd_set fd;
	FD_ZERO(&fd); // clear the set
	FD_SET(sock, &fd); // add your socket to the set
	if (sock == SOCKET_ERROR) {
		printf("socket error in recv()\n");
		return FAILED_RECV;
	}
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = INITIAL_PROBE_TIMEOUT;

	int available = 0;
	struct sockaddr_in response;
	int response_size = 0;
	int recv_pkt_size = 0;

	//TODO: handle for different ICMP codes
	//TODO: make the timeout dynamic
	//TODO: Calculate the RTO's
	bool inspect_packet = true;


	std::stack<int> retx_stk;
	for (int i = 0; i < MAX_HOPS; i++) {
		if (!info_arr[i]->success) {
			retx_stk.push(i);
		}
		if (info_arr[i]->final_destination) {
			break;
		}
	}

	if (retx_stk.size() < 1) {
		return STATUS_OK;
	}

	//printf("Calculate RTO\n");
	calculateRTO(retx_stk);

	int cur_seq = retx_stk.top();
	//printf("Send first retx\n");
	sendICMPPacket(IP, cur_seq);

	//Set the timeout to the calculated one
	//printf("Timeout: %d", info_arr[cur_seq]->RTO);
	timeout.tv_usec = info_arr[cur_seq]->RTO;

	while (retx_stk.size() > 0) {

		FD_ZERO(&fd); // clear the set
		FD_SET(sock, &fd); // add your socket to the set
		if (sock == SOCKET_ERROR) {
			printf("socket error in recv()\n");
			return FAILED_RECV;
		}

		//TODO: Make this timeout dynamic
		available = select(0, &fd, NULL, NULL, &timeout);
		response_size = sizeof(response);

		if (available == SOCKET_ERROR) { //Error
			printf("select() error occurred: %d\n", WSAGetLastError());
			inspect_packet = false;
		}
		else if (available == 0) { //Timeout
			info_arr[cur_seq]->number_of_attempts++;
			if (info_arr[cur_seq]->number_of_attempts < 3) {
				sendICMPPacket(IP, cur_seq);
				//TODO: reset the timeout
			}
			else {
				retx_stk.pop();
				if (retx_stk.size() == 0) {
					break;
				}
				else {
					cur_seq = retx_stk.top();
				}
				
			}
			//printf("select() timed out\n");
		}
		else if (available > 0) { //Stuff available to read
			

			if ((recv_pkt_size = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &response_size)) == SOCKET_ERROR) {
				printf("Error while receiving: %d\n", WSAGetLastError());
				inspect_packet = false;
			}
			
			//printf("Recv'ed the packet\n");

			//TODO: handle for the code
			if (router_icmp_hdr->type == ICMP_TTL_EXPIRE /*&& router_icmp_hdr->code == '0'*/) //TTL expired response
			{
				if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[orig_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[orig_icmp_hdr->seq]->time_sent;

						// take router_ip_hdr->source_ip and
						// initiate a DNS lookup
						info_arr[orig_icmp_hdr->seq]->success = true;
						info_arr[orig_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[orig_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						}

						//inet_ntop();
					}
				}
			}
			else if (router_icmp_hdr->type == ICMP_ECHO_REPLY /*&& router_icmp_hdr->code == '0'*/) //Echo Reply response
			{
				//printf("\n\nGot the final reply\n\n");
				if (router_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (router_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[router_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[router_icmp_hdr->seq]->time_sent;

						// take router_ip_hdr->source_ip and
						// initiate a DNS lookup
						info_arr[router_icmp_hdr->seq]->success = true;
						info_arr[router_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[router_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, router_icmp_hdr->seq);
						}

						info_arr[router_icmp_hdr->seq]->final_destination = true;
						//inet_ntop();
					}
				}
			}
			else {
				if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == id)
					{
						//Record the RTT
						info_arr[orig_icmp_hdr->seq]->RTT = pc.getCounter() - info_arr[orig_icmp_hdr->seq]->time_sent;

						// initiate a DNS lookup
						info_arr[orig_icmp_hdr->seq]->success = true;
						info_arr[orig_icmp_hdr->seq]->ip = router_ip_hdr->source_ip;
						info_arr[orig_icmp_hdr->seq]->number_of_attempts++;
						if (!batchMode) {
							dnsLookUp(router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						}

						info_arr[orig_icmp_hdr->seq]->unexpected_code = true;

						//Add the error message
						char error_message[50];
						sprintf(error_message, "Unexpected type/code: Type: %c Code: %c", router_icmp_hdr->type, router_icmp_hdr->code);
						info_arr[orig_icmp_hdr->seq]->error_message = error_message;
					}
				}
			}
		}
		else { //Unknown
			//printf("Unknown error in select()\n");
			inspect_packet = false;
		}

		////Check if we're done
		//bool done = true;
		//for (int i = 0; i < MAX_HOPS; i++) {
		//	if (!info_arr[i]->success) {
		//		done = false;
		//	}
		//	if (info_arr[i]->final_destination) {
		//		break;
		//	}
		//}

		//if (done) {
		//	break;
		//}
	}

	return STATUS_OK;
}

DWORD Traceroute::dnsLookUp(u_long source_ip,u_short seq) {

	//Create the info for the response
	/*
	if (info_arr[seq] == NULL) {
		ICMPResponseInfo *new_info = new ICMPResponseInfo();
		new_info->success = true;
		new_info->ip = source_ip;
		new_info->number_of_attempts++;
		new_info->time = 0;
		new_info->host_name = "hostname.com";

		info_arr[seq] = new_info;
	}
	else {
		info_arr[seq]->number_of_attempts++;
	*/

	/*info_arr[seq]->success = true;
	info_arr[seq]->ip = source_ip;
	info_arr[seq]->number_of_attempts++;*/
	
	
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

void Traceroute::printResults() {
	char str[INET_ADDRSTRLEN];
	for (int i = 0; i < MAX_HOPS; i++) {
		if (!info_arr[i]->success) {
			if (info_arr[i]->error_message != "") {
				printf("%d * %s\n", i, info_arr[i]->error_message);
			}
			else {
				printf("%d *\n", i);
			}
		}
		else {
			/*
			* Modified solution from http://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
			*/
			inet_ntop(AF_INET, &info_arr[i]->ip, str, INET_ADDRSTRLEN);
			
			if (!info_arr[i]->unexpected_code) {
				printf("%d %s (%s) %.3f ms (%d)\n", i, info_arr[i]->host_name.c_str(), str, info_arr[i]->RTT, info_arr[i]->number_of_attempts);
			}
			else {
				printf("%d %s (%s) %.3f ms (%d) \n", i, info_arr[i]->host_name.c_str(), str, info_arr[i]->RTT, info_arr[i]->number_of_attempts);
			}
			
			//If this was the last one break
			
			
			if (info_arr[i]->final_destination) {
				//printf("Final Destination\n");
				break;
			}
			
			
		}
	}

	return;
}


bool Traceroute::gatherStatisticsAboutTrace() {
	char str[INET_ADDRSTRLEN];
	for (int i = 0; i < MAX_HOPS; i++) {
		if (!info_arr[i]->success) {
			//printf("%d * (%d)\n", i, info_arr[i]->number_of_attempts);
		}
		else {
			/*
			* Modified solution from http://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
			*/
			unique_ips.insert(info_arr[i]->ip);
			total_number_of_ips++;

			inet_ntop(AF_INET, &info_arr[i]->ip, str, INET_ADDRSTRLEN);

			if (!info_arr[i]->unexpected_code) {
				printf("%d %s (%s) %.3f ms (%d)\n", i, info_arr[i]->host_name.c_str(), str, info_arr[i]->RTT, info_arr[i]->number_of_attempts);
			}
			else {
				printf("%d %s (%s) %.3f ms (%d) \n", i, info_arr[i]->host_name.c_str(), str, info_arr[i]->RTT, info_arr[i]->number_of_attempts);
			}

			//If this was the last one break

			if (info_arr[i]->final_destination) {
				//Replace the longest trace if this is new
				if (i > longest_trace) {
					longest_trace = i;
					ip_for_longest_trace = info_arr[i]->ip;
				}

				hop_counts[i]++;
				printf("Final Destination\n");
				return true;
			}


		}
	}

	return false;
}

void Traceroute::printStatistics() {

	//int hop_counts[MAX_HOPS];
	//std::set<u_long> unique_ips;
	//int total_number_of_ips;
	//int longest_trace;

	/*
	* Modified solution from http://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
	*/
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_for_longest_trace), str, INET_ADDRSTRLEN);
	printf("IP for longest trace: %s\n", str);

	printf("Unique IPs: %d\n",unique_ips.size());
	printf("Total # of IPs: %d\n",total_number_of_ips);
	printf("Longest Trace: %d\n",longest_trace);

	for (int i = 0; i < MAX_HOPS; i++) {
		printf("Hop Count[%d]: %d\n",i,hop_counts[i]);
	}

	for (int i = 0; i < trace_times_vec.size(); i++) {
		printf("%f\n",trace_times_vec[i]);
	}
}