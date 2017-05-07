#pragma once
#include "NetworkStructs.h"

class ThreadData {
public:
	HANDLE mutex;

	boolean traceroute_completed;

	//char *ip_to_lookup; //NULL if no ip needs to be looked up
	std::string ip_to_lookup;

	std::string host_name;
};

inline void WINAPI reverseDNSLookupFunction(LPVOID lpParam) {

	if (lpParam == NULL) {
		printf("No parameters sent to sender thread");
		return;
	}
	ThreadData *threadData = ((ThreadData*)lpParam);

	boolean cont = true;
	while (cont) {
		WaitForSingleObject(threadData->mutex, INFINITE);

		struct in_addr ip;
		struct hostent *he;

		threadData->host_name = "<no DNS entry>";
		
		//Check if we have an IP to look up
		if (cont) {
			if (threadData->ip_to_lookup != "") {
				//Were going to look up an IP so were done
				cont = false;
				char *host_name = "";

				inet_pton(AF_INET, threadData->ip_to_lookup.c_str(), &ip);

				he = gethostbyaddr((const char *)&ip, sizeof(ip), AF_INET);
				if (he == NULL) {
					//printf("No host name found for ip\n");
					threadData->host_name = "<no DNS entry>";
				}
				else {
					threadData->host_name = he->h_name;
				}

				printf("%s --> %s\n", threadData->ip_to_lookup.c_str(), threadData->host_name);
			}
		}

		//Check if its time to quit
		if (threadData->traceroute_completed) {
			cont = false;
		}

		ReleaseMutex(threadData->mutex);
	}

	printf("Exiting thread\n");
	return;
}