#pragma once
#include "NetworkStructs.h"

class ThreadData {
public:
	HANDLE mutex;

	boolean traceroute_completed;

	char *ip_to_lookup; //NULL if no ip needs to be looked up

	char *host_name;
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

		//Check if its time to quit
		if (threadData->traceroute_completed) {
			cont = false;
		}

		struct in_addr ip;
		struct hostent *he;
		
		if (cont) {
			if (threadData->ip_to_lookup != NULL) {

				inet_pton(AF_INET, threadData->ip_to_lookup, &ip);

				he = gethostbyaddr((const char *)&ip, sizeof(ip), AF_INET);
				if (he == NULL) {
					printf("No host name found for ip\n");
				}

				printf("%s --> %s\n", threadData->ip_to_lookup, he->h_name);
			}
		}

		ReleaseMutex(threadData->mutex);
	}


	return;
}