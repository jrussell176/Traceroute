#pragma once
#include "DNSThreading.h"

class ICMPResponseInfo {
public:
	ICMPResponseInfo() {
		number_of_attempts = 0;
		ip = NULL;
		host_name = NULL;
		time = 0;
		success = false;
	}

	int number_of_attempts;
	u_long ip;
	char *host_name;
	float time;
	boolean success;
};