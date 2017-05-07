#pragma once
#include "DNSThreading.h"

class ICMPResponseInfo {
public:
	ICMPResponseInfo() {
		number_of_attempts = 0;
		ip = NULL;
		host_name = "";
		time = 0;
		success = false;
	}

	int number_of_attempts;
	u_long ip;
	std::string host_name;
	float time;
	boolean success;
};