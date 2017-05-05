#pragma once
#include "NetworkStructs.h"

class ICMPResponseInfo {
public:
	int number_of_attempts;
	char *ip;
	char *host_name;
	float time;
	boolean success;
};