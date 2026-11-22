/*
 * pcapd.h
 * com.apple.pcapd service header file.
 */

#ifndef __PCAPD_H
#define __PCAPD_H

#include "idevice.h"
#include "libimobiledevice/pcapd.h"
#include "property_list_service.h"

struct pcapd_client_private {
	property_list_service_client_t parent;
};

#endif
