/*
 * pcapd.c
 * com.apple.pcapd service implementation.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>

#include "pcapd.h"
#include "property_list_service.h"
#include "common/debug.h"

#define PCAPD_HEADER_V1_SIZE 25
#define PCAPD_HEADER_V2_SIZE 95

static uint16_t read_be16(const uint8_t *data)
{
	return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_be32(const uint8_t *data)
{
	return ((uint32_t)data[0] << 24) |
	       ((uint32_t)data[1] << 16) |
	       ((uint32_t)data[2] << 8) |
	       (uint32_t)data[3];
}

static uint32_t read_le32(const uint8_t *data)
{
	return ((uint32_t)data[3] << 24) |
	       ((uint32_t)data[2] << 16) |
	       ((uint32_t)data[1] << 8) |
	       (uint32_t)data[0];
}

static void copy_padded_string(char *dst, size_t dst_size, const uint8_t *src, size_t src_size)
{
	size_t i;

	if (!dst || dst_size == 0) {
		return;
	}

	for (i = 0; (i < src_size) && (i < (dst_size - 1)); i++) {
		if (src[i] == '\0') {
			break;
		}
		dst[i] = (char)src[i];
	}
	dst[i] = '\0';
}

/**
 * Convert a property_list_service_error_t value to a pcapd_error_t value.
 */
static pcapd_error_t pcapd_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return PCAPD_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return PCAPD_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return PCAPD_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return PCAPD_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return PCAPD_E_SSL_ERROR;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return PCAPD_E_RECEIVE_TIMEOUT;
		case PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA:
			return PCAPD_E_NOT_ENOUGH_DATA;
		default:
			break;
	}
	return PCAPD_E_UNKNOWN_ERROR;
}

static int is_pairing_error(lockdownd_error_t err)
{
	switch (err) {
		case LOCKDOWN_E_INVALID_CONF:
		case LOCKDOWN_E_PAIRING_FAILED:
		case LOCKDOWN_E_PASSWORD_PROTECTED:
		case LOCKDOWN_E_USER_DENIED_PAIRING:
		case LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING:
		case LOCKDOWN_E_MISSING_HOST_ID:
		case LOCKDOWN_E_INVALID_HOST_ID:
		case LOCKDOWN_E_MISSING_PAIR_RECORD:
		case LOCKDOWN_E_INVALID_PAIR_RECORD:
		case LOCKDOWN_E_PAIRING_PROHIBITED_OVER_THIS_CONNECTION:
			return 1;
		default:
			break;
	}
	return 0;
}

pcapd_error_t pcapd_client_new(idevice_t device, lockdownd_service_descriptor_t service, pcapd_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	pcapd_error_t err;

	if (!device || !service || (service->port == 0) || !client || *client) {
		return PCAPD_E_INVALID_ARG;
	}

	err = pcapd_error(property_list_service_client_new(device, service, &plistclient));
	if (err != PCAPD_E_SUCCESS) {
		return err;
	}

	pcapd_client_t client_loc = (pcapd_client_t)malloc(sizeof(struct pcapd_client_private));
	if (!client_loc) {
		property_list_service_client_free(plistclient);
		return PCAPD_E_UNKNOWN_ERROR;
	}

	client_loc->parent = plistclient;
	*client = client_loc;

	return PCAPD_E_SUCCESS;
}

pcapd_error_t pcapd_client_start_service(idevice_t device, pcapd_client_t *client, const char *label)
{
	lockdownd_client_t lockdown = NULL;
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_error_t lerr;
	pcapd_error_t err;

	if (!device || !client) {
		return PCAPD_E_INVALID_ARG;
	}

	*client = NULL;

	lerr = lockdownd_client_new_with_handshake(device, &lockdown, label);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		debug_info("Could not pair with device: %s", lockdownd_strerror(lerr));
		if (lockdown) {
			lockdownd_client_free(lockdown);
		}
		return is_pairing_error(lerr) ? PCAPD_E_PAIRING_FAILED : PCAPD_E_UNKNOWN_ERROR;
	}

	lerr = lockdownd_start_service(lockdown, PCAPD_SERVICE_NAME, &service);
	lockdownd_client_free(lockdown);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		debug_info("Could not start service %s: %s", PCAPD_SERVICE_NAME, lockdownd_strerror(lerr));
		return PCAPD_E_UNKNOWN_ERROR;
	}

	err = pcapd_client_new(device, service, client);
	lockdownd_service_descriptor_free(service);

	return err;
}

pcapd_error_t pcapd_client_free(pcapd_client_t client)
{
	if (!client) {
		return PCAPD_E_INVALID_ARG;
	}

	if (client->parent) {
		pcapd_error(property_list_service_client_free(client->parent));
	}
	free(client);

	return PCAPD_E_SUCCESS;
}

void pcapd_packet_free(pcapd_packet_t *packet)
{
	if (!packet) {
		return;
	}

	free(packet->data);
	free(packet);
}

pcapd_error_t pcapd_packet_parse(const uint8_t *data, uint32_t length, pcapd_packet_t **packet)
{
	pcapd_packet_t *pkt;
	uint32_t header_length;
	uint32_t packet_length;
	uint8_t header_version;

	if (!data || !packet) {
		return PCAPD_E_INVALID_ARG;
	}

	*packet = NULL;

	if (length < 9) {
		return PCAPD_E_NOT_ENOUGH_DATA;
	}

	header_length = read_be32(data);
	header_version = data[4];
	packet_length = read_be32(data + 5);

	if ((header_version < 1) || (header_version > 2)) {
		return PCAPD_E_UNSUPPORTED_VERSION;
	}

	if ((header_version == 1) && (header_length < PCAPD_HEADER_V1_SIZE)) {
		return PCAPD_E_NOT_ENOUGH_DATA;
	}
	if ((header_version == 2) && (header_length < PCAPD_HEADER_V2_SIZE)) {
		return PCAPD_E_NOT_ENOUGH_DATA;
	}

	if (header_length > length) {
		return PCAPD_E_NOT_ENOUGH_DATA;
	}
	if (packet_length > (length - header_length)) {
		return PCAPD_E_NOT_ENOUGH_DATA;
	}

	pkt = (pcapd_packet_t *)calloc(1, sizeof(pcapd_packet_t));
	if (!pkt) {
		return PCAPD_E_UNKNOWN_ERROR;
	}

	pkt->header_length = header_length;
	pkt->header_version = header_version;
	pkt->packet_length = packet_length;

	if (header_version == 2) {
		pkt->interface_type = data[9];
		pkt->unit = read_be16(data + 10);
		pkt->io = data[12];
		pkt->protocol_family = read_be32(data + 13);
		pkt->frame_pre_length = read_be32(data + 17);
		pkt->frame_post_length = read_be32(data + 21);
		copy_padded_string(pkt->interface_name, sizeof(pkt->interface_name), data + 25, 16);
		pkt->pid = read_le32(data + 41);
		copy_padded_string(pkt->comm, sizeof(pkt->comm), data + 45, 17);
		pkt->svc = read_be32(data + 62);
		pkt->epid = read_le32(data + 66);
		copy_padded_string(pkt->ecomm, sizeof(pkt->ecomm), data + 70, 17);
		pkt->seconds = read_be32(data + 87);
		pkt->microseconds = read_be32(data + 91);
	} else {
		pkt->frame_pre_length = read_be32(data + 17);
		if (header_length > PCAPD_HEADER_V1_SIZE) {
			uint32_t name_length = header_length - PCAPD_HEADER_V1_SIZE;
			if (name_length > 16) {
				name_length = 16;
			}
			copy_padded_string(pkt->interface_name, sizeof(pkt->interface_name), data + PCAPD_HEADER_V1_SIZE, name_length);
		}
	}

	if (packet_length > 0) {
		pkt->data = (uint8_t *)malloc(packet_length);
		if (!pkt->data) {
			pcapd_packet_free(pkt);
			return PCAPD_E_UNKNOWN_ERROR;
		}
		memcpy(pkt->data, data + header_length, packet_length);
		pkt->data_length = packet_length;
	}

	*packet = pkt;
	return PCAPD_E_SUCCESS;
}

pcapd_error_t pcapd_receive_packet_with_timeout(pcapd_client_t client, pcapd_packet_t **packet, unsigned int timeout)
{
	property_list_service_error_t serr;
	pcapd_error_t err;
	plist_t node = NULL;
	plist_t payload = NULL;

	if (!client || !client->parent || !packet) {
		return PCAPD_E_INVALID_ARG;
	}

	*packet = NULL;

	serr = property_list_service_receive_plist_with_timeout(client->parent, &node, timeout);
	if (serr != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		if (node) {
			plist_free(node);
		}
		return pcapd_error(serr);
	}
	if (!node) {
		return PCAPD_E_PLIST_ERROR;
	}

	payload = node;
	if (plist_get_node_type(node) == PLIST_DICT) {
		plist_t data_node = plist_dict_get_item(node, "Data");
		if (data_node) {
			payload = data_node;
		}
	}

	if (plist_get_node_type(payload) != PLIST_DATA) {
		plist_free(node);
		return PCAPD_E_PLIST_ERROR;
	}

	{
		char *raw = NULL;
		uint64_t raw_length = 0;
		plist_get_data_val(payload, &raw, &raw_length);

		if (!raw || (raw_length == 0) || (raw_length > UINT32_MAX)) {
			free(raw);
			plist_free(node);
			return PCAPD_E_NOT_ENOUGH_DATA;
		}

		err = pcapd_packet_parse((const uint8_t *)raw, (uint32_t)raw_length, packet);
		free(raw);
	}

	plist_free(node);
	return err;
}

pcapd_error_t pcapd_receive_packet(pcapd_client_t client, pcapd_packet_t **packet)
{
	return pcapd_receive_packet_with_timeout(client, packet, 30000);
}
