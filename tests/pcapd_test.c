#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libimobiledevice/pcapd.h>

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
		return 1; \
	} \
} while (0)

static void put_be16(uint8_t *data, uint16_t value)
{
	data[0] = (uint8_t)(value >> 8);
	data[1] = (uint8_t)value;
}

static void put_be32(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)(value >> 24);
	data[1] = (uint8_t)(value >> 16);
	data[2] = (uint8_t)(value >> 8);
	data[3] = (uint8_t)value;
}

static void put_le32(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
	data[2] = (uint8_t)(value >> 16);
	data[3] = (uint8_t)(value >> 24);
}

static uint8_t *make_v2_packet(uint32_t header_length, const char *interface_name,
                               uint16_t unit, uint8_t interface_type, uint32_t frame_pre_length,
                               const char *comm, const char *ecomm, uint32_t pid, uint32_t epid,
                               uint32_t seconds, uint32_t microseconds,
                               const uint8_t *payload, uint32_t payload_length)
{
	uint8_t *raw = (uint8_t *)malloc(header_length + payload_length);
	size_t name_length;
	size_t comm_length;
	size_t ecomm_length;

	if (!raw) {
		return NULL;
	}

	memset(raw, 0xDD, header_length + payload_length);
	put_be32(raw, header_length);
	raw[4] = 2;
	put_be32(raw + 5, payload_length);
	raw[9] = interface_type;
	put_be16(raw + 10, unit);
	raw[12] = 0;
	put_be32(raw + 13, 2);
	put_be32(raw + 17, frame_pre_length);
	put_be32(raw + 21, 0);

	name_length = strlen(interface_name);
	if (name_length > 16) {
		name_length = 16;
	}
	memcpy(raw + 25, interface_name, name_length);
	if (name_length < 16) {
		raw[25 + name_length] = '\0';
	}
	put_le32(raw + 41, pid);

	comm_length = strlen(comm);
	if (comm_length > 17) {
		comm_length = 17;
	}
	memcpy(raw + 45, comm, comm_length);
	if (comm_length < 17) {
		raw[45 + comm_length] = '\0';
	}
	put_be32(raw + 62, 7);
	put_le32(raw + 66, epid);

	ecomm_length = strlen(ecomm);
	if (ecomm_length > 17) {
		ecomm_length = 17;
	}
	memcpy(raw + 70, ecomm, ecomm_length);
	if (ecomm_length < 17) {
		raw[70 + ecomm_length] = '\0';
	}
	put_be32(raw + 87, seconds);
	put_be32(raw + 91, microseconds);

	if (payload_length > 0) {
		memcpy(raw + header_length, payload, payload_length);
	}
	return raw;
}

static uint8_t *make_v1_packet(uint32_t offset_to_ip_data, const uint8_t *payload, uint32_t payload_length)
{
	uint8_t *raw = (uint8_t *)malloc(25 + payload_length);

	if (!raw) {
		return NULL;
	}

	memset(raw, 0, 25 + payload_length);
	put_be32(raw, 25);
	raw[4] = 1;
	put_be32(raw + 5, payload_length);
	put_be32(raw + 17, offset_to_ip_data);
	if (payload_length > 0) {
		memcpy(raw + 25, payload, payload_length);
	}
	return raw;
}

static int test_iphone_packet(void)
{
	const uint8_t payload[] = {0x45, 0x00, 0x00, 0x3C, 0x12, 0x34};
	uint8_t *raw = make_v2_packet(95, "en0", 0, 6, 14, "nsurlsessiond", "MyApp",
	                              1234, 5678, 1700000000, 123456, payload, sizeof(payload));
	pcapd_packet_t *packet = NULL;
	pcapd_error_t err;

	CHECK(raw != NULL);
	err = pcapd_packet_parse(raw, 95 + sizeof(payload), &packet);
	CHECK(err == PCAPD_E_SUCCESS);
	CHECK(packet->header_version == 2);
	CHECK(packet->interface_type == 6);
	CHECK(packet->frame_pre_length == 14);
	CHECK(strcmp(packet->interface_name, "en0") == 0);
	CHECK(packet->pid == 1234);
	CHECK(packet->epid == 5678);
	CHECK(strcmp(packet->comm, "nsurlsessiond") == 0);
	CHECK(strcmp(packet->ecomm, "MyApp") == 0);
	CHECK(packet->seconds == 1700000000);
	CHECK(packet->microseconds == 123456);
	CHECK(packet->data_length == sizeof(payload));
	CHECK(memcmp(packet->data, payload, sizeof(payload)) == 0);
	pcapd_packet_free(packet);
	free(raw);
	return 0;
}

static int test_ipad_packet(void)
{
	const uint8_t payload[] = {0x08, 0x00, 0x45, 0x00, 0x00, 0x20};
	uint8_t *raw = make_v2_packet(128, "en2", 2, 6, 14, "mDNSResponder", "mDNSResponder",
	                              4321, 4321, 1700000001, 654321, payload, sizeof(payload));
	pcapd_packet_t *packet = NULL;
	pcapd_error_t err;

	CHECK(raw != NULL);
	err = pcapd_packet_parse(raw, 128 + sizeof(payload), &packet);
	CHECK(err == PCAPD_E_SUCCESS);
	CHECK(packet->header_length == 128);
	CHECK(packet->unit == 2);
	CHECK(strcmp(packet->interface_name, "en2") == 0);
	CHECK(packet->svc == 7);
	CHECK(packet->data_length == sizeof(payload));
	CHECK(memcmp(packet->data, payload, sizeof(payload)) == 0);
	pcapd_packet_free(packet);
	free(raw);
	return 0;
}

static int test_ipod_packet(void)
{
	const uint8_t payload[] = {0x45, 0x00, 0x00, 0x14};
	uint8_t *raw = make_v2_packet(95, "pdp_ip", 0, 71, 4, "CommCenter", "Mail",
	                              100, 200, 1700000002, 111111, payload, sizeof(payload));
	pcapd_packet_t *packet = NULL;
	pcapd_error_t err;

	CHECK(raw != NULL);
	err = pcapd_packet_parse(raw, 95 + sizeof(payload), &packet);
	CHECK(err == PCAPD_E_SUCCESS);
	CHECK(packet->interface_type == 71);
	CHECK(packet->frame_pre_length == 4);
	CHECK(strcmp(packet->interface_name, "pdp_ip") == 0);
	CHECK(packet->data_length == sizeof(payload));
	CHECK(memcmp(packet->data, payload, sizeof(payload)) == 0);
	pcapd_packet_free(packet);
	free(raw);
	return 0;
}

static int test_v1_packet(void)
{
	const uint8_t payload[] = {0x45, 0x00, 0x00, 0x18};
	uint8_t *raw = make_v1_packet(0, payload, sizeof(payload));
	pcapd_packet_t *packet = NULL;
	pcapd_error_t err;

	CHECK(raw != NULL);
	err = pcapd_packet_parse(raw, 25 + sizeof(payload), &packet);
	CHECK(err == PCAPD_E_SUCCESS);
	CHECK(packet->header_version == 1);
	CHECK(packet->header_length == 25);
	CHECK(packet->frame_pre_length == 0);
	CHECK(packet->data_length == sizeof(payload));
	CHECK(memcmp(packet->data, payload, sizeof(payload)) == 0);
	pcapd_packet_free(packet);
	free(raw);
	return 0;
}

static int test_truncated_packet(void)
{
	const uint8_t payload[] = {0x45, 0x00, 0x00, 0x10};
	uint8_t *raw = make_v2_packet(95, "en0", 0, 6, 14, "test", "test",
	                              1, 1, 1, 1, payload, sizeof(payload));
	pcapd_packet_t *packet = NULL;
	pcapd_error_t err;

	CHECK(raw != NULL);
	err = pcapd_packet_parse(raw, 94, &packet);
	CHECK(err == PCAPD_E_NOT_ENOUGH_DATA);
	CHECK(packet == NULL);
	err = pcapd_packet_parse(raw, 95 + sizeof(payload) - 1, &packet);
	CHECK(err == PCAPD_E_NOT_ENOUGH_DATA);
	CHECK(packet == NULL);
	free(raw);
	return 0;
}

static int test_invalid_arguments(void)
{
	pcapd_packet_t *packet = NULL;

	CHECK(pcapd_packet_parse(NULL, 1, &packet) == PCAPD_E_INVALID_ARG);
	CHECK(packet == NULL);
	CHECK(pcapd_packet_parse((const uint8_t *)"x", 1, NULL) == PCAPD_E_INVALID_ARG);
	pcapd_packet_free(NULL);
	return 0;
}

int main(void)
{
	if (test_iphone_packet() != 0 ||
	    test_ipad_packet() != 0 ||
	    test_ipod_packet() != 0 ||
	    test_v1_packet() != 0 ||
	    test_truncated_packet() != 0 ||
	    test_invalid_arguments() != 0) {
		return 1;
	}

	printf("pcapd parser tests passed (iPhone/iPad/iPod fixtures)\n");
	return 0;
}
