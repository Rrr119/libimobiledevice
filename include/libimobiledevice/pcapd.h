/**
 * @file libimobiledevice/pcapd.h
 * @brief Capture network traffic from a device.
 */

#ifndef IPCAPD_H
#define IPCAPD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** Service identifier passed to lockdownd_start_service() to start the pcapd service */
#define PCAPD_SERVICE_NAME "com.apple.pcapd"

/** Error Codes */
typedef enum {
	PCAPD_E_SUCCESS              =  0,
	PCAPD_E_INVALID_ARG          = -1,
	PCAPD_E_PLIST_ERROR          = -2,
	PCAPD_E_MUX_ERROR            = -3,
	PCAPD_E_SSL_ERROR            = -4,
	PCAPD_E_RECEIVE_TIMEOUT      = -5,
	PCAPD_E_NOT_ENOUGH_DATA      = -6,
	PCAPD_E_UNSUPPORTED_VERSION  = -7,
	PCAPD_E_PAIRING_FAILED       = -8,
	PCAPD_E_UNKNOWN_ERROR        = -256
} pcapd_error_t;

typedef struct pcapd_client_private pcapd_client_private; /**< \private */
typedef pcapd_client_private *pcapd_client_t; /**< The client handle. */

/**
 * A packet received from the pcapd service.
 *
 * The packet contains the per-packet metadata reported by the device and the
 * captured frame in #data. Fields without a value on older packet header
 * versions are set to zero.
 */
typedef struct pcapd_packet {
	uint32_t header_length;      /**< length of the pcapd packet header */
	uint8_t header_version;      /**< pcapd packet header version */
	uint32_t packet_length;      /**< length of the captured frame */
	uint8_t interface_type;      /**< IANA interface type (e.g. 6 for Ethernet) */
	uint16_t unit;               /**< interface unit number */
	uint8_t io;                  /**< packet direction */
	uint32_t protocol_family;    /**< address family of the captured frame */
	uint32_t frame_pre_length;   /**< length of link-layer data before the frame */
	uint32_t frame_post_length;  /**< length of link-layer data after the frame */
	char interface_name[17];     /**< interface name, e.g. "en0" or "pdp_ip0" */
	uint32_t pid;                /**< process ID that owns the socket */
	char comm[18];               /**< process name that owns the socket */
	uint32_t svc;                /**< service identifier reported by the device */
	uint32_t epid;               /**< effective process ID */
	char ecomm[18];              /**< effective process name */
	uint32_t seconds;            /**< capture timestamp, seconds */
	uint32_t microseconds;       /**< capture timestamp, microseconds */
	uint8_t *data;               /**< captured frame data, owned by this packet */
	uint32_t data_length;        /**< number of bytes in #data */
} pcapd_packet_t;

/**
 * Connects to the pcapd service on the specified device.
 *
 * The service descriptor must be obtained from lockdownd_start_service().
 * Starting the service requires a trusted (paired) host.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Reference that will point to a newly allocated
 *     pcapd_client_t upon successful return.
 *
 * @return PCAPD_E_SUCCESS on success,
 *     PCAPD_E_INVALID_ARG when one of the parameters is invalid,
 *     or PCAPD_E_MUX_ERROR when the connection failed.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_client_new(idevice_t device, lockdownd_service_descriptor_t service, pcapd_client_t *client);

/**
 * Starts a new pcapd service on the specified device and connects to it.
 *
 * This uses the normal lockdownd handshake and therefore pairs with the
 * device when it is not paired yet. The user may have to confirm the trust
 * dialog on the device.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     pcapd_client_t upon successful return. Must be freed using
 *     pcapd_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return PCAPD_E_SUCCESS on success,
 *     PCAPD_E_PAIRING_FAILED when the device is not paired or the trust
 *     dialog was denied, or another PCAPD_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_client_start_service(idevice_t device, pcapd_client_t *client, const char *label);

/**
 * Disconnects a pcapd client from the device and frees up the client data.
 *
 * @param client The pcapd client to disconnect and free.
 *
 * @return PCAPD_E_SUCCESS on success,
 *     PCAPD_E_INVALID_ARG when client is invalid, or a
 *     PCAPD_E_UNKNOWN_ERROR when another error occurred.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_client_free(pcapd_client_t client);

/**
 * Receives the next packet from the pcapd service.
 *
 * The caller must free the returned packet with pcapd_packet_free().
 * This function uses a 30 second timeout.
 *
 * @param client The pcapd client.
 * @param packet Pointer that will be set to the received packet.
 *
 * @return PCAPD_E_SUCCESS on success,
 *     PCAPD_E_INVALID_ARG when one of the parameters is invalid,
 *     PCAPD_E_RECEIVE_TIMEOUT when no packet arrived within the timeout,
 *     PCAPD_E_PLIST_ERROR when the reply is not a data property list,
 *     PCAPD_E_NOT_ENOUGH_DATA when the packet is truncated, or another
 *     PCAPD_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_receive_packet(pcapd_client_t client, pcapd_packet_t **packet);

/**
 * Receives the next packet from the pcapd service with the given timeout.
 *
 * The caller must free the returned packet with pcapd_packet_free().
 *
 * @param client The pcapd client.
 * @param packet Pointer that will be set to the received packet.
 * @param timeout Maximum time in milliseconds to wait for a packet.
 *
 * @return PCAPD_E_SUCCESS on success, or a PCAPD_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_receive_packet_with_timeout(pcapd_client_t client, pcapd_packet_t **packet, unsigned int timeout);

/**
 * Parses a raw pcapd packet.
 *
 * This is useful for processing packets from a device-independent transport
 * or for testing. The caller must free the returned packet with
 * pcapd_packet_free().
 *
 * @param data Raw packet data.
 * @param length Length of @p data in bytes.
 * @param packet Pointer that will be set to the parsed packet.
 *
 * @return PCAPD_E_SUCCESS on success,
 *     PCAPD_E_INVALID_ARG when one of the parameters is invalid,
 *     PCAPD_E_NOT_ENOUGH_DATA when the header or frame is truncated,
 *     PCAPD_E_UNSUPPORTED_VERSION when the header version is not supported,
 *     or another PCAPD_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API pcapd_error_t pcapd_packet_parse(const uint8_t *data, uint32_t length, pcapd_packet_t **packet);

/**
 * Frees a packet returned by pcapd_receive_packet() or pcapd_packet_parse().
 *
 * @param packet The packet to free. Passing NULL is allowed.
 */
LIBIMOBILEDEVICE_API void pcapd_packet_free(pcapd_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif
