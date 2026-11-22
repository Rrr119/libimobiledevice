/*
 * idevicepcap.c
 * Capture network traffic from a device using the pcapd service.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "idevicepcap"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/pcapd.h>

#define PCAP_SNAPLEN 65535
#define PCAP_LINKTYPE_ETHERNET 1

#define PCAPNG_BT_SHB 0x0A0D0D0A
#define PCAPNG_BT_IDB 0x00000001
#define PCAPNG_BT_EPB 0x00000006

static volatile sig_atomic_t stop_requested = 0;

static void handle_sigint(int sig)
{
	(void)sig;
	stop_requested = 1;
}

static int write_le16(FILE *fp, uint16_t value)
{
	uint8_t buf[2];
	buf[0] = (uint8_t)(value & 0xFF);
	buf[1] = (uint8_t)((value >> 8) & 0xFF);
	return (fwrite(buf, 1, sizeof(buf), fp) == sizeof(buf)) ? 0 : -1;
}

static int write_le32(FILE *fp, uint32_t value)
{
	uint8_t buf[4];
	buf[0] = (uint8_t)(value & 0xFF);
	buf[1] = (uint8_t)((value >> 8) & 0xFF);
	buf[2] = (uint8_t)((value >> 16) & 0xFF);
	buf[3] = (uint8_t)((value >> 24) & 0xFF);
	return (fwrite(buf, 1, sizeof(buf), fp) == sizeof(buf)) ? 0 : -1;
}

static int write_le64(FILE *fp, uint64_t value)
{
	return (write_le32(fp, (uint32_t)(value & 0xFFFFFFFF)) == 0 &&
	        write_le32(fp, (uint32_t)(value >> 32)) == 0) ? 0 : -1;
}

static int write_pcap_header(FILE *fp)
{
	if (write_le32(fp, 0xA1B2C3D4) != 0 ||
	    write_le16(fp, 2) != 0 ||
	    write_le16(fp, 4) != 0 ||
	    write_le32(fp, 0) != 0 ||
	    write_le32(fp, 0) != 0 ||
	    write_le32(fp, PCAP_SNAPLEN) != 0 ||
	    write_le32(fp, PCAP_LINKTYPE_ETHERNET) != 0) {
		return -1;
	}
	return 0;
}

static int write_pcapng_header(FILE *fp)
{
	/* Section Header Block */
	if (write_le32(fp, PCAPNG_BT_SHB) != 0 ||
	    write_le32(fp, 28) != 0 ||
	    write_le32(fp, 0x1A2B3C4D) != 0 ||
	    write_le16(fp, 1) != 0 ||
	    write_le16(fp, 0) != 0 ||
	    write_le64(fp, UINT64_C(0xFFFFFFFFFFFFFFFF)) != 0 ||
	    write_le32(fp, 28) != 0) {
		return -1;
	}

	/* Interface Description Block */
	if (write_le32(fp, PCAPNG_BT_IDB) != 0 ||
	    write_le32(fp, 20) != 0 ||
	    write_le16(fp, PCAP_LINKTYPE_ETHERNET) != 0 ||
	    write_le16(fp, 0) != 0 ||
	    write_le32(fp, PCAP_SNAPLEN) != 0 ||
	    write_le32(fp, 20) != 0) {
		return -1;
	}

	return 0;
}

static uint32_t padded_length(uint32_t length)
{
	return (length + 3U) & ~3U;
}

static void sanitize_comment(char *dst, size_t dst_size, const char *src)
{
	size_t i;

	if (!dst || (dst_size == 0)) {
		return;
	}

	for (i = 0; (i < (dst_size - 1)) && src[i]; i++) {
		unsigned char c = (unsigned char)src[i];
		dst[i] = ((c >= 0x20) && (c < 0x7F)) ? (char)c : '?';
	}
	dst[i] = '\0';
}

static int write_pcapng_comment(FILE *fp, const pcapd_packet_t *packet)
{
	char comment[128];
	char comm[18];
	char ecomm[18];
	uint32_t comment_length;

	sanitize_comment(comm, sizeof(comm), packet->comm);
	sanitize_comment(ecomm, sizeof(ecomm), packet->ecomm);
	snprintf(comment, sizeof(comment), "PID: %u, ProcName: %s, EPID: %u, EProcName: %s, SVC: %u",
	         packet->pid, comm, packet->epid, ecomm, packet->svc);
	comment_length = (uint32_t)strlen(comment);

	if (write_le16(fp, 1) != 0 ||
	    write_le16(fp, (uint16_t)comment_length) != 0 ||
	    fwrite(comment, 1, comment_length, fp) != comment_length) {
		return -1;
	}
	if ((comment_length % 4) != 0) {
		uint8_t padding[3] = {0, 0, 0};
		uint32_t pad_len = padded_length(comment_length) - comment_length;
		if (fwrite(padding, 1, pad_len, fp) != pad_len) {
			return -1;
		}
	}

	/* End of options */
	if (write_le16(fp, 0) != 0 || write_le16(fp, 0) != 0) {
		return -1;
	}
	return 0;
}

static int write_pcapng_packet(FILE *fp, const pcapd_packet_t *packet, uint64_t timestamp_us)
{
	uint32_t packet_length = packet->data_length;
	uint32_t padded_packet_length = padded_length(packet_length);
	uint32_t comment_length;
	uint32_t block_length;
	char comment[128];
	char comm[18];
	char ecomm[18];
	uint64_t timestamp_high = (timestamp_us >> 32) & 0xFFFFFFFFU;
	uint64_t timestamp_low = timestamp_us & 0xFFFFFFFFU;

	sanitize_comment(comm, sizeof(comm), packet->comm);
	sanitize_comment(ecomm, sizeof(ecomm), packet->ecomm);
	snprintf(comment, sizeof(comment), "PID: %u, ProcName: %s, EPID: %u, EProcName: %s, SVC: %u",
	         packet->pid, comm, packet->epid, ecomm, packet->svc);
	comment_length = (uint32_t)strlen(comment);

	block_length = 8 + 20 + padded_packet_length + 4 + padded_length(comment_length) + 4 + 4;

	if (write_le32(fp, PCAPNG_BT_EPB) != 0 ||
	    write_le32(fp, block_length) != 0 ||
	    write_le32(fp, 0) != 0 ||
	    write_le32(fp, (uint32_t)timestamp_high) != 0 ||
	    write_le32(fp, (uint32_t)timestamp_low) != 0 ||
	    write_le32(fp, packet_length) != 0 ||
	    write_le32(fp, packet_length) != 0) {
		return -1;
	}

	if (packet_length > 0 && fwrite(packet->data, 1, packet_length, fp) != packet_length) {
		return -1;
	}
	if ((packet_length % 4) != 0) {
		uint8_t padding[3] = {0, 0, 0};
		uint32_t pad_len = padded_packet_length - packet_length;
		if (fwrite(padding, 1, pad_len, fp) != pad_len) {
			return -1;
		}
	}

	if (write_pcapng_comment(fp, packet) != 0) {
		return -1;
	}
	if (write_le32(fp, block_length) != 0) {
		return -1;
	}
	return 0;
}

static int write_pcap_packet(FILE *fp, const pcapd_packet_t *packet, uint64_t timestamp_us)
{
	uint32_t seconds = (uint32_t)(timestamp_us / 1000000ULL);
	uint32_t microseconds = (uint32_t)(timestamp_us % 1000000ULL);

	if (write_le32(fp, seconds) != 0 ||
	    write_le32(fp, microseconds) != 0 ||
	    write_le32(fp, packet->data_length) != 0 ||
	    write_le32(fp, packet->data_length) != 0) {
		return -1;
	}
	if (packet->data_length > 0 && fwrite(packet->data, 1, packet->data_length, fp) != packet->data_length) {
		return -1;
	}
	return 0;
}

static const uint8_t fake_ethernet_header[14] = {
	0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
	0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
	0x08, 0x00
};

static int make_export_frame(const pcapd_packet_t *packet, uint8_t **frame, uint32_t *frame_length)
{
	uint32_t skip = 0;
	uint32_t payload_length = packet->data_length;
	int add_ethernet_header = 0;
	uint8_t *out;

	if (packet->frame_pre_length == 0) {
		add_ethernet_header = 1;
	} else if ((strncmp(packet->interface_name, "pdp_ip", 6) == 0) &&
	           (packet->frame_pre_length == 4) &&
	           (packet->data_length >= 4)) {
		add_ethernet_header = 1;
		skip = 4;
		payload_length -= 4;
	}

	out = (uint8_t *)malloc(payload_length + (add_ethernet_header ? sizeof(fake_ethernet_header) : 0));
	if (!out) {
		return -1;
	}

	if (add_ethernet_header) {
		memcpy(out, fake_ethernet_header, sizeof(fake_ethernet_header));
	}
	if (payload_length > 0) {
		memcpy(out + (add_ethernet_header ? sizeof(fake_ethernet_header) : 0),
		       packet->data + skip, payload_length);
	}

	*frame = out;
	*frame_length = payload_length + (add_ethernet_header ? (uint32_t)sizeof(fake_ethernet_header) : 0);
	return 0;
}

static int interface_matches(const pcapd_packet_t *packet, const char *interface)
{
	char full_interface[32];

	if (!interface || !*interface) {
		return 1;
	}

	snprintf(full_interface, sizeof(full_interface), "%s%u", packet->interface_name, packet->unit);
	return (strcmp(interface, full_interface) == 0) || (strcmp(interface, packet->interface_name) == 0);
}

static int process_matches(const pcapd_packet_t *packet, const char *process)
{
	char pid_string[32];
	char epid_string[32];
	int is_pid = 1;
	const char *p;

	if (!process || !*process) {
		return 1;
	}

	for (p = process; *p; p++) {
		if (*p < '0' || *p > '9') {
			is_pid = 0;
			break;
		}
	}

	if (is_pid) {
		snprintf(pid_string, sizeof(pid_string), "%u", packet->pid);
		snprintf(epid_string, sizeof(epid_string), "%u", packet->epid);
		return (strcmp(process, pid_string) == 0) || (strcmp(process, epid_string) == 0);
	}

	return (strcmp(process, packet->comm) == 0) || (strcmp(process, packet->ecomm) == 0);
}

static int packet_matches_filter(const pcapd_packet_t *packet, const char *process, const char *interface)
{
	return process_matches(packet, process) && interface_matches(packet, interface);
}

static uint64_t packet_timestamp_us(const pcapd_packet_t *packet)
{
	if (packet->seconds != 0) {
		return ((uint64_t)packet->seconds * 1000000ULL) + packet->microseconds;
	}
	return (uint64_t)time(NULL) * 1000000ULL;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS]\n", (name ? name + 1 : argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Capture network traffic from a connected device using the pcapd service.\n"
		"The device must be paired with this host; use --pair to validate the pairing\n"
		"before starting the capture.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID          target specific device by UDID\n"
		"  -n, --network            connect to network device\n"
		"  -o, --output FILE        output file (default: capture.pcapng, use '-' for stdout)\n"
		"  -f, --format FORMAT      output format: pcapng (default) or pcap\n"
		"  -c, --count N            stop after N captured packets (default: unlimited)\n"
		"  -p, --process NAME|PID   only capture packets for this process\n"
		"  -i, --interface NAME     only capture packets on this interface (e.g. en0 or en)\n"
		"  -P, --pair               validate or create the host pairing before capture\n"
		"  -q, --quiet              do not print a packet summary on stderr\n"
		"  -d, --debug              enable communication debugging\n"
		"  -h, --help               prints usage information\n"
		"  -v, --version            prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

static void print_pairing_error(lockdownd_error_t err)
{
	switch (err) {
		case LOCKDOWN_E_PASSWORD_PROTECTED:
			fprintf(stderr, "ERROR: Unlock the device and enter the passcode, then retry.\n");
			break;
		case LOCKDOWN_E_INVALID_CONF:
		case LOCKDOWN_E_INVALID_HOST_ID:
		case LOCKDOWN_E_MISSING_PAIR_RECORD:
			fprintf(stderr, "ERROR: The device is not paired with this host. Accept the trust dialog and retry.\n");
			break;
		case LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING:
			fprintf(stderr, "ERROR: Accept the trust dialog on the device, then retry.\n");
			break;
		case LOCKDOWN_E_USER_DENIED_PAIRING:
			fprintf(stderr, "ERROR: The user denied the trust dialog on the device.\n");
			break;
		case LOCKDOWN_E_PAIRING_FAILED:
			fprintf(stderr, "ERROR: Pairing with the device failed.\n");
			break;
		default:
			fprintf(stderr, "ERROR: Pairing failed with lockdown error %d (%s).\n", err, lockdownd_strerror(err));
			break;
	}
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	pcapd_client_t pcapd = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = LOCKDOWN_E_UNKNOWN_ERROR;
	idevice_error_t idev_err = IDEVICE_E_UNKNOWN_ERROR;
	pcapd_error_t pcapd_err = PCAPD_E_UNKNOWN_ERROR;
	const char *udid = NULL;
	const char *output_path = "capture.pcapng";
	const char *process_filter = NULL;
	const char *interface_filter = NULL;
	int use_network = 0;
	int use_pcapng = 1;
	int validate_pairing = 0;
	int quiet = 0;
	unsigned long packet_count = 0;
	unsigned long captured = 0;
	FILE *out = NULL;
	int close_output = 0;
	int result = EXIT_FAILURE;
	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "output", required_argument, NULL, 'o' },
		{ "format", required_argument, NULL, 'f' },
		{ "count", required_argument, NULL, 'c' },
		{ "process", required_argument, NULL, 'p' },
		{ "interface", required_argument, NULL, 'i' },
		{ "pair", no_argument, NULL, 'P' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "dhnu:o:f:c:p:i:Pqv", longopts, NULL)) != -1) {
		switch (c) {
			case 'd':
				idevice_set_debug_level(1);
				break;
			case 'u':
				if (!*optarg) {
					fprintf(stderr, "ERROR: UDID must not be empty!\n");
					return 2;
				}
				udid = optarg;
				break;
			case 'n':
				use_network = 1;
				break;
			case 'o':
				if (!*optarg) {
					fprintf(stderr, "ERROR: output path must not be empty!\n");
					return 2;
				}
				output_path = optarg;
				break;
			case 'f':
				if (strcmp(optarg, "pcapng") == 0) {
					use_pcapng = 1;
				} else if (strcmp(optarg, "pcap") == 0) {
					use_pcapng = 0;
				} else {
					fprintf(stderr, "ERROR: Unsupported format '%s' (use pcap or pcapng)\n", optarg);
					return 2;
				}
				break;
			case 'c': {
				char *endptr = NULL;
				errno = 0;
				packet_count = strtoul(optarg, &endptr, 0);
				if (errno != 0 || !endptr || *endptr != '\0' || endptr == optarg) {
					fprintf(stderr, "ERROR: Invalid packet count '%s'\n", optarg);
					return 2;
				}
				break;
			}
			case 'p':
				process_filter = optarg;
				break;
			case 'i':
				interface_filter = optarg;
				break;
			case 'P':
				validate_pairing = 1;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'h':
				print_usage(argc, argv, 0);
				return 0;
			case 'v':
				printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
				return 0;
			default:
				print_usage(argc, argv, 1);
				return 2;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "ERROR: Unexpected argument '%s'\n", argv[optind]);
		print_usage(argc, argv, 1);
		return 2;
	}

	idev_err = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (idev_err != IDEVICE_E_SUCCESS) {
		fprintf(stderr, "ERROR: %s\n", udid ? "Device not found" : "No device found");
		goto cleanup;
	}

	if (validate_pairing) {
		lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME);
		if (lerr != LOCKDOWN_E_SUCCESS) {
			print_pairing_error(lerr);
			goto cleanup;
		}
		lockdownd_client_free(lockdown);
		lockdown = NULL;
		fprintf(stderr, "Device pairing validated.\n");
	}

	pcapd_err = pcapd_client_start_service(device, &pcapd, TOOL_NAME);
	if (pcapd_err != PCAPD_E_SUCCESS) {
		if (pcapd_err == PCAPD_E_PAIRING_FAILED) {
			fprintf(stderr, "ERROR: The device is not paired with this host. Accept the trust dialog on the device and retry (or use --pair).\n");
		} else {
			fprintf(stderr, "ERROR: Could not start pcapd service (error %d). Make sure the device is paired and unlocked.\n", pcapd_err);
		}
		goto cleanup;
	}

	if (strcmp(output_path, "-") == 0) {
		out = stdout;
	} else {
		out = fopen(output_path, "wb");
		if (!out) {
			fprintf(stderr, "ERROR: Could not open '%s' for writing: %s\n", output_path, strerror(errno));
			goto cleanup;
		}
		close_output = 1;
	}

	if ((use_pcapng ? write_pcapng_header(out) : write_pcap_header(out)) != 0) {
		fprintf(stderr, "ERROR: Could not write capture header.\n");
		goto cleanup;
	}
	fflush(out);

#ifndef _WIN32
	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
#endif

	while (!stop_requested && ((packet_count == 0) || (captured < packet_count))) {
		pcapd_packet_t *packet = NULL;
		uint64_t timestamp_us;
		uint8_t *frame = NULL;
		uint32_t frame_length = 0;

		pcapd_err = pcapd_receive_packet_with_timeout(pcapd, &packet, 1000);
		if (pcapd_err == PCAPD_E_RECEIVE_TIMEOUT) {
			continue;
		}
		if (pcapd_err != PCAPD_E_SUCCESS) {
			fprintf(stderr, "ERROR: Could not receive pcapd packet (error %d).\n", pcapd_err);
			goto cleanup;
		}

		if (!packet_matches_filter(packet, process_filter, interface_filter)) {
			pcapd_packet_free(packet);
			continue;
		}

		if (make_export_frame(packet, &frame, &frame_length) != 0) {
			fprintf(stderr, "ERROR: Could not allocate packet buffer.\n");
			pcapd_packet_free(packet);
			goto cleanup;
		}

		{
			pcapd_packet_t export_packet = *packet;
			export_packet.data = frame;
			export_packet.data_length = frame_length;
			timestamp_us = packet_timestamp_us(packet);

			if ((use_pcapng ? write_pcapng_packet(out, &export_packet, timestamp_us)
			                : write_pcap_packet(out, &export_packet, timestamp_us)) != 0) {
				fprintf(stderr, "ERROR: Could not write captured packet.\n");
				free(frame);
				pcapd_packet_free(packet);
				goto cleanup;
			}
		}

		if (!quiet) {
			fprintf(stderr, "%s%u %s pid=%u epid=%u length=%u\n",
			        packet->interface_name, packet->unit, packet->comm,
			        packet->pid, packet->epid, frame_length);
		}

		free(frame);
		pcapd_packet_free(packet);
		captured++;
	}

	if (close_output) {
		fclose(out);
		out = NULL;
		close_output = 0;
	}

	fprintf(stderr, "Captured %lu packet%s to %s\n", captured, (captured == 1) ? "" : "s", output_path);
	result = EXIT_SUCCESS;

cleanup:
	if (out && close_output) {
		fclose(out);
	}
	if (pcapd) {
		pcapd_client_free(pcapd);
	}
	if (lockdown) {
		lockdownd_client_free(lockdown);
	}
	if (device) {
		idevice_free(device);
	}
	return result;
}
