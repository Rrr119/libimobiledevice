# pcapd tests

`make check` runs the offline `pcapd_test` binary. It exercises the pcapd
header parser with synthetic v1 and v2 packets, including fixtures for the
interface and process metadata seen on iPhone, iPad, and iPod traffic.

Hardware validation requires three paired and unlocked devices (one iPhone,
one iPad, and one iPod touch). Run:

```sh
tests/device_matrix.sh UDID_IPHONE UDID_IPAD UDID_IPOD
```

The script validates each model, creates a pairing if necessary, captures three
packets with `idevicepcap`, and checks the resulting PCAPNG file. Set
`IDEVICEPCAP`, `IDEVICEINFO`, and `IDEVICEPAIR` when the tools are not in
`PATH`.
