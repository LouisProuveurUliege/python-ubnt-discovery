# python-ubnt-discovery
Command line python script to discover Ubiquiti devices on the local LAN segment.

## Run the script

**Requirements :** the script uses the python scapy library to craft and send the raw packet. You can install it with:

```bash
pip install scapy
```

The script must run as root to be able to use the scapy library.

**Alternatively**: To avoid issues with root permissions and system-level package management, the script can run within a docker container. You can build and run the image with

```bash
docker build -t ubnt-discovery .
docker run -it --rm --network host ubnt-discovery:latest
```

The `--network host` flag allows the container to run using the network namespace of the host. It is usually not recommended to do so, but here we need the container to be on the same broadcast domain as the host. 

**Note**: due to WSL running in its own subnetwork, the docker method might not work on Windows.

## Authorship

This script and all work in this folder were originally done by nitefood and published on [github](https://github.com/nitefood/python-ubnt-discovery).

I also took the work of jrjparks into account, also available on [github](https://jrjparks.github.io/unofficial-unifi-guide/protocols/discovery.html).

I merely took jrjpark's observations and my own into account and modified nitefood's script accordingly.

The remainder of this `README` file is a copy of the `README` file available on the original repository.

## Ubiquiti Discovery Protocol brief description

*Disclaimer: this code is based exclusively on packet sniffing and analysis, there are some fields that remain unknown to me.
This code may therefore not be compatible with all devices.
I have not tested this on Unifi APs or EdgeOS products.*

Ubiquiti discovery works by sending an UDP packet to the local broadcast address (255.255.255.255) on port **10001**,
containing 4 bytes in the payload, namely `01 00 00 00`, and waiting for UDP replies destined to the local
broadcast address.

The payload of the reply packet sent by the radio is structured as follows:
- offset `00` (3 bytes) : *Ubiquiti discovery reply signature (*`0x01 0x00 0x00`*). We'll check this to make sure it's a valid discovery-reply packet.*
- offset `03` (1 byte) : *Payload size (excluding signature)*

Starting at offset `04`, the structure of the payload is as follows:
- `Field Type`        (1 byte) : *see the UBNT_ constants in the code for the ones I saw and could figure out*
- `Field data length` (2 bytes) : *contains the length of this field's data*
- `Field data`        (*n* bytes) : *contains the actual field data (eg. radio name, firmware version, etc)*

This sequence is repeated for every field in the reply packet.

In case the radio has multiple IPs configured, we'll get several type *02* fields (MAC Address + IP Address).

The other field types appear only once in the packets I have observed.
