# This script was originally created by nitefood
# and available on this GitHub repository:
# https://github.com/nitefood/python-ubnt-discovery


from scapy.all import *
import time

# UBNT field types
UBNT_MAC         = '01'     # Hardware Address
UBNT_MAC_AND_IP  = '02'     # Hardware Address + IPv4
UBNT_FIRMWARE    = '03'     # String
UBNT_USERNAME    = '06'     # String
UBNT_SALT        = '07'     # [u8]
UBNT_CHALLENGE   = '08'     # [u8]
UBNT_UPTIME      = '0a'     # i64
UBNT_HOSTNAME    = '0b'     # String
UBNT_PLATFORM    = '0c'     # String
UBNT_ESSID       = '0d'     # String
UBNT_WMODE       = '0e'     # i32
UBNT_SEQUENCE    = '12'     # i32       Incrementing Number
UBNT_SERIAL      = '13'     # String    Usually the MAC
UBNT_MODEL_FULL  = '14'     # Unknown
UBNT_MODEL       = '15'     # String
UBNT_MIN_CV      = '16'     # Minimum Controller Version
UBNT_ISDEFAULT   = '17'     # Bool
UBNT_VERSION     = '1b'     # String
UBNT_UUID        = '20'     # String
# Other field types will be stored raw

# UBNT discovery packet payload (Legacy from original code)
UBNT_REQUEST_PAYLOAD = '01000000'

# Reply signature
UBNT_REPLY_SIGNATURE = '010000'

# Some devices send packets without being asked
UBNT_BROADCAST = '02'

# When Factory-reset, sends packet every 10 seconds
DISCOVERY_TIMEOUT = 10


def formatMAC(mac):
    
    """Formats a raw bytearray into a MAC address\n
    xx:xx:xx:xx:xx:xx

    Returns:
        string: the MAC address computed from the byte array
    """    
    
    mac_str = ""
    for mac_byte in mac:
        mac_str += hex(mac_byte)[2:] + ":"
        
    mac_str = mac_str[:len(mac_str)-1]
    
    return mac_str

def encodeField(Device, type, data):
    
    """Encodes the field's **data** according to the fields **type**
    and stores it within the **Device** data structure      

    Returns:
        dict: a dictionnary containing key-value pairs, with field types as keys
    """    
    
    if type == UBNT_MAC:
        Device['mac'] = formatMAC(data)
    
    elif type == UBNT_MAC_AND_IP:
        mac = data[:6]
        IP = data[6:]  
            
        IP_str = ""
        for IP_byte in IP:
            IP_str += str(IP_byte) + "."
        
        IP_str = IP_str[:len(IP_str)-1]
        
        data = {
            "mac": formatMAC(mac),
            "IP": IP_str
        }
        
        if 'ifs' in Device:
            Device['ifs'].append(data)
        else:
            Device['ifs'] = [data]
    
    elif type == UBNT_FIRMWARE:
        Device['firmware'] = data.decode()
        
    elif type == UBNT_USERNAME:
        Device['user'] = data.decode()
    
    elif type == UBNT_SALT:
        Device['salt'] = data.hex()
        
    elif type == UBNT_CHALLENGE:
        Device['challenge'] = data.hex()
        
    elif type == UBNT_UPTIME:
        Device['uptime'] = int(data.hex(), 16)
        
    elif type == UBNT_HOSTNAME:
        Device['hostname'] = data.decode()
    
    elif type == UBNT_PLATFORM:
        Device['platform'] = data.decode()
        
    elif type == UBNT_ESSID:
        Device['essid'] = data.decode()
        
    elif type == UBNT_WMODE:
        Device['wmode'] = int(data.hex(), 16)
        
    elif type == UBNT_SEQUENCE:
        Device['sequence'] = int(data.hex(), 16)
        
    elif type == UBNT_SERIAL:
        Device['serial'] = data.hex()
        
    elif type == UBNT_MODEL_FULL:
        Device['model_full'] = data
        
    elif type == UBNT_MODEL:
        Device['model'] = data.decode()
        
    elif type == UBNT_MIN_CV:
        Device['min_controller_version'] = data.decode()
    
    elif type == UBNT_ISDEFAULT:
        Device['default'] = bool(int(data.hex(), 16))
        
    elif type == UBNT_VERSION:
        Device['version'] = data.decode()
        
    elif type == UBNT_UUID:
        Device['uuid'] = data.decode()
        
    else:
        Device['unknow_fields'].append({
            'type': type,
            'raw_data': data
        })
        
    return Device


def ubntDiscovery():

    # Prepare and send our discovery packet
    conf.checkIPaddr = False # we're broadcasting our discovery packet from a local IP (local->255.255.255.255)
                             # but we'll expect a reply on the broadcast IP as well (radioIP->255.255.255.255),
                             # not on our local IP.
                             # Therefore we must disable destination IP checking in scapy
                             
    SRC_PORT=34053
    DST_PORT=10001                             
                             
    ubnt_broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/\
                            IP(dst="255.255.255.255")/\
                            UDP(sport=SRC_PORT,dport=DST_PORT)/\
                            Raw(bytes.fromhex(UBNT_REQUEST_PAYLOAD))
    
    ubnt_multicast_packet = Ether(dst="01:00:5e:59:bc:01")/\
                            IP(dst="233.89.188.1")    /\
                            UDP(sport=SRC_PORT,dport=DST_PORT)/\
                            Raw(bytes.fromhex(UBNT_REQUEST_PAYLOAD))
    
    # determine our own MAC address to avoid capturing own packets
    local_mac = get_if_hwaddr(conf.iface)


    bpf_filter = (
        f"udp and ("
        f"dst port {SRC_PORT} "
        f"or dst port {DST_PORT}"
        f") and not ether src {local_mac}"
    )

    # listen for packets matching the filter
    sniffer = AsyncSniffer(filter=bpf_filter, timeout=DISCOVERY_TIMEOUT)
    sniffer.start()
    
    # brief sleep to ensure sniffer thread is fully initialized before sending;
    time.sleep(0.05)

    # transmit packets
    sendp(ubnt_broadcast_packet, verbose=0)
    sendp(ubnt_multicast_packet, verbose=0)

    # wait for timeout of sniffer to elapse
    sniffer.join()
    packets = sniffer.results


    # Loop over received packets
    DeviceList = []
    
    for pkt in packets:

        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            continue
        
        payload = pkt[Raw].load

        # Check for a valid UBNT discovery broadcast (first byte should be 0x02)
        if payload[0:1].hex() == UBNT_BROADCAST:
            pointer = 2
            
        elif payload[0:3].hex() == UBNT_REPLY_SIGNATURE:
            pointer = 4
            
        else:
            print("Invalid Packet")
            continue            # Not a valid UBNT discovery reply, skip to next received packet
        
        # At this point, this is an expected packet. 
        Device = {}                     # Init the device
        Device['unknow_fields'] = []    # Initialize 'unknow fields'
        
        pointer = 2
        
        # Get total payload length in bytes
        length = int(payload[pointer:pointer+2].hex(), 16)

        pointer += 2
        remaining_bytes = length


        while remaining_bytes > 0:
            fieldType = payload[pointer:pointer+1].hex()
            pointer += 1
            remaining_bytes -= 1
            fieldLen = payload[pointer:pointer+2].hex() # Data length is stored as a 16-bit word
            fieldLen = int( fieldLen, 16 )
            pointer += 2
            remaining_bytes -= 2
            fieldData = payload[pointer:pointer+fieldLen]
            
            # Encode the field and add it to the device
            Device = encodeField(Device, fieldType, fieldData)
            
            pointer += fieldLen
            remaining_bytes -= fieldLen

        DeviceList.append(Device)

    return DeviceList


print("\nDiscovery in progress...")
DeviceList = ubntDiscovery()
found_radios = len(DeviceList)
if found_radios:
    print("\nDiscovered " + str(found_radios) + " device(s):")
    for Device in DeviceList:
        print(Device)
else:
    print("\nNo radios discovered\n")
