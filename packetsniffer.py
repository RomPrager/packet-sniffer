import scapy.all as scapy
import psutil

def get_ethernet_interfaces():
    stats = psutil.net_if_stats()
    ethernet_ifaces = []

    for name, st in stats.items():
        lname = name.lower()


        if "loopback" in lname:
            continue

        if not st.isup:
            continue

        if "ethernet" in lname or 'eno' in lname or 'eth' in lname or 'wi-fi' in lname:
            ethernet_ifaces.append(name)

    return ethernet_ifaces


def choose_interface():
    interfaces = get_ethernet_interfaces()
    print('Avaliable Ethernet interfaces: \n')

    for idx, iface in enumerate(interfaces):
        print(f"  [{idx}] {iface}")

    while True:
        if len(interfaces) == 1:
            return interfaces
        
        choice = input('Enter the number of the interface you want to sniff\n')
    
        if not choice.isdigit():
            print('enter a valid number \n')
            continue

        eth = int(choice)
        if eth < 0 or eth >= len(interfaces):
            print(f'choose number between 0 and {len(interfaces)}')
            continue

        selected_iface = interfaces[eth]
        print(f'you chose: {selected_iface}')
        return selected_iface


def print_packet(pkt):
    print(pkt.summary())

def filter_packet():
    pass
    
def sniffing():
    scapy.sniff(
        iface=choose_interface(),
        #filter=,
        prn=print_packet,
        store=False
    )
    
sniffing()