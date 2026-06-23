from scapy.all import get_if_list, get_if_addr

interfaces = get_if_list()

print("All interfaces and their IPs:\n")
for i, iface in enumerate(interfaces):
    try:
        ip = get_if_addr(iface)
        print(f"{i} | {ip} | {iface}")
    except:
        print(f"{i} | No IP | {iface}")