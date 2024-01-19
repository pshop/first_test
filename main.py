from scapy.all import ARP, Ether, srp

def scan(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether_frame/arp_request
    result = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    
    clients_list = []
    for sent, received in result:
        clients_list.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients_list

def print_result(result_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in result_list:
        print(f"{client['ip']}\t\t{client['mac']}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP range (e.g., 192.168.1.1/24): ")
    scan_result = scan(target_ip)
    print_result(scan_result)