#! /usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    boardcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boardcast = boardcast / arp_request
    answered_list = scapy.srp(arp_request_boardcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(results_list):
    print('------------------------------------------------------------------------------------------')
    print(
        'IP\t\t\t\t\tMAC '
        'Address\n------------------------------------------------------------------------------------------')
    for client in results_list:
        print(client['ip'] + '\t\t\t' + client['mac'])


scan_result = scan('10.0.2.1/24')
print_result(scan_result)
