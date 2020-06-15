#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="Targer IP / IP range.")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for i in answered:
        clients_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def result(result_list):
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for i in result_list:
        print(i["ip"] + "\t\t" + i["mac"])


options = get_argument()
scan_result = scan(options.ip)
result(scan_result)
