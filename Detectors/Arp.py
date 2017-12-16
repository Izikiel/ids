from AttackDetect import AttackDetect
from collections import defaultdict
from scapy.all import ARP
import netifaces


class ArpDetect(AttackDetect):
    def __init__(self, log_filename, interface):
        super(ArpDetect, self).__init__(log_filename)
        self.replies_count = defaultdict(int)
        self.destinations = set()
        self.request_threshold = 10

        address = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in address:
            return
        for adrs in address[netifaces.AF_INET]:
            if "addr" in adrs and "netmask" in adrs:
                self.local_ip = adrs["addr"]
                break

    def analyze(self, pkt):
        if ARP not in pkt:
            return

        operation = pkt.sprintf("%ARP.op%")
        if operation == "who-has":
            return
        source = pkt.sprintf("%ARP.psrc%")
        dest = pkt.sprintf("%ARP.pdst%")
        source_mac = pkt.sprintf("%ARP.hwsrc%")

        if source == self.local_ip:
            self.destinations.add(dest)

        if source not in self.destinations:
            self.replies_count[source_mac] += 1

            if self.replies_count[source_mac] > self.request_threshold:
                message = "ARP Spoofing Detected from MAC Address {}\n".format(
                    source_mac)
                print(message)
                self.write_log(message)
        else:
            self.destinations.remove(source)
