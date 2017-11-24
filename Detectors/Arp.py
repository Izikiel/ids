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
        for adrs in address[netifaces.AF_INET]:
            if "addr" in adrs and "netmask" in adrs:
                self.local_ip = adrs["addr"]
                break

    def analyze(self, pkt):
        if not pkt.haslayer(ARP):
            return
        source = pkt.sprintf("%ARP.psrc%")
        dest = pkt.sprintf("%ARP.pdst%")
        source_mac = pkt.sprintf("%ARP.hwsrc%")
        operation = pkt.sprintf("%ARP.op%")

        if source == self.local_ip:
            self.destinations.add(dest)
        if operation == "who-has":
            return

        if source not in self.destinations:
            self.replies_count[source_mac] += 1

            if self.replies_count[source_mac] > self.request_threshold:
                self.write_log(
                    "ARP Spoofing Detected from MAC Address {}\n".format(
                        source_mac)
                )
        else:
            self.destinations.remove(source)
