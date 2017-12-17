from AttackDetect import AttackDetect
from scapy.all import *


class EvilTwinDetect(AttackDetect):
    def __init__(self, log_filename):
        super(EvilTwinDetect, self).__init__(log_filename)
        self.ssids = {}
        self.message_template = "Detected duplicate ssid.\tSSID:{ssid} BSSID1:{bssid1} BSSID2:{bssid2}\n"

    def analyze(self, pkt):
        if Dot11 not in pkt:
            return
        if Dot11Beacon in pkt or Dot11ProbeResp in pkt:
            ssid = pkt[Dot11Elt].info
            bssid = pkt[Dot11].addr3

            if ssid not in self.ssids:
                self.ssids[ssid] = set([bssid])
            elif bssid not in self.ssids[ssid]:
                message = self.message_template.format(**{
                    "ssid": ssid,
                    "bssid1": next(iter(self.ssids[ssid])),
                    "bssid2": bssid
                })
                print(message)
                self.write_log(message)
                self.ssids[ssid].add(bssid)
