from AttackDetect import AttackDetect
from scapy.all import Dot11Deauth


class DeauthDetect(AttackDetect):
    def __init__(self, log_filename):
        super(DeauthDetect, self).__init__(log_filename)
        self.log_message = "Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]\n"

    def analyze(self, pkt):
        if pkt.haslayer(Dot11Deauth):
            # Look for a deauth packet and print the AP BSSID, Client BSSID and the reason for the deauth.
            pkt_content = pkt.sprintf(self.log_message)
            self.write_log(pkt_content)
            print(pkt_content)
