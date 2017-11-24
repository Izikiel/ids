from scapy.all import sniff
from Detectors.Arp import ArpDetect
from Detectors.Deauth import DeauthDetect
from Detectors.Krack import KrackDetect 


def analyze_packets(detectors, pkt):
    for detector in detectors:
        detector.analyze(pkt)


def main():
    log_filename = "log_ids.txt"
    detectors = [
        KrackDetect(log_filename),
        DeauthDetect(log_filename),
        ArpDetect(log_filename, "wlan1")
    ]
    sniff(prn=lambda pkt: analyze_packets(detectors, pkt))

if __name__ == '__main__':
    main()
