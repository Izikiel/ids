from scapy.all import sniff
from Detectors.Arp import ArpDetect
from Detectors.Deauth import DeauthDetect
from Detectors.Krack import KrackDetect
from Detectors.EvilTwin import EvilTwinDetect
import sys


def analyze_packets(detectors, pkt):
    for detector in detectors:
        detector.analyze(pkt)


def main(interface):
    log_filename = "log_ids.txt"
    detectors = [
        # KrackDetect(log_filename),
        # DeauthDetect(log_filename),
        # ArpDetect(log_filename, interface),
        EvilTwinDetect(log_filename)
    ]
    sniff(prn=lambda pkt: analyze_packets(detectors, pkt))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Ingrese nombre de la interfaz a sniffear\n")
    else:
        main(sys.argv[1])
