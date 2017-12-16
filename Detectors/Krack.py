from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from AttackDetect import AttackDetect
import time


WPA_KEY_INFO_INSTALL = 1 << 6
WPA_KEY_INFO_ACK = 1 << 7
WPA_KEY_INFO_MIC = 1 << 8


class NonceInfo(object):
    """docstring for NonceInfo"""

    def __init__(self, nonce, seq, time):
        super(NonceInfo, self).__init__()
        self.nonce = nonce
        self.seq = seq
        self.time = time

    def is_reused(self, nonce, seq, p):
        return all([self.nonce == nonce,
                    self.seq != seq,
                    p.time >= self.time + 1]
                   )


class NonceCollection(object):
    """docstring for NonceCollection"""

    def __init__(self):
        super(NonceCollection, self).__init__()
        self.nonces = dict()

    def add_nonce(self, nonce, seq, p):
        self.nonces[nonce] = NonceInfo(nonce, seq, p.time)

    def is_nonce_reused(self, nonce, seq, p):
        return nonce in self.nonces and \
            self.nonces[nonce].is_reused(nonce, seq, p)


def str2hex(string):
    """Convert a string to it's hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


class KrackDetect(AttackDetect):
    """docstring for KrackDetect"""

    def __init__(self, log_filename):
        super(KrackDetect, self).__init__(log_filename)
        self.nonce_collection = NonceCollection()
        self.msg_template = "Detected nonce reuse against {dst} from {src}! {nonce}, {seq}\n"
        self.start = int(time.time())

    def analyze(self, pkt):
        if WPA_key not in pkt:
            return

        if Ether not in pkt:
            return

        dst_mac = pkt[Ether].dst
        src_mac = pkt[Ether].src

        key_info = pkt[WPA_key].key_info
        if Dot11 in pkt:
            seq = pkt[Dot11].SC >> 4
        else:
            # Esto esta porque los paquetes que emite
            # el script de ataque no tienen capa Dot11
            seq = int(time.time()) - self.start
        nonce = pkt[WPA_key].nonce

        if all([key_info & WPA_KEY_INFO_MIC,
                key_info & WPA_KEY_INFO_ACK == 0,
                key_info & WPA_KEY_INFO_INSTALL == 0]):
            # Skip frame 4
            return

        # Get frame 3
        if all([key_info & WPA_KEY_INFO_MIC,
                key_info & WPA_KEY_INFO_ACK,
                key_info & WPA_KEY_INFO_INSTALL]):

            if self.nonce_collection.is_nonce_reused(nonce, seq, pkt):
                msg = self.msg_template.format(**{"nonce": str2hex(nonce),
                                                  "seq": seq,
                                                  "dst": dst_mac,
                                                  "src": src_mac})
                print(msg)
                self.write_log(msg)

            self.nonce_collection.add_nonce(nonce, seq, pkt)


if __name__ == '__main__':
    k = KrackDetect("log_krack.txt")
    sniff(prn=lambda p: k.analyze(p))
