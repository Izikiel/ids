from AttackDetect import AttackDetect
from scapy.all import Dot11, Dot11WEP, struct


def dot11_get_seqnum(p):
    return p[Dot11].SC >> 4


def dot11_get_iv(p):
    """Scapy can't handle Extended IVs, so do this properly ourselves (only works for CCMP)"""
    if Dot11WEP not in p:
        return 0

    wep = p[Dot11WEP]
    if wep.keyid & 32:
        # FIXME: Only CCMP is supported (TKIP uses a different IV structure)
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
    else:
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)


class IvInfo():
    def __init__(self, p):
        self.iv = dot11_get_iv(p)
        self.seq = dot11_get_seqnum(p)
        self.time = p.time

    def is_reused(self, p):
        """Return true if frame p reuses an IV and if p is not a retransmitted frame"""
        iv = dot11_get_iv(p)
        seq = dot11_get_seqnum(p)
        return self.iv == iv and self.seq != seq and p.time >= self.time + 1


class IvCollection():
    def __init__(self):
        self.ivs = dict()  # maps IV values to IvInfo objects

    def reset(self):
        self.ivs = dict()

    def track_used_iv(self, p):
        iv = dot11_get_iv(p)
        self.ivs[iv] = IvInfo(p)

    def is_iv_reused(self, p):
        """Returns True if this is an *observed* IV reuse and not just a retransmission"""
        iv = dot11_get_iv(p)
        if iv == 0:
            return False
        return iv in self.ivs and self.ivs[iv].is_reused(p)

    def is_new_iv(self, p):
        """Returns True if the IV in this frame is higher than all previously observed ones"""
        iv = dot11_get_iv(p)
        if self.ivs:
            return True
        return iv > max(self.ivs.keys())


class KrackDetect(AttackDetect):
    def __init__(self, log_filename):
        super(KrackDetect, self).__init__(log_filename)
        self.ivs = IvCollection()

    def analyze(self, pkt):
        if Dot11 not in pkt:
            return
        if self.ivs.is_iv_reused(pkt):
            iv = dot11_get_iv(pkt)
            seq = dot11_get_seqnum(pkt)
            message = "IV reuse detected (IV={iv}, seq={seq}).\n Src={src}\tDst={dst}".format({
                "iv": iv,
                "seq": seq,
                "src": pkt.psrc,
                "dst": pkt.pdst
            })
            self.write_log(message)
        else:
            self.ivs.track_used_iv(pkt)
