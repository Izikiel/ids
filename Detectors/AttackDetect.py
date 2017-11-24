
class AttackDetect(object):
    def __init__(self, log_filename):
        self.log_filename = log_filename

    def analyze(self, pkt):
        raise NotImplementedError

    def write_log(self, message):
        with open(self.log_filename, "a") as log:
            log.write(message)
