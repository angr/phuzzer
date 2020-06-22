from . import Phuzzer
from .afl import AFL
import logging
import os

l = logging.getLogger("phuzzer.phuzzers.afl")


class AFLMultiCB(AFL):
    '''This is a multi-CB AFL phuzzer (for CGC).'''

    def __init__(self, targets, **kwargs):
        self.targets = targets
        super().__init__(targets[0], **kwargs)

        self.timeout = 1000 * len(targets)
        self.target_opts = targets[1:]

    def choose_afl(self):
        self.afl_bin_dir, _ = Phuzzer.init_afl_config(self.targets[0], is_multicb=True)
        afl_bin_path = os.path.join(self.afl_bin_dir, "afl-fuzz")
        return afl_bin_path
