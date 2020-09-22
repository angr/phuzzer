from .afl import AFL
import logging
import os

l = logging.getLogger("phuzzer.phuzzers.afl")


class AFLPlusPlus(AFL):
    """ AFL++ port of AFL phuzzer.
        Paper found here:
        https://aflplus.plus//papers/aflpp-woot2020.pdf
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def choose_afl(self):
        self.afl_bin_dir = '/phuzzers/AFLplusplus/'
        afl_bin_path = os.path.join(self.afl_bin_dir, "afl-fuzz")
        return afl_bin_path
