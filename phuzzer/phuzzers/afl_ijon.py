import logging
import os

from .afl import AFL

l = logging.getLogger(__name__)


class AFLIJON(AFL):
    """ IJON port of AFL phuzzer.
        Paper found here:
        https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def choose_afl(self):
        self.afl_bin_dir = '/phuzzers/ijon/'
        afl_bin_path = os.path.join(self.afl_bin_dir, "afl-fuzz")
        return afl_bin_path
