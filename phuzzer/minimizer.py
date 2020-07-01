import os
import shutil
import tempfile
import subprocess
from .phuzzers import Phuzzer
from .phuzzers.afl import AFL

import logging
l = logging.getLogger("phuzzer.Minimizer")

class Minimizer:
    """Testcase minimizer"""

    def __init__(self, binary_path, testcase):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        """

        self.binary_path = binary_path
        self.testcase = testcase

        AFL.check_environment()

        afl_dir, _ = AFL.init_afl_config(binary_path)
        self.tmin_path = os.path.join(afl_dir, "afl-tmin")

        # create temp
        self.work_dir = tempfile.mkdtemp(prefix='tmin-', dir='/tmp/')

        # flag for work directory removal
        self._removed = False

        self.input_testcase = os.path.join(self.work_dir, 'testcase')
        self.output_testcase = os.path.join(self.work_dir, 'minimized_result')

        l.debug("input_testcase: %s", self.input_testcase)
        l.debug("output_testcase: %s", self.output_testcase)

        # populate contents of input testcase
        with open(self.input_testcase, 'wb') as f:
            f.write(testcase)

        self.errlog = ""

    def __del__(self):
        if not self._removed:
            import traceback
            traceback.print_stack()
            shutil.rmtree(self.work_dir)

    def minimize(self):
        """Start minimizing"""

        self._start_minimizer().wait()
        if os.path.isfile(self.output_testcase):
            with open(self.output_testcase, 'rb') as f:
                result = f.read()
        else:
            print(open(self.errlog, "r").read())
            raise ValueError(f"minized version not created see error output above {self.output_testcase} ")


        shutil.rmtree(self.work_dir)
        self._removed = True

        return result

    def _start_minimizer(self, memory="8G"):

        args = [self.tmin_path]

        args += ["-i", self.input_testcase]
        args += ["-o", self.output_testcase]
        args += ["-m", memory]
        args += ["-Q"]

        args += ["--"]
        args += [self.binary_path]

        outfile = "minimizer.log"

        l.debug("execing: %s > %s", " ".join(args), outfile)

        self.errlog = os.path.join(self.work_dir, outfile)

        with open(self.errlog, "wb") as fp:
            return subprocess.Popen(args, stderr=fp)
