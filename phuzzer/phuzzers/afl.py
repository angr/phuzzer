import contextlib
import glob
import logging
import os
import shutil
import signal
import subprocess

from collections import defaultdict
from ..errors import InstallError
from ..util import hexescape
from . import Phuzzer

l = logging.getLogger("phuzzer.phuzzers.afl")


class AFL(Phuzzer):
    """ Phuzzer object, spins up a fuzzing job on a binary """

    def __init__(
            self, target, seeds=None, dictionary=None, create_dictionary=None,
            work_dir=None, seeds_dir=None, resume=False,
            afl_count=1, memory="8G", timeout=None,
            library_path=None, target_opts=None, extra_opts=None,
            crash_mode=False, use_qemu=True,
            run_timeout=None
    ):
        """
        :param target: path to the binary to fuzz. List or tuple for multi-CB.
        :param seeds: list of inputs to seed fuzzing with
        :param dictionary: a list of bytes objects to seed the dictionary with
        :param create_dictionary: create a dictionary from the string references in the binary

        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param resume: resume the prior run, if possible

        :param memory: AFL child process memory limit (default: "8G")
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param timeout: timeout for individual runs within AFL

        :param library_path: library path to use, if none is specified a default is chosen
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up

        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a
        crashing input :param use_qemu: Utilize QEMU for instrumentation of binary.

        :param run_timeout: amount of time for AFL to wait for a single execution to finish

        """
        super().__init__(target=target, seeds=seeds, dictionary=dictionary, create_dictionary=create_dictionary,
                         timeout=timeout)

        self.work_dir = work_dir or os.path.join("/tmp", "phuzzer", os.path.basename(str(target)))
        if resume and os.path.isdir(self.work_dir):
            self.in_dir = "-"
        else:
            l.info("could resume, but starting over upon request")
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(self.work_dir)
            self.in_dir = seeds_dir or os.path.join(self.work_dir, "initial_seeds")
            with contextlib.suppress(FileExistsError):
                os.makedirs(self.in_dir)

        self.afl_count = afl_count
        self.memory = memory

        self.library_path = library_path
        self.target_opts = target_opts or []
        self.extra_opts = extra_opts if type(extra_opts) is list else extra_opts.split() if type(
            extra_opts) is str else []

        self.crash_mode = crash_mode
        self.use_qemu = use_qemu

        self.run_timeout = run_timeout

        # sanity check crash mode
        if self.crash_mode:
            if seeds is None:
                raise ValueError("Seeds must be specified if using the fuzzer in crash mode")
            l.info("AFL will be started in crash mode")

        # set up the paths
        self.afl_phuzzer_bin_path = self.choose_afl()

    #
    # Overrides
    #

    def create_dictionary(self):
        d = super().create_dictionary()

        # AFL has a limit of 128 bytes per dictionary entries
        valid_strings = []
        for s in d:
            if len(s) <= 128:
                valid_strings.append(s)
            for s_atom in s.split():
                if len(s_atom) <= 128:
                    valid_strings.append(s_atom)
                else:
                    valid_strings.append(s[:128])

        return valid_strings

    #
    # AFL functionality
    #

    @property
    def dictionary_file(self):
        return os.path.join(self.work_dir, "dict.txt")

    def start(self):
        """
        start fuzzing
        """

        super().start()

        # check for the existence of the AFL Directory
        if self.afl_bin_dir is None or not os.path.isdir(self.afl_bin_dir):
            l.error("AFL Bin Directory does not exist at: %s.", self.afl_bin_dir)

        # create the directory
        with contextlib.suppress(FileExistsError):
            os.makedirs(self.work_dir)

        # write the dictionary
        if self.dictionary:
            with open(self.dictionary_file, "w") as df:
                for i, s in enumerate(set(self.dictionary)):
                    if len(s) == 0:
                        continue
                    s_val = hexescape(s)
                    df.write("string_%d=\"%s\"" % (i, s_val) + "\n")

        # write the seeds
        if self.in_dir != "-":
            if not self.seeds:
                l.warning("No seeds provided - using 'fuzz'")
            template = os.path.join(self.in_dir, "seed-%d")
            for i, seed in enumerate(self.seeds or [b"fuzz"]):
                with open(template % i, "wb") as f:
                    f.write(seed)

        # spin up the master AFL instance
        master = self._start_afl_instance()  # the master fuzzer
        self.processes.append(master)

        # only spins up an AFL instances if afl_count > 1
        for i in range(1, self.afl_count):
            self.processes.append(self._start_afl_instance(i))

        return self

    @property
    def alive(self):
        if not len(self.stats):
            return False

        alive_cnt = 0
        for fuzzer in self.stats:
            try:
                os.kill(int(self.stats[fuzzer]['fuzzer_pid']), 0)
                alive_cnt += 1
            except (OSError, KeyError):
                pass

        return bool(alive_cnt)

    @property
    def summary_stats(self):
        stats = self.stats
        summary_stats = defaultdict(lambda: 0)
        for _, fuzzstats in stats.items():
            for fstat, value in fuzzstats.items():
                try:
                    fvalue = float(value)
                    if fstat == "paths_total":
                        summary_stats[fstat] = max(summary_stats[fstat], int(fvalue))
                    else:
                        summary_stats[fstat] += fvalue
                except ValueError:
                    pass
        return summary_stats

    @property
    def stats(self):

        # collect stats into dictionary
        stats = {}
        if os.path.isdir(self.work_dir):
            for fuzzer_dir in os.listdir(self.work_dir):
                stat_path = os.path.join(self.work_dir, fuzzer_dir, "fuzzer_stats")
                if os.path.isfile(stat_path):
                    stats[fuzzer_dir] = {}

                    with open(stat_path, "r") as f:
                        stat_blob = f.read()
                        stat_lines = stat_blob.split("\n")[:-1]
                        for stat in stat_lines:
                            if ":" in stat:
                                try:

                                    key, val = stat.split(":")
                                except:
                                    index = stat.find(":")
                                    key = stat[:index]
                                    val = stat[index + 1:]

                            else:
                                print(f"Skipping stat '${stat}' in \n${stat_lines} because no split value")
                                continue
                            stats[fuzzer_dir][key.strip()] = val.strip()

        return stats

    #
    # Helpers
    #

    def _get_crashing_inputs(self, signals):
        """
        Retrieve the crashes discovered by AFL. Only return those crashes which
        recieved a signal within 'signals' as the kill signal.

        :param signals: list of valid kill signal numbers
        :return: a list of strings which are crashing inputs
        """

        crashes = set()
        for fuzzer in os.listdir(self.work_dir):
            crashes_dir = glob.iglob(f"{self.work_dir}/fuzzer-*/crashes*")
            for crash_dir in crashes_dir:
                if not os.path.isdir(crash_dir):
                    # if this entry doesn't have a crashes directory, just skip it
                    continue

                for crash in os.listdir(crash_dir):
                    if crash == "README.txt":
                        # skip the readme entry
                        continue

                    attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), crash.split(","))))

                    if int(attrs['sig']) not in signals:
                        continue

                    crash_path = os.path.join(crash_dir, crash)
                    with open(crash_path, 'rb') as f:
                        crashes.add(f.read())

        return list(crashes)

    #
    # AFL-specific
    #

    def bitmap(self, fuzzer='fuzzer-master'):
        """
        retrieve the bitmap for the fuzzer `fuzzer`.
        :return: a string containing the contents of the bitmap.
        """

        if not fuzzer in os.listdir(self.work_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.work_dir, fuzzer, "fuzz_bitmap")

        bdata = None
        try:
            with open(bitmap_path, "rb") as f:
                bdata = f.read()
        except IOError:
            pass

        return bdata

    #
    # Interface
    #

    @staticmethod
    def _check_environment():
        err = ""
        # check for afl sensitive settings
        with open("/proc/sys/kernel/core_pattern") as f:
            if not "core" in f.read():
                err += "echo core | sudo tee /proc/sys/kernel/core_pattern\n"

        # This file is based on a driver not all systems use
        # http://unix.stackexchange.com/questions/153693/cant-use-userspace-cpufreq-governor-and-set-cpu-frequency
        # TODO: Perform similar performance check for other default drivers.
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
                if not "performance" in f.read():
                    err += "echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\n"

        # TODO: test, to be sure it doesn't mess things up
        if os.path.exists("/proc/sys/kernel/sched_child_runs_first"):
            with open("/proc/sys/kernel/sched_child_runs_first") as f:
                if not "1" in f.read():
                    err += "echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first\n"

        if err:
            raise InstallError(err)

    def add_core(self):
        """
        add one fuzzer
        """

        self.processes.append(self._start_afl_instance())

    def remove_core(self):
        """
        remove one fuzzer
        """

        try:
            f = self.processes.pop()
        except IndexError:
            l.error("no fuzzer to remove")
            raise ValueError("no fuzzer to remove")

        f.kill()

    def crashes(self, signals=(signal.SIGSEGV, signal.SIGILL)):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.

        :param signals: list of valid kill signal numbers to override the default (SIGSEGV and SIGILL)
        :return: a list of strings which are crashing inputs
        """

        return self._get_crashing_inputs(signals)

    def queue(self, fuzzer='fuzzer-master'):
        """
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        """

        if not fuzzer in os.listdir(self.work_dir):
            raise ValueError(f"fuzzer '{fuzzer}' does not exist")

        queue_path = os.path.join(self.work_dir, fuzzer, 'queue')
        queue_files = list(filter(lambda x: x != ".state", os.listdir(queue_path)))

        queue_l = []
        for q in queue_files:
            with open(os.path.join(queue_path, q), 'rb') as f:
                queue_l.append(f.read())

        return queue_l

    def pollenate(self, *testcases):
        """
        pollenate a fuzzing job with new testcases

        :param testcases: list of bytes objects representing new inputs to introduce
        """

        nectary_queue_directory = os.path.join(self.work_dir, 'pollen', 'queue')
        if not 'pollen' in os.listdir(self.work_dir):
            os.makedirs(nectary_queue_directory)

        pollen_cnt = len(os.listdir(nectary_queue_directory))

        for tcase in testcases:
            with open(os.path.join(nectary_queue_directory, "id:%06d,src:pollenation" % pollen_cnt), "wb") as f:
                f.write(tcase)

            pollen_cnt += 1

    #
    # AFL launchers
    #
    def build_args(self):
        args = [self.afl_phuzzer_bin_path]

        args += ["-i", self.in_dir]
        args += ["-o", self.work_dir]
        args += ["-m", self.memory]

        if self.use_qemu:
            args += ["-Q"]

        if self.crash_mode:
            args += ["-C"]

        if len(self.processes) == 0:
            fuzzer_id = "fuzzer-master"
            args += ["-M", fuzzer_id]
        else:
            fuzzer_id = f"fuzzer-{len(self.processes)}"
            args += ["-S", fuzzer_id]

        if os.path.exists(self.dictionary_file):
            args += ["-x", self.dictionary_file]

        args += self.extra_opts

        if self.run_timeout is not None:
            args += ["-t", "%d+" % self.run_timeout]
        args += ["--"]
        args += [self.target]
        target_opts = []

        for op in self.target_opts:
            target_opts.append(op.replace("~~", "--").replace("~", "-"))

        args += target_opts

        return args, fuzzer_id

    def _start_afl_instance(self, instance_cnt=0):

        args, fuzzer_id = self.build_args()

        my_env = os.environ.copy()

        self.log_command(args, fuzzer_id, my_env)

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")
        l.debug("execing: %s > %s", ' '.join(args), logpath)

        with open(logpath, "w") as fp:
            return subprocess.Popen(args, stdout=fp, stderr=fp, close_fds=True, env=my_env)

    def log_command(self, args, fuzzer_id, my_env):
        with open(os.path.join(self.work_dir, fuzzer_id + ".cmd"), "w") as cf:
            cf.write(" ".join(args) + "\n")
            listvars = [f"{k}={v}" for k, v in my_env.items()]
            listvars.sort()
            cf.write("\n" + "\n".join(listvars))

    def choose_afl(self):
        """
        Chooses the right AFL and sets up some environment.
        """

        afl_dir, qemu_arch_name = Phuzzer.init_afl_config(self.target)

        directory = None
        if qemu_arch_name == "aarch64":
            directory = "arm64"
        if qemu_arch_name == "i386":
            directory = "i386"
        if qemu_arch_name == "x86_64":
            directory = "x86_64"
        if qemu_arch_name == "mips":
            directory = "mips"
        if qemu_arch_name == "mipsel":
            directory = "mipsel"
        if qemu_arch_name == "ppc":
            directory = "powerpc"
        if qemu_arch_name == "arm":
            # some stuff qira uses to determine the which libs to use for arm
            with open(self.target, "rb") as f:
                progdata = f.read(0x800)
            if b"/lib/ld-linux.so.3" in progdata:
                directory = "armel"
            elif b"/lib/ld-linux-armhf.so.3" in progdata:
                directory = "armhf"

        if directory is None and qemu_arch_name != "":
            l.warning("architecture \"%s\" has no installed libraries", qemu_arch_name)
        elif directory is not None:
            libpath = os.path.join(afl_dir, "..", "fuzzer-libs", directory)

            l.debug(f"exporting QEMU_LD_PREFIX of '{libpath}'")
            os.environ['QEMU_LD_PREFIX'] = libpath

        # return the AFL path
        # import ipdb
        # ipdb.set_trace()
        afl_bin = os.path.join(afl_dir, "afl-fuzz")
        l.debug(f"afl_bin={afl_bin}")
        return afl_bin
