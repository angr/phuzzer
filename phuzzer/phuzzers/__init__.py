import distutils.spawn #pylint:disable=no-name-in-module,import-error
import subprocess
import logging
import signal
import time
import sys
import os
import re
l = logging.getLogger("phuzzer.phuzzers")


class Phuzzer:
    """ Phuzzer object, spins up a fuzzing job on a binary """

    AFL_MULTICB = "AFLMULTICB"
    WITCHER_AFL = "WITCHERAFL"
    AFL = "AFL"
    qemu_arch_name = ""
    afl_bin_dir = None

    def __init__(self, target, seeds=None, dictionary=None, create_dictionary=False, timeout=None):
        """
        :param target: the target (i.e., path to the binary to fuzz, or a docker target)
        :param seeds: list of inputs to seed fuzzing with
        :param dictionary: a list of bytes objects to seed the dictionary with
        :param create_dictionary: create a dictionary from the string references in the binary
        :param timeout: duration to run fuzzing session
        """

        self.target = target
        self.target_os = ""
        self.target_qemu_arch = ""
        self.seeds = seeds or [ ]

        # processes spun up
        self.processes            = [ ]

        self.start_time = None
        self.end_time = None
        self.timeout = timeout

        self.check_environment()

        # token dictionary
        self.dictionary = dictionary or (self.create_dictionary() if create_dictionary else [])

    @staticmethod
    def phactory(*args, **kwargs):
        if len(args) < 1 and 'phuzzer_type' not in kwargs:
            raise TypeError("The phactory() requires 'type' argument")
        if len(args) > 1:
            raise TypeError("The phactory() allows only 1 positional argument")

        if len(args) == 1:
            classtype = args[0]
        else:
            classtype = kwargs.get('phuzzer_type')
            del kwargs['phuzzer_type']
        classtype = classtype.upper()

        if classtype == Phuzzer.AFL:
            from .afl import AFL
            return AFL(**kwargs)
        elif classtype == Phuzzer.AFL_MULTICB:
            from .afl_multicb import AFLMultiCB
            return AFLMultiCB(**kwargs)
        elif classtype == Phuzzer.WITCHER_AFL:
            from .witcherafl import WitcherAFL
            return WitcherAFL(**kwargs)
        else:
            raise ValueError(f"Fuzzer type {classtype} is not found.")

    #
    # Some convenience functionality.
    #

    def found_crash(self):
        return len(self.crashes()) > 0

    def add_cores(self, n):
        for _ in range(n):
            self.add_core()

    def remove_cores(self, n):
        """
        remove multiple fuzzers
        """
        for _ in range(n):
            self.remove_core()

    def timed_out(self):
        if self.timeout is None:
            return False

        return time.time() - self.start_time > self.timeout

    def start(self):
        self.start_time = int(time.time())
        return self
    __enter__ = start

    def stop(self):
        self.end_time = int(time.time())
        if self.start_time is not None:
            l.info("Phuzzer %s shut down after %d seconds.", self, self.end_time - self.start_time)
        for p in self.processes:
            p.terminate()
            p.wait()
    __exit__ = stop

    @staticmethod
    def init_afl_config(binary_path, is_multicb=False):
        """
        Returns AFL_PATH and AFL_DIR, if AFL_PATH is set in os.environ it returns that, if not it attempts to auto-detect
        :param binary_path:
        :return: afl_path_var, afl_dir, qemu_arch_name: afl_path_var is location of qemu_trace to use, afl_dir is the location of the afl binaries, qemu_arch_name is the name of the binary's architecture
        """

        if Phuzzer.afl_bin_dir is not None:
            return Phuzzer.afl_bin_dir, Phuzzer.qemu_arch_name

        if "AFL_PATH" in os.environ:
            Phuzzer.afl_bin_dir = os.environ["AFL_PATH"]
        else:

            try:
                import angr
            except ImportError:
                raise ModuleNotFoundError("AFL_PATH was found in enviornment variables and angr is not installed.")
            try:
                import shellphish_afl
            except ImportError:
                raise ModuleNotFoundError(
                    "AFL_PATH was found in enviornment variables and either shellphish_afl is not installed.")
            try:
                p = angr.Project(binary_path)
                Phuzzer.qemu_arch_name = p.arch.qemu_name
                tracer_id = 'cgc' if p.loader.main_object.os == 'cgc' else p.arch.qemu_name
                if is_multicb:
                    tracer_id = 'multi-{}'.format(tracer_id)

                afl_path_var = shellphish_afl.afl_path_var(tracer_id)
                os.environ['AFL_PATH'] = afl_path_var

                Phuzzer.afl_bin_dir = shellphish_afl.afl_dir(tracer_id)
                print(f"afl_dir {Phuzzer.afl_bin_dir}")

            except Exception as ex:
                import traceback
                traceback.format_exc()
                raise ModuleNotFoundError("AFL_PATH was found in enviornment variables and "
                                          "either angr or shellphish_afl is not installed.")

        return Phuzzer.afl_bin_dir, Phuzzer.qemu_arch_name

    @classmethod
    def check_environment(cls):
        try:
            cls._check_environment()
        except InstallError as e:
            tmp = ""
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "####### THE FUZZER WILL NOT RUN. AND IT IS ***YOUR FAULT***!!!!!!!!!!!!  ######\n"
            tmp += "####### DIRECTLY BELOW THIS, THERE ARE CONCRETE REASONS FOR WHY THIS IS  ######\n"
            tmp += "####### IF YOU COMPLAIN TO US ON GITHUB ABOUT THIS NOT WORKING, AND YOU  ######\n"
            tmp += "####### DON'T RESOLVE THESE ISSUES FIRST, WE WILL NOT HELP YOU!!!!!!!!!  ######\n"
            tmp += "####### PLEASE RESOLVE THE ISSUES BELOW.    THEY LITERALLY TELL YOU WHAT ######\n"
            tmp += "####### YOU HAVE TO EXECUTE. DO NOT ASK FOR HELP IF YOU ARE SEEING THIS  ######\n"
            tmp += "####### MESSAGE; JUST FIX THE PROBLEM WITH YOUR SYSTEM!!!!!!!!!!!!!!!!!  ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += e.args[0]
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "####### FIX THE ABOVE ISSUES BEFORE ASKING FOR HELP. THE TEXT LITERALLY  ######\n"
            tmp += "####### TELLS YOU HOW TO DO IT. DO NOT ASK FOR HELP ABOUT THIS BEFORE    ######\n"
            tmp += "####### FIXING THE ABOVE ISSUES. IF YOU ARE SEEING THIS MESSAGE, YOUR    ######\n"
            tmp += "####### SYSTEM MISCONFIGURATION IS *******YOUR FAULT*********!!!!!!!!!!! ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                GET YOUR SYSTEM SETUP FIXED!!!!!!!!!!             ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            e.args = (tmp,)
            xmsg = distutils.spawn.find_executable("xmessage") #pylint:disable=no-member
            if xmsg:
                subprocess.Popen([xmsg, tmp]).wait()
            l.critical(tmp)
            print(tmp)
            sys.stderr.write(tmp)
            sys.stdout.write(tmp)
            raise


    #
    # Dictionary creation
    #
    def create_dictionary(self):
        try:
            import angr
            return self.create_dictionary_angr()
        except ImportError:
            try:
                import elftools
                return self.create_dictionary_elftools()
            except ImportError:
                raise ModuleNotFoundError("Cannot create a dictionary without angr or elftools being installed")

    def create_dictionary_elftools(self):
        from elftools.elf.elffile import ELFFile
        MAX = 120
        strings = set()
        with open(self.target, 'rb') as f:
            elf = ELFFile(f)

            for sec in elf.iter_sections():
                if sec.name not in {'.rodata'}:
                    continue
                for match in re.findall(b"[a-zA-Z0-9_]{4}[a-zA-Z0-9_]*", sec.data()):
                    t = match.decode()
                    for i in range(0, len(t), MAX):
                        strings.add(t[i:i + MAX])
        return strings

    def create_dictionary_angr(self):

        l.warning("creating a dictionary of string references within target \"%s\"", self.target)
        import angr

        b = angr.Project(self.target, load_options={'auto_load_libs': False})
        cfg = b.analyses.CFG(resolve_indirect_jumps=True, collect_data_references=True)
        state = b.factory.blank_state()

        string_references = []
        for v in cfg._memory_data.values():
            if v.sort == "string" and v.size > 1:
                st = state.solver.eval(state.memory.load(v.address, v.size), cast_to=bytes)
                string_references.append((v.address, st))

        strings = [] if len(string_references) == 0 else list(list(zip(*string_references))[1])
        return strings


    #
    # Subclasses should override this.
    #

    @staticmethod
    def _check_environment():
        raise NotImplementedError()

    def crashes(self, signals=(signal.SIGSEGV, signal.SIGILL)):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.

        :param signals: list of valid kill signal numbers to override the default (SIGSEGV and SIGILL)
        :return: a list of strings which are crashing inputs
        """
        raise NotImplementedError()

    def queue(self, fuzzer='fuzzer-master'):
        """
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        """
        raise NotImplementedError()

    def pollenate(self, *testcases):
        """
        pollenate a fuzzing job with new testcases

        :param testcases: list of bytes objects representing new inputs to introduce
        """
        raise NotImplementedError()

    def add_core(self):
        raise NotImplementedError()

    def remove_core(self):
        raise NotImplementedError()

    def __del__(self):
        self.stop()

from ..errors import InstallError
