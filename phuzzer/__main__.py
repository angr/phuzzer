#!/usr/bin/env python
from .reporter import Reporter
from .phuzzers import Phuzzer
import pkg_resources
import logging.config
import importlib
import argparse
import tarfile
import shutil
import socket
import time
import imp
import os

try:
    import driller
    DRILLER_EXISTS = True
except ImportError:
    DRILLER_EXISTS=False

from . import GreaseCallback


def main():
    parser = argparse.ArgumentParser(description="Shellphish fuzzer interface")
    parser.add_argument('binary', help="the path to the target binary to fuzz")
    parser.add_argument('-g', '--grease-with', help="A directory of inputs to grease the fuzzer with when it gets stuck.")
    parser.add_argument('-d', '--driller_workers', help="When the fuzzer gets stuck, drill with N workers.", type=int)
    parser.add_argument('-f', '--force_interval', help="Force greaser/fuzzer assistance at a regular interval (in seconds).", type=float)
    parser.add_argument('-w', '--work-dir', help="The work directory for AFL.", default="/dev/shm/work/")

    parser.add_argument('-l', '--login-data', help="The json file from which to get the login information", default="")
    parser.add_argument('-c', '--afl-cores', help="Number of AFL workers to spin up.", default=1, type=int)
    parser.add_argument('-C', '--first-crash', help="Stop on the first crash.", action='store_true', default=False)
    parser.add_argument('-Q', '--use-qemu', help="Use qemu to trace binary.", action='store_true', default=False)
    parser.add_argument('-t', '--timeout', help="Timeout (in seconds).", type=float, default=None)
    parser.add_argument('-i', '--ipython', help="Drop into ipython after starting the fuzzer.", action='store_true')
    parser.add_argument('-T', '--tarball', help="Tarball the resulting AFL workdir for further analysis to this file -- '{}' is replaced with the hostname.")
    parser.add_argument('-m', '--helper-module',
                        help="A module that includes some helper scripts for seed selection and such.")
    parser.add_argument('-D', '--dictionary', default=None,
                        help="Load the dictionary from a file, with each on a single line  ")
    parser.add_argument('--memory', help="Memory limit to pass to AFL (MB, or use k, M, G, T suffixes)", default="8G")
    parser.add_argument('--no-dictionary', help="Do not create a dictionary before fuzzing.", action='store_true', default=False)
    parser.add_argument('--logcfg', help="The logging configuration file.", default=".shellphuzz.ini")
    parser.add_argument('-s', '--seed-dir', action="append", help="Directory of files to seed fuzzer with")
    parser.add_argument('--run-timeout', help="Number of milliseconds permitted for each run of binary", type=int, default=None)
    parser.add_argument('--driller-timeout', help="Number of seconds to allow driller to run", type=int, default=10*60)
    parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
    parser.add_argument('--target-opts', help="Options to pass to target.", default=None, nargs='+')
    parser.add_argument('-r', '--resume', help="Resume prior run if possible and do not destroy work directory.",
                        action='store_true', default=False)
    parser.add_argument('--reportdir', help="The directory to use for the reports.", default=".")
    parser.add_argument('-p','--phuzzer-type', '--fuzzer-type', help="Which phuzzer are you using: AFL, AFL_IJON, AFL++, Witcher, AFL_MULTICB.", default=Phuzzer.AFL)
    args = parser.parse_args()

    if os.path.isfile(os.path.join(os.getcwd(), args.logcfg)):
        logging.config.fileConfig(os.path.join(os.getcwd(), args.logcfg))

    try: os.mkdir("/dev/shm/work/")
    except OSError: pass

    if args.helper_module:
        try:
            helper_module = importlib.import_module(args.helper_module)
        except (ImportError, TypeError):
            helper_module = imp.load_source('fuzzing_helper', args.helper_module)
    else:
        helper_module = None

    drill_extension = None
    grease_extension = None

    if args.grease_with:
        print ("[*] Greasing...")
        grease_extension = GreaseCallback(
            args.grease_with,
            grease_filter=helper_module.grease_filter if helper_module is not None else None,
            grease_sorter=helper_module.grease_sorter if helper_module is not None else None
        )

    if args.driller_workers and DRILLER_EXISTS:
        print ("[*] Drilling...")
        drill_extension = driller.LocalCallback(num_workers=args.driller_workers, worker_timeout=args.driller_timeout, length_extension=args.length_extension)

    stuck_callback = (
        (lambda f: (grease_extension(f), drill_extension(f))) if drill_extension and grease_extension
        else drill_extension or grease_extension
    )

    seeds = None
    if args.seed_dir:
        seeds = []
        print ("[*] Seeding...")
        for dirpath in args.seed_dir:
            for filename in os.listdir(dirpath):
                filepath = os.path.join(dirpath, filename)
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'rb') as seedfile:
                    seeds.append(seedfile.read())

    if args.dictionary:
        built_dict = open(args.dictionary,"rb").read().split(b"\n")
    else:
        built_dict = None

    print ("[*] Creating fuzzer...")
    fuzzer = Phuzzer.phactory(phuzzer_type=args.phuzzer_type,
                              target=args.binary, work_dir=args.work_dir, seeds=seeds, afl_count=args.afl_cores,
                              create_dictionary=not args.no_dictionary, timeout=args.timeout,
                              memory=args.memory, run_timeout=args.run_timeout, dictionary=built_dict, use_qemu=args.use_qemu,
                              resume=args.resume, target_opts=args.target_opts
                              )

    # start it!
    print ("[*] Starting fuzzer...")
    fuzzer.start()
    start_time = time.time()

    reporter = Reporter(args.binary, args.reportdir, args.afl_cores, args.first_crash, args.timeout, fuzzer.work_dir )

    reporter.start()

    if args.ipython:
        print ("[!]")
        print ("[!] Launching ipython shell. Relevant variables:")
        print ("[!]")
        print ("[!] fuzzer")
        if args.driller_workers and DRILLER_EXISTS:
            print ("[!] driller_extension")
        if args.grease_with:
            print ("[!] grease_extension")
        print ("[!]")
        import IPython; IPython.embed()

    try:
        loopcnt = 0
        #print ("[*] Waiting for fuzzer completion (timeout: %s, first_crash: %s)." % (args.timeout, args.first_crash))
        crash_seen = False
        reporter.enable_printing()

        while True:

            if not crash_seen and fuzzer.found_crash():
                # print ("\n[*] Crash found!")
                crash_seen = True
                reporter.set_crash_seen()
                if args.first_crash:
                    break
            if fuzzer.timed_out():
                reporter.set_timeout_seen()
                print("\n[*] Timeout reached.")
                break

            time.sleep(1)
            loopcnt += 1

    except KeyboardInterrupt:
        end_reason = "Keyboard Interrupt"
        print ("\n[*] Aborting wait. Ctrl-C again for KeyboardInterrupt.")
    except Exception as e:
        end_reason = "Exception occurred"
        print ("\n[*] Unknown exception received (%s). Terminating fuzzer." % e)
        fuzzer.stop()
        if drill_extension:
            drill_extension.kill()
        raise

    print ("[*] Terminating fuzzer.")
    reporter.stop()

    fuzzer.stop()
    if drill_extension:
        drill_extension.kill()

    if args.tarball:
        print ("[*] Dumping results...")
        p = os.path.join("/tmp/", "afl_sync")
        try:
            shutil.rmtree(p)
        except (OSError, IOError):
            pass
        shutil.copytree(fuzzer.work_dir, p)

        tar_name = args.tarball.replace("{}", socket.gethostname())

        tar = tarfile.open("/tmp/afl_sync.tar.gz", "w:gz")
        tar.add(p, arcname=socket.gethostname()+'-'+os.path.basename(args.binary))
        tar.close()
        print ("[*] Copying out result tarball to %s" % tar_name)
        shutil.move("/tmp/afl_sync.tar.gz", tar_name)


if __name__ == "__main__":
    main()
