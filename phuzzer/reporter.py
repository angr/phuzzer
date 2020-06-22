import time
import glob
import os
from collections import defaultdict
from threading import Thread


class Reporter(Thread):
    DETAIL_FREQ = 1

    def __init__(self, binary, reportdir, afl_cores, first_crash, timeout,  work_dir):
        Thread.__init__(self)
        self.binary = binary
        self.reportdir = reportdir
        self.afl_cores = afl_cores
        self.first_crash = first_crash
        self.timeout = timeout

        self.work_dir = work_dir

        self.details_fn = f"{reportdir}/run_details.txt"
        self.summary_fn = f"{reportdir}/run_summary.txt"

        if not os.path.exists(self.details_fn):
            open(self.details_fn, "w").write(
                f'Date\tTime\tBinary\tTarget\tElapsed\tCores\tExecs\tExec/sec\tCycles\tPaths\tCrashes\tReason\tTestVer\n')

        if not os.path.exists(self.summary_fn):
            open(self.summary_fn, "w").write(
                f'Date\tTime\tBinary\tTarget\tElapsed\tCores\tExecs\tExec/sec\tCycles\tPaths\tCrashes\tReason\tTestVer\n')

        self.start_time = time.time()
        self.statement_cnt = 0
        self.get_fuzzer_stats()
        self.keepgoing=True
        self.summary_stats = defaultdict(lambda: 0)
        self.last_printed_crashes = self.summary_stats["unique_crashes"]
        self.last_printed_paths_total = self.summary_stats["paths_total"]
        self._crash_seen=False
        self._timeout_reached=False
        self.statement_cnt = 0
        self.do_printing = False

    def run(self):
        while self.keepgoing:
            self.get_fuzzer_stats()
            self.summarize_stats()
            self.generate_report_line()
            if self.do_printing:
                self.print_details()
            time.sleep(1)
            pass

    def enable_printing(self):
        self.do_printing = True

    def summarize_stats(self):

        summary_stats = defaultdict(lambda: 0)
        for _, fuzzstats in self.stats.items():
            for fstat, value in fuzzstats.items():
                try:
                    fvalue = float(value)
                    if fstat == "paths_total":
                        summary_stats[fstat] = max(summary_stats[fstat], int(fvalue))
                    else:
                        summary_stats[fstat] += fvalue
                except ValueError:
                    pass

        self.summary_stats = summary_stats

    def get_fuzzer_stats(self):
        self.stats = {}
        if os.path.isdir(self.work_dir):
            for fuzzer_dir in os.listdir(self.work_dir):
                if os.path.exists(os.path.join(self.work_dir, fuzzer_dir)):
                    stat_path = os.path.join(self.work_dir, fuzzer_dir, "fuzzer_stats")
                    self.stats[fuzzer_dir] = {}
                    if os.path.isfile(stat_path):
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
                                self.stats[fuzzer_dir][key.strip()] = val.strip()


                    fuzz_q_mask = os.path.join(self.work_dir, fuzzer_dir, "queue", "id*")
                    self.stats[fuzzer_dir]["paths_total"] = len(glob.glob(fuzz_q_mask))

    def print_details(self):
        timeout_str = ""
        run_until_str = ""
        self.elapsed_time = time.time() - self.start_time
        if self.timeout:
            if self.first_crash:
                run_until_str = "until first crash or "
            run_until_str += "timeout "
            timeout_str = "for %d of %d seconds " % (self.elapsed_time, self.timeout)
        elif self.first_crash:
            run_until_str = "until first crash "
        else:
            run_until_str = "until stopped by you "

        outstr = "[*] %d fuzzers running %s%scompleted %d execs at %d execs/sec and %d cycles with %d paths and \033[32;5;3m%d crashes \033[0m)." % \
                 (self.afl_cores, run_until_str, timeout_str, self.summary_stats["execs_done"], self.summary_stats["execs_per_sec"],
                  self.summary_stats["cycles_done"],
                  self.summary_stats["paths_total"], self.summary_stats["unique_crashes"])

        if self.last_printed_crashes != self.summary_stats["unique_crashes"] or (
                self.elapsed_time > 3600 and self.summary_stats["paths_total"] != self.last_printed_paths_total):
            print(outstr)
        else:
            print(outstr, end="\r")
        self.last_printed_crashes = self.summary_stats["unique_crashes"]
        self.last_printed_paths_total = self.summary_stats["paths_total"]

    def generate_report_line(self):
        self.elapsed_time = time.time() - self.start_time
        run_until_str = ""
        timeout_str = ""
        self.build_report_stats()
        self.statement_cnt += 1
        if self.statement_cnt % Reporter.DETAIL_FREQ == 0:
            open(self.details_fn, "a+").write(self.build_report_stats() + "\n")

    def build_report_stats(self, end_reason=""):

        import datetime, os
        version = ""
        if "WC_TESTVER" in os.environ:
            wc_testver = os.environ["WC_TESTVER"]
        else:
            wc_testver = "UNKNOWN"

        dt = datetime.datetime.now()
        binary_version = self.binary.replace("/p/webcam/php/", "").replace("/sapi/cgi/php-cgi", "")

        return f'{dt:%Y-%m-%d}\t{dt:%H:%M:%S}\t{binary_version}\t{os.environ["SCRIPT_FILENAME"]:<25}' \
               f'\t{self.elapsed_time:.0f}\t{self.afl_cores}\t{self.summary_stats["execs_done"]:.0f}' \
               f'\t{float(self.summary_stats["execs_per_sec"]):.0f}\t{self.summary_stats["cycles_done"]}' \
               f'\t{self.summary_stats["paths_total"]:.0f}\t{self.summary_stats["unique_crashes"]:.0f}' \
               f'\t{end_reason}\t{wc_testver}'

    def set_crash_seen(self):
        self._crash_seen = True

    def set_timeout_seen(self):
        self._timeout_seen = True

    def save_summary_line(self, end_reason):
        run_results = self.build_report_stats()
        open(self.summary_fn, "a+").write(run_results + "\n")

    def stop(self):
        end_reason=""
        if self.first_crash:
            end_reason = "First Crash"

        if self._crash_seen:
            # print ("\n[*] Crash found!")
            end_reason = "Crash Found."

        if self._timeout_reached:
            end_reason = "Max Time Reached"

        self.save_summary_line(end_reason)

        self.keepgoing = False

