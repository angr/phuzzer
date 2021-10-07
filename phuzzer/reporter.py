import os
import time
import glob
import datetime
import traceback
from threading import Thread
from collections import defaultdict


class Reporter(Thread):
    DETAIL_FREQ = 1

    def __init__(self, binary, reportdir, afl_cores, first_crash, timeout,  work_dir, testversion=""):
        Thread.__init__(self)
        self.binary = binary
        self.reportdir = reportdir
        self.afl_cores = afl_cores
        self.first_crash = first_crash
        self.timeout = timeout
        self.timeout_seen = False
        self.work_dir = work_dir

        self.details_fn = f"{reportdir}/run_details.txt"
        self.summary_fn = f"{reportdir}/run_summary.txt"

        if not os.path.exists(self.details_fn):
            open(self.details_fn, "w").write('Date\tTime\tBinary\tTarget\tElapsed\tCores\tExecs\tExec/sec\tCycles\tPaths\tCrashes\tReason\tTestVer\n')

        if not os.path.exists(self.summary_fn):
            open(self.summary_fn, "w").write('Date\tTime\tBinary\tTarget\tElapsed\tCores\tExecs\tExec/sec\tCycles\tPaths\tCrashes\tReason\tTestVer\n')

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
        self.elapsed_time = 0
        self.testversion = testversion
        self.script_filename = ""

    def set_script_filename(self, script_fn):
        self.script_filename = script_fn

    def run(self):
        while self.keepgoing:
            self.generate_report_line()
            time.sleep(1)

    def enable_printing(self):
        self.do_printing = True

    def summarize_stats(self):

        summary_stats = defaultdict(lambda: 0)
        for _, fuzzstats in self.stats.items():
            for fstat, value in fuzzstats.items():
                try:
                    fvalue = float(value)
                    if fstat in ('paths_total', 'unique_crashes'):
                        summary_stats[fstat] = max(summary_stats[fstat], int(fvalue))
                    else:
                        try:
                            summary_stats[fstat] += int(fvalue)
                        except Exception:
                            summary_stats[fstat] += 0
                except ValueError:
                    pass

        self.summary_stats = summary_stats

    def get_fuzzer_stats(self):
        self.stats = {}
        if os.path.isdir(self.work_dir):
            for fuzzer_dir in os.listdir(self.work_dir):
                if os.path.isdir(os.path.join(self.work_dir, fuzzer_dir)):
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
                                    except Exception:
                                        index = stat.find(":")
                                        key = stat[:index]
                                        val = stat[index + 1:]
                                else:
                                    print(f"Skipping stat '${stat}' in \n${stat_lines} because no split value")
                                    continue
                                try:
                                    self.stats[fuzzer_dir][key.strip()] = val.strip()
                                except KeyError as ke:
                                    print(ke)
                                    traceback.format_exc()
                                    print(self.stats.keys())

                    try:
                        fuzz_q_mask = os.path.join(self.work_dir, fuzzer_dir, "crashes*", "id*")
                        self.stats[fuzzer_dir]["unique_crashes"] = len(glob.glob(fuzz_q_mask))
                        fuzz_q_mask = os.path.join(self.work_dir, fuzzer_dir, "queue", "id*")
                        self.stats[fuzzer_dir]["paths_total"] = len(glob.glob(fuzz_q_mask))
                    except KeyError as ke:
                        print(ke)
                        traceback.format_exc()
                        print(self.stats.keys())

    def print_details(self, mandatory_print=False):
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

        outstr =  f'[*] {self.afl_cores} fuzzers running {run_until_str}{timeout_str}completed '
        outstr += f'{self.summary_stats["execs_done"]} at {self.summary_stats["execs_per_sec"]} execs/sec '
        outstr += f'with {self.summary_stats["cycles_done"]} cycles finding {self.summary_stats["paths_total"]} paths and '
        outstr += f'\033[32;5;3m{self.summary_stats["unique_crashes"]} crashes \033[0m'

        if self.last_printed_crashes != self.summary_stats["unique_crashes"] or mandatory_print or (
                self.elapsed_time > 3600 and self.summary_stats["paths_total"] != self.last_printed_paths_total):
            print(outstr)
        else:
            print(outstr, end="\r")
        self.last_printed_crashes = self.summary_stats["unique_crashes"]
        self.last_printed_paths_total = self.summary_stats["paths_total"]

    def generate_report_line(self, mandatory_record=False):
        self.elapsed_time = time.time() - self.start_time

        self.get_fuzzer_stats()
        self.summarize_stats()

        self.build_report_stats()
        self.statement_cnt += 1
        if self.statement_cnt % Reporter.DETAIL_FREQ == 0 or mandatory_record:
            with open(self.details_fn, "a+") as fp :
                fp.write(self.build_report_stats() + "\n")

        if self.do_printing:
            self.print_details(mandatory_record)

    def build_report_stats(self, end_reason=""):

        dt = datetime.datetime.now()
        binary_version = self.binary.replace("/p/webcam/php/", "").replace("/sapi/cgi/php-cgi", "")

        return f'{dt:%Y-%m-%d}\t{dt:%H:%M:%S}\t{binary_version}\t{self.script_filename:<25}' \
               f'\t{self.elapsed_time:.0f}\t{self.afl_cores}\t{self.summary_stats["execs_done"]:.0f}' \
               f'\t{float(self.summary_stats["execs_per_sec"]):.0f}\t{self.summary_stats["cycles_done"]}' \
               f'\t{self.summary_stats["paths_total"]:.0f}\t{self.summary_stats["unique_crashes"]:.0f}' \
               f'\t{end_reason}\t{self.testversion}'

    def set_crash_seen(self):
        self._crash_seen = True

    def set_timeout_seen(self):
        self._timeout_seen = True

    def save_summary_line(self, end_reason):
        run_results = self.build_report_stats(end_reason)
        with open(self.summary_fn, "a+") as fp:
            fp.write(run_results + "\n")

    def stop(self):
        end_reason=""
        if self.first_crash:
            end_reason = "First Crash"

        if self._crash_seen:
            # print ("\n[*] Crash found!")
            end_reason = "Crash Found."

        if self._timeout_reached:
            end_reason = "Max Time Reached"

        self.keepgoing = False

        self.generate_report_line(mandatory_record=True)

        self.save_summary_line(end_reason)
