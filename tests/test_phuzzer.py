import os
import time
import tempfile
import unittest
from os.path import join

import phuzzer


class TestPhuzzer(unittest.TestCase):
    bin_location = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries"
    )

    def test_parallel_execution(self):
        """
        test parallel execution, summary stats, and the timed_out method of Phuzzer
        """

        timeout_value = 5
        binary = os.path.join(self.bin_location, "tests", "cgc", "ccf3d301_01")
        with tempfile.TemporaryDirectory() as work_dir:
            afl = phuzzer.AFL(
                binary,
                work_dir=work_dir,
                afl_count=2,
                create_dictionary=True,
                resume=False,
                timeout=timeout_value,
            )

            afl.start()

            start_time = time.time()
            while not afl.timed_out():
                time.sleep(0.75)
            elapsed_time = time.time() - start_time
            assert elapsed_time <= (timeout_value + 1)

            assert os.path.exists(join(afl.work_dir, "fuzzer-master", "queue"))
            assert os.path.exists(join(afl.work_dir, "fuzzer-1", "queue"))
            # assert os.path.exists(join(afl.work_dir, "fuzzer-2", "queue"))

            assert afl.summary_stats["execs_done"] > 0
            assert afl.summary_stats["execs_per_sec"] > 0

            afl.stop()

    def test_dictionary_creation_cgc(self):
        """
        test dictionary creation on a binary
        """

        binary = os.path.join(self.bin_location, "tests", "cgc", "ccf3d301_01")
        afl = phuzzer.AFL(binary, create_dictionary=True, resume=False)
        assert len(afl.dictionary) >= 60
        assert not os.path.exists(afl.dictionary_file)
        afl.start()
        assert os.path.exists(afl.dictionary_file)
        afl.stop()

    def test_minimizer(self):
        """
        Test minimization of an input
        """

        binary = os.path.join(self.bin_location, "tests", "cgc", "PIZZA_00001")

        crash = bytes.fromhex(
            "66757fbeff10ff7f1c3131313131413131317110314301000080006980009fdce6fecc4c66747fbeffffff7f1c31313131314131313171793143cfcfcfcfcfcfcf017110314301000000003e3e3e3e3e413e3e2e3e3e383e317110000000003e3e3e3e3e413e3e2e3e3e383e31713631310031103c3b6900ff3e3131413131317110313100000000006900ff91dce6fecc7e6e000200fecc4c66747fbeffffff7f1c31313131314131313171793143cf003100000000006900ff91dcc3c3c3479fdcffff084c3131313133313141314c6f00003e3e3e3e30413e3e2e3e3e383e31712a000000003e3e3e3e3eedededededededededededededededededededededededededededededededededededededededededede0dadada4c4c4c4c333054c4c4c401000000fb6880009fdce6fecc4c66757fbeffffff7f1c31313131314131313171793143cfcfcfcfcfcfcf017110314301000000003e3e3e3e3e413e3e2e343e383e317110000000003e3e3e3e3e413e3e2e3e3e383e31713631310031103c3b6900ff3e3131413131317110313100000000006900ff91dce6fecc7e6e000200003100000000006900ff91dcc3c3c3479fdcffff084c0d0d0d0d0dfa1d7f"
        )

        m = phuzzer.Minimizer(binary, crash)

        assert m.minimize() == b"100"

    def test_showmap(self):
        """
        Test the mapping of an input
        """

        true_dict = {
            7525: 1,
            14981: 1,
            25424: 1,
            31473: 1,
            33214: 1,
            37711: 1,
            64937: 1,
            65353: 4,
            66166: 1,
            79477: 1,
            86259: 1,
            86387: 1,
            96625: 1,
            107932: 1,
            116010: 1,
            116490: 1,
            117482: 4,
            120443: 1,
        }

        binary = os.path.join(self.bin_location, "tests", "cgc", "cfe_CADET_00003")

        testcase = b"hello"

        s = phuzzer.Showmap(binary, testcase)
        smap = s.showmap()

        for te in true_dict:
            assert true_dict[te] == smap[te]

    def test_fuzzer_spawn(self):
        """
        Test that the fuzzer spawns correctly
        """

        binary = os.path.join(self.bin_location, "tests", "cgc", "PIZZA_00001")

        f = phuzzer.AFL(binary, resume=False)
        f.start()

        for _ in range(15):
            if f.alive:
                break
            time.sleep(1)

        assert f.alive
        if f.alive:
            f.stop()

    def test_multicb_spawn(self):
        """
        Test that the fuzzer spins up for a multicb challenge.
        """
        binaries = [
            os.path.join(self.bin_location, "tests", "cgc", "251abc02_01"),
            os.path.join(self.bin_location, "tests", "cgc", "251abc02_02"),
        ]

        f = phuzzer.AFLMultiCB(binaries, create_dictionary=True)
        f.start()

        for _ in range(15):
            if f.alive:
                break
            time.sleep(1)

        assert f.alive

        dictionary_path = os.path.join(f.work_dir, "dict.txt")
        assert os.path.isfile(dictionary_path)

        if f.alive:
            f.stop()

    def test_pollenate(self):
        fauxware = os.path.join(self.bin_location, "tests", "i386", "fauxware")
        f = phuzzer.AFL(fauxware, resume=False)
        f.start()

        time.sleep(1)

        # this should get synchronized
        f.pollenate(b"A" * 9 + b"SOSNEAKY\0")
        for _ in range(30):
            if any(b"SOSNEAKY" in t for t in f.queue()):
                if f.alive:
                    f.stop()
                break
            time.sleep(1)
        else:
            if f.alive:
                f.stop()
            assert False, "AFL failed to synchronize pollenated seed."

    def inprogress_dict(self):
        va = os.path.join(self.bin_location, "tests", "x86_64", "veritesting_a")
        f = phuzzer.AFL(va, resume=False, dictionary=[b"B"])
        f.start()

        time.sleep(1)
        assert f.alive

        # this should get synchronized
        for _ in range(30):
            if any(t.count(b"B") == 10 in t for t in f.queue()):
                if f.alive:
                    f.stop()
                break
            time.sleep(1)
        else:
            if f.alive:
                f.stop()
            assert False, "AFL failed to find the easter egg given a dict."


if __name__ == "__main__":
    unittest.main()
