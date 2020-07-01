
from queue import Queue, Empty
from threading import Thread
from .afl import AFL
import json
import os
import re
import subprocess
import shutil
import time
import stat
import glob
import logging
import urllib.request

l = logging.getLogger("phuzzer.phuzzers.wafl")
l.setLevel(logging.INFO)

class WitcherAFL(AFL):
    """ WitcherAFL launches the web fuzzer building on the AFL object """

    def __init__(
        self, target, seeds=None, dictionary=None, create_dictionary=None,
        work_dir=None, resume=False,
        afl_count=1, memory="8G", timeout=None,
        target_opts=None, extra_opts=None,
        crash_mode=False, use_qemu=True,
        run_timeout=None, login_json_fn=""
    ):
        """
        :param target: path to the script to fuzz (from AFL)
        :param seeds: list of inputs to seed fuzzing with (from AFL)
        :param dictionary: a list of bytes objects to seed the dictionary with (from AFL)
        :param create_dictionary: create a dictionary from the string references in the binary (from AFL)
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here (from AFL)

        :param resume: resume the prior run, if possible (from AFL)
        :param afl_count:

        :param memory: AFL child process memory limit (default: "8G")
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param timeout: timeout for individual runs within AFL

        :param library_path: library path to use, if none is specified a default is chosen
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up

        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param use_qemu: Utilize QEMU for instrumentation of binary.

        :param run_timeout: amount of time for AFL to wait for a single execution to finish
        :param login_json_fn: login configuration file path for automatically craeting a login session and performing other initial tasks

        """
        super().__init__(
            target=target, work_dir=work_dir, seeds=seeds, afl_count=afl_count,
            create_dictionary=create_dictionary, timeout=timeout,
            memory=memory, dictionary=dictionary, use_qemu=use_qemu,
            target_opts=target_opts, resume=resume, crash_mode=crash_mode, extra_opts=extra_opts,
            run_timeout=run_timeout
        )

        self.login_json_fn = login_json_fn

        self.used_sessions = set()
        self.session_name = ""
        self.bearer = ""

        if "AFL_PATH" in os.environ:
            afl_fuzz_bin = os.path.join(os.environ['AFL_PATH'], "afl-fuzz")
            if os.path.exists(afl_fuzz_bin):
                self.afl_path = afl_fuzz_bin
            else:
                raise ValueError(
                    f"error, have AFL_PATH but cannot find afl-fuzz at {os.environ['AFL_PATH']} with {afl_fuzz_bin}")

    def _start_afl_instance(self, instance_cnt=0):

        args, fuzzer_id = self.build_args()

        my_env = os.environ.copy()

        target_opts = []
        for op in self.target_opts:
            target_opts.append(op.replace("~~", "--").replace("@PORT@", my_env["PORT"]))
        args += target_opts

        self._get_login(my_env)

        my_env["AFL_BASE"] = os.path.join(self.work_dir, fuzzer_id)
        my_env["STRICT"] = "true"

        if "METHOD" not in my_env:
            my_env["METHOD"] = "POST"

        # print(f"[WC] my word dir {self.work_dir} AFL_BASE={my_env['AFL_BASE']}")

        self.log_command(args, fuzzer_id, my_env)

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")
        l.debug("execing: %s > %s", ' '.join(args), logpath)

        # set core affinity if environment variable is set
        if "AFL_SET_AFFINITY" in my_env:
            tempint = int(my_env["AFL_SET_AFFINITY"])
            tempint += instance_cnt
            my_env["AFL_SET_AFFINITY"] = str(tempint)

        with open(logpath, "w") as fp:
            return subprocess.Popen(args, stdout=fp, stderr=fp, close_fds=True, env=my_env)

    def _check_for_authorized_response(self, body, headers, loginconfig):
        return WitcherAFL._check_body(body, loginconfig) and WitcherAFL._check_headers(headers, loginconfig)

    @staticmethod
    def _check_body(self, body, loginconfig):
        if "positiveBody" in loginconfig and len(loginconfig["positiveBody"]) > 1:
            pattern = re.compile(loginconfig["positiveBody"])
            return pattern.search(body) is None
        return True

    @staticmethod
    def _check_headers(self, headers, loginconfig):
        if "postiveHeaders" in loginconfig:
            posHeaders = loginconfig["positiveHeaders"]
            for ph in posHeaders:
                for posname, posvalue in ph:
                    found = False
                    for headername, headervalue in headers:
                        if posname == headername and posvalue == headervalue:
                            found = True
                    if not found:
                        return False
        return True

    def _save_session(self, session_cookie, loginconfig):
        session_cookie_locations = ["/tmp","/var/lib/php/sessions"]
        if "loginSessionCookie" in loginconfig:
            session_name = loginconfig["loginSessionCookie"]
        else:
            session_name = r".*"
        if "cookieLocations" in loginconfig:
            for cl in loginconfig["cookeLocations"]:
                session_cookie_locations.append(cl)

        sessidrex = re.compile(rf"{session_name}=(?P<sessid>[a-z0-9]{{24,40}})")
        sessid = sessidrex.match(session_cookie).group("sessid")
        if not sessid:
            return False

        # print("[WC] sessidrex " + sessid)
        actual_sess_fn = ""
        for f in session_cookie_locations:

            sfile = f"*{sessid}"
            sesmask = os.path.join(f,sfile)
            for sfn in glob.glob(sesmask):
                if os.path.isfile(sfn):
                    actual_sess_fn = sfn
                    break
            if len(actual_sess_fn) > 0:
                break

        if len(actual_sess_fn) == 0:
            return False

        saved_sess_fn = f"/tmp/save_{sessid}"
        if os.path.isfile(actual_sess_fn):
            shutil.copyfile(actual_sess_fn, saved_sess_fn)
            os.chmod(saved_sess_fn, stat.S_IRWXO | stat.S_IRWXG | stat.S_IRWXU)
            self.used_sessions.add(saved_sess_fn)
            return True
        return False

    def _extract_authdata(self, headers, loginconfig):
        authdata = []
        for headername, headervalue in headers:
            if headername.upper() == "SET-COOKIE":
                # Uses special authdata header so that the value prepends all other cookie values and
                # random data from AFL does not interfere

                if self._save_session(headervalue, loginconfig):
                    authdata.append(("LOGIN_COOKIE", headervalue))


            if headername.upper() == "AUTHORIZATION":
                self.bearer = [(headername, headervalue)]
                authdata.append((headername, headervalue))

        return authdata

    def _do_local_cgi_req_login(self, loginconfig):

        login_cmd = [loginconfig["cgiBinary"]]

        # print("[WC] \033[34m starting with command " + str(login_cmd) + "\033[0m")
        myenv = os.environ.copy()
        if "AFL_BASE" in myenv:
            del myenv["AFL_BASE"]

        myenv["METHOD"] = loginconfig["method"]
        myenv["STRICT"] = "1"
        myenv["SCRIPT_FILENAME"] = loginconfig["url"]

        if "afl_preload" in loginconfig:
            myenv["LD_PRELOAD"] = loginconfig["afl_preload"]
        if "ld_library_path" in loginconfig:
            myenv["LD_LIBRARY_PATH"] = loginconfig["ld_library_path"]

        cookieData = loginconfig["cookieData"] if "cookieData" in loginconfig else ""
        getData = loginconfig["getData"] if "getData" in loginconfig else ""
        postData = loginconfig["postData"] if "postData" in loginconfig else ""

        httpdata = f'{cookieData}\x00{getData}\x00{postData}\x00'

        open("/tmp/login_req.dat", "wb").write(httpdata.encode())

        login_req_file = open("/tmp/login_req.dat", "r")

        p = subprocess.Popen(login_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=login_req_file,
                             env=myenv)

        nbsr = NonBlockingStreamReader(p.stdout)
        strout = ""

        while not nbsr.is_finished:

            line = nbsr.readline(0.1)
            if line is not None:
                inp = line.decode('latin-1')
                strout += inp
                # print("\033[32m", end="")
                # print(inp, end="")
                # print("\033[0m", end="")

        p.wait()

        headers = []
        body = ""
        inbody = False
        for respline in strout.splitlines():
            if len(respline) == 0:
                inbody = True
                continue
            if inbody:
                body += respline + "\n"
            else:
                header = respline.split(":")
                if len(header) > 1 and inbody:
                    headername = header[0].strip()
                    headerval = ":".join(header[1:])
                    headerval = headerval.lstrip()
                    headers.append((headername, headerval))

        if not self._check_for_authorized_response(body, headers, loginconfig):
            return []

        return self._extract_authdata(headers, loginconfig)

    def _do_http_req_login(self, loginconfig):

        url = loginconfig["url"]

        if "getData" in loginconfig:
            url += f"?{loginconfig['getData']}"

        post_data = loginconfig["postData"] if "postData" in loginconfig else ""
        post_data = post_data.encode('ascii')

        req_headers = loginconfig["headers"] if "headers" in loginconfig else {}
        opener = urllib.request.build_opener(NoRedirection)
        urllib.request.install_opener(opener)

        req = urllib.request.Request(url, post_data, req_headers)
        response = urllib.request.urlopen(req)

        headers = response.getheaders()
        body = response.read()

        if not self._check_for_authorized_response(body, headers, loginconfig):
            return []

        return self._extract_authdata(headers, loginconfig)

    @staticmethod
    def _do_authorized_requests(self, loginconfig, authdata):
        extra_requests = loginconfig["extra_authorized_requests"] if "postData" in loginconfig else []

        for auth_request in extra_requests:
            url = auth_request["url"]

            if "getData" in auth_request:
                url += f"?{auth_request['getData']}"

            post_data = auth_request["postData"] if "postData" in auth_request else ""
            post_data = post_data.encode('ascii')

            req_headers = auth_request["headers"] if "headers" in auth_request else {}
            for adname, advalue in authdata:
                adname = adname.replace("LOGIN_COOKIE","Cookie")
                req_headers[adname] = advalue
                req = urllib.request.Request(url, post_data, req_headers)
                urllib.request.urlopen(req)

    def _get_login(self, my_env):
        if self.login_json_fn == "":
            return
        if len(self.bearer) > 0:
            for bname, bvalue in self.bearer:
                my_env[bname] = bvalue
            return

        with open(self.login_json_fn, "r") as jfile:
            jdata = json.load(jfile)
        if jdata["direct"]["url"] == "NO_LOGIN":
            return
        loginconfig = jdata["direct"]

        saved_session_id = self._get_saved_session()
        if len(saved_session_id) > 0:
            saved_session_name = loginconfig["loginSessionCookie"]
            my_env["LOGIN_COOKIE"] = f"{saved_session_name}:{saved_session_id}"
            return

        authdata = None
        for _ in range(0, 10):
            if loginconfig["url"].startswith("http"):
                authdata = self._do_http_req_login(loginconfig)
                WitcherAFL._do_authorized_requests(loginconfig, authdata)
            else:
                authdata = self._do_local_cgi_req_login(loginconfig)
            if authdata is not None:
                break
            time.sleep(5)

        if authdata is None:
            raise ValueError("Login failed to return authenticated cookie/bearer value")

        for authname, authvalue in authdata:

            my_env[authname] = authvalue

    def _get_saved_session(self):
        # if we have an unused session file, we are done for this worker.
        for saved_sess_fn in glob.iglob("/tmp/save_????????????????????*"):
            if saved_sess_fn not in self.used_sessions:
                sess_fn = saved_sess_fn.replace("save", "sess")
                # print("sess_fn=" + sess_fn)
                self.used_sessions.add(saved_sess_fn)
                shutil.copyfile(saved_sess_fn, sess_fn)

                saved_session_id = saved_sess_fn.split("_")[1]
                return saved_session_id
        return ""


class NoRedirection(urllib.request.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response


class NonBlockingStreamReader:

    def __init__(self, stream):
        '''
        stream: the stream to read from.
                Usually a process' stdout or stderr.
        '''

        self._s = stream
        self._q = Queue()
        self._finished = False

        def _populateQueue(stream, queue):
            '''
            Collect lines from 'stream' and put them in 'quque'.
            '''

            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                else:
                    self._finished = True
                    #raise UnexpectedEndOfStream

        self._t = Thread(target = _populateQueue,
                         args = (self._s, self._q))
        self._t.daemon = True
        self._t.start() #start collecting lines from the stream

    @property
    def is_finished(self):
        return self._finished

    def readline(self, timeout = None):
        try:
            if self._finished:
                return None
            return self._q.get(block = timeout is not None,
                    timeout = timeout)
        except Empty:
            return None


class UnexpectedEndOfStream(Exception):
    pass
