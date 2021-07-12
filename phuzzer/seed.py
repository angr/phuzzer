import logging
import os

l = logging.getLogger('fuzzer.seed')

class Seed:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.worker = os.path.basename(os.path.dirname(os.path.dirname(filepath)))
        self.technique = self.worker.split("-")[0].split("_")[0].split(":")[0]

        self.id = None
        self.source_ids = [ ]
        self.cov = False
        self.op = None
        self.synced_from = None
        self.other_fields = { }
        self.val = None
        self.rep = None
        self.pos = None
        self.orig = None
        self.crash = False
        self.sig = None
        self._process_filename(self.filename)

        self.timestamp = os.stat(self.filepath).st_mtime

        # these are resolved by the hierarchy
        self.parents = None
        self.origins = None
        self.contributing_techniques = None

    def _process_filename(self, filename):
        # process the fields
        fields = filename.split(',')
        for f in fields:
            if f == "+cov":
                self.cov = True
            elif f == "grease":
                assert self.id
                self.orig = "greased_%s" % self.id
            else:
                n,v = f.split(':', 1)
                if n == 'id':
                    assert not self.id
                    self.id = v
                elif n == 'src':
                    assert not self.source_ids
                    self.source_ids = v.split('+')
                elif n == 'sync':
                    assert not self.synced_from
                    self.synced_from = v
                elif n == 'op':
                    assert not self.op
                    self.op = v
                elif n == 'rep':
                    assert not self.rep
                    self.rep = v
                elif n == 'orig':
                    assert not self.orig
                    self.orig = v
                elif n == 'pos':
                    assert not self.pos
                    self.pos = v
                elif n == 'val':
                    assert not self.val
                    self.val = v
                elif n == 'from': # driller uses this instead of synced/src
                    instance, from_id = v[:-6], v[-6:]
                    self.synced_from = instance
                    self.source_ids.append(from_id)
                elif n == 'sig':
                    assert not self.crash
                    assert not self.sig
                    assert self.id
                    self.crash = True
                    self.sig = v
                    self.id = 'c'+self.id
                else:
                    l.warning("Got unexpected field %s with value %s for file %s.", n, v, filename)
                    self.other_fields[n] = v

        assert self.id is not None
        assert self.source_ids or self.orig

    def read(self):
        with open(self.filepath, 'rb') as f:
            return f.read()

    def __repr__(self):
        s = "<Input %s/%s>" % (self.worker, self.filename)
        #if self.synced_from:
        #   s += " sync:%s" % self.synced_from
        #s += "src:%s" % self.source_ids
        return s
