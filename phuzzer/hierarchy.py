import networkx
import logging
import tqdm
import glob
import os

l = logging.getLogger('fuzzer.input_hierarchy')

class InputHierarchy:
    """
    This class deals with the AFL input hierarchy and analyses done on it.
    """

    def __init__(self, fuzzer_dir, load_crashes=True):
        self._dir = fuzzer_dir
        self.inputs = { }
        self.worker_inputs = { }
        self.workers = [ ]

        self.reload(load_crashes)

        while self._remove_cycles():
            pass

    def _remove_cycles(self):
        """
        Really hacky way to remove cycles in hierarchies (wtf).
        """

        G = self.make_graph()
        cycles = list(networkx.simple_cycles(G))
        if not cycles:
            return False
        else:
            cycles[0][0].looped = True
            cycles[0][0].parents[:] = [ ]
            return True

    def triggered_blocks(self):
        """
        Gets the triggered blocks by all the testcases.
        """
        return set.union(*(i.block_set for i in tqdm.tqdm(self.inputs.values())))

    def crashes(self):
        """
        Returns the crashes, if they are loaded.
        """
        return [ i for i in self.inputs.values() if i.crash ]

    def technique_contributions(self):
        """
        Get coverage and crashes by technique.
        """
        results = { }
        for s,(b,c) in self.seed_contributions():
            results.setdefault(s.worker.split('-')[0], [0,0])[0] += b
            results.setdefault(s.worker.split('-')[0], [0,0])[1] += c
        return results

    def reload(self, load_crashes):
        self._load_workers()
        for i in self.workers:
            self._load_inputs(i)
            if load_crashes:
                self._load_inputs(i, input_type="crashes")
        self._resolve_all_parents()
        return self

    def _load_workers(self):
        self.workers = [
            os.path.basename(os.path.dirname(n))
            for n in glob.glob(os.path.join(self._dir, "*", "queue"))
        ]
        self.worker_inputs = { i: { } for i in self.workers }
        l.debug("Instances: %s", self.workers)

    def _load_inputs(self, worker, input_type="queue"):
        l.info("Loading inputs from worker %s", worker)
        for fp in glob.glob(os.path.join(self._dir, worker, input_type, "id*")):
            l.debug("Adding input %s", fp)
            i = Seed(fp)
            self.inputs[i.worker + ':' + i.id] = i
            self.worker_inputs[i.worker][i.id] = i

    def _resolve_all_parents(self):
        for i in self.inputs.values():
            self._resolve_parents(i)

    def _resolve_parents(self, seed):
        try:
            if seed.source_ids and seed.source_ids[0] == "pollenation":
                # this is pollenated in
                seed.parents = [ ]
            elif seed.synced_from:
                seed.parents = [ self.input_from_worker(seed.synced_from, seed.source_ids[0]) ]
            else:
                seed.parents = [ self.input_from_worker(seed.worker, i) for i in seed.source_ids ]
        except KeyError as e:
            l.warning("Unable to resolve source ID %s for %s", e, self)
            seed.parents = [ ]


    def input_from_worker(self, worker, id): #pylint:disable=redefined-builtin
        return self.worker_inputs[worker][id]

    def make_graph(self):
        G = networkx.DiGraph()
        for child in self.inputs.values():
            for parent in child.parents:
                G.add_edge(parent, child)
        return G

    def plot(self, output=None):
        import matplotlib.pyplot as plt #pylint:disable=import-error,import-outside-toplevel
        plt.close()
        networkx.draw(self.make_graph())
        if output:
            plt.savefig(output)
        else:
            plt.show()

    #
    # Lineage analysis
    #

    def seed_parents(self, seed):
        if seed.parents is None:
            self._resolve_parents(seed)
        return seed.parents

    def seed_lineage(self, seed):
        for p in self.seed_parents(seed):
            yield from self.seed_lineage(p)
        yield seed

    def print_lineage(self, seed, depth=0):
        if depth:
            print(' '*depth + str(seed))
        else:
            print(seed)
        for parent in self.seed_parents(seed):
            self.print_lineage(parent, depth=depth+1)

    def seed_origins(self, seed):
        """
        Return the origins of the given seed.

        :param seed: the seed
        """
        if seed.origins is not None:
            return seed.origins

        if not self.seed_parents(seed):
            o = { seed }
        else:
            o = set.union(*(self.seed_origins(s) for s in self.seed_parents(seed)))
        seed.origins = o
        return seed.origins

    def contributing_techniques(self, seed):
        if seed.contributing_techniques is None:
            # don't count this current technique if we synced it
            if seed.synced_from:
                new_technique = frozenset()
            else:
                new_technique = frozenset([seed.technique])
            seed.contributing_techniques = frozenset.union(
                new_technique, *(i.contributing_techniques for i in self.seed_parents(seed))
            )
        return seed.contributing_techniques

    def contributing_workers(self, seed):
        return set(i.worker for i in self.seed_lineage(seed))

    def seed_contributions(self):
        """
        Get the seeds (including inputs introduced by extensions) that
        resulted in coverage and crashes.
        """
        sorted_inputs = sorted((
            i for i in self.inputs.values() if i.worker.startswith('fuzzer-')
        ), key=lambda j: j.timestamp)

        found = set()
        contributions = { }
        for s in tqdm.tqdm(sorted_inputs):
            o = max(s.origins, key=lambda i: i.timestamp)
            if s.crash:
                contributions.setdefault(o, (set(),set()))[1].add(s)
            else:
                c = o.transition_set - found
                if not c:
                    continue
                contributions.setdefault(o, (set(),set()))[0].update(c)
                found |= c

        return sorted(((k, list(map(len,v))) for k,v in contributions.items()), key=lambda x: x[0].timestamp)

from .seed import Seed
