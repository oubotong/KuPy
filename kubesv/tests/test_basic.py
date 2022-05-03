from kubesv.kubesv.constraint import ground_default_pods
from kubesv.constraint import *
from kubesv.postprocess import *
from .context import sample

import z3
import unittest


class BasicTestSuite(unittest.TestCase):
    """Basic test cases."""

    def test_egress_traffic(self):
        sample.setup_z3_printer()

        pods, pols, nams = sample.paper_example()
        gi = build(pods, pols, nams, 
            check_self_ingress_traffic=False, 
            check_select_by_no_policy=False,
            ground_default_pod=False)

        rch, iso = all_reach_isolate(gi)
        print(rch)
        print(iso)
        # sat, answer = user_crosscheck(gi, "role")
        # sat, answer = get_all_pairs(gi, "edge")
        sat, answer = policy_shadow(gi)
        print(sat)
        print(answer)

        """
        with open('tests/output/sample.smt2', 'w+') as f:
            f.write(get_datalog(gi.fp, fact))

        with open('tests/output/answer.z3', 'w+') as f:
            f.write(z3.z3printer.obj_to_string(answer))
        """
        
        with open('tests/output/pairs.out', 'w+') as f:
            for p in answer:
                if isinstance(p, tuple):
                    src, dst = p
                    f.write(str(pods[src].to_dict()) + " -> " + str(pods[dst].to_dict()) + "\n")
                else:
                    f.write(str(pods[p].to_dict()) + "\n")


if __name__ == '__main__':
    unittest.main()