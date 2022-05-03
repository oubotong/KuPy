import yaml
import kano_py.kano.algorithm as kano
import kubesv.kubesv.postprocess as ksv

from contextlib import contextmanager
from time import perf_counter
from kano_py.kano.model import *
from kano_py.kano.parser import ConfigParser
from kano_py.tests.generate import ConfigFiles
from kubesv.kubesv.constraint import *
from kubesv.kubesv.postprocess import *
from kubesv.kubesv.parser import from_yaml
from pprint import pprint


@contextmanager
def timing(description: str) -> None:
    start = perf_counter()    
    yield
    ellapsed_time = perf_counter() - start

    print(f"{description}: {ellapsed_time}")


def read_kubesv_yaml(filepath):
    pods = []
    policies = []
    for subdir, _, files in os.walk(filepath):
        for file in files:
            filename = os.path.join(subdir, file)
            with open(filename, 'r') as f:
                if file.startswith("pod"):
                    pods.append(PodAdapter(from_yaml('V1Pod', f)))
                elif file.startswith('policy'):
                    policies.append(PolicyAdapter(from_yaml('V1NetworkPolicy', f)))

    ns_templ = """
kind: Namespace
apiVersion: v1
metadata:
  name: default
"""
    default_namespace = NamespaceAdapter(from_yaml('V1Namespace', ns_templ))

    return pods, policies, [default_namespace]


def compare_results(podN_i=100, policyN_i=50, keyL_i=10, userL_i=5, selectedLL_i=3, allowpodLL_i=3):
    data_folder = "data"
    config = ConfigFiles(data_folder, podN=podN_i, policyN=policyN_i, keyL=keyL_i, userL=userL_i, selectedLL=selectedLL_i, allowpodLL=allowpodLL_i)
    config.generateConfigFiles()

    cp = ConfigParser()
    containers, policies = cp.parse(data_folder)
    k_pods, k_pols, k_ns = read_kubesv_yaml(data_folder)

    # Enable ingress_traffic from self pod
    check_self_ingress_traffic = True 
    # Enable default policy checking
    check_select_by_no_policy = True
    # Build transpose reachablity matrix -> fast getCol(k) operation
    build_transpose_matrix = True
    # Ground all default pods -> eliminate negation in ingress/egress_traffic
    ground_default_pod = True

    '''
    print("Configuration: ", 
        check_self_ingress_traffic, 
        check_select_by_no_policy, 
        build_transpose_matrix,
        ground_default_pod)
    '''

    #with timing("calculating reachability matrix"):
    with timing(""):
        matrix = ReachabilityMatrix.build_matrix(containers, policies, 
            check_self_ingress_traffic=check_self_ingress_traffic,
            check_select_by_no_policy=check_select_by_no_policy,
            build_transpose_matrix=build_transpose_matrix)

    # https://github.com/Z3Prover/z3/discussions/4992
    # @nunoplopes: If you really need speed, you can't use Python. Python is slow and Z3's Python API is super slow.
    #with timing("calculating SMT constraints"):
    with timing(""):
        gi = build(k_pods, k_pols, k_ns, 
                check_self_ingress_traffic=check_self_ingress_traffic, 
                check_select_by_no_policy=check_select_by_no_policy,
                ground_default_pod=ground_default_pod)
    
    #with timing("measuring kano algorithm speed"):
    with timing(""):
        ar, ai = kano.all_reachable(matrix), kano.all_isolated(matrix)
        si = kano.system_isolation(matrix, 0)
        ps, pc = kano.policy_shadow(matrix, policies, containers), kano.policy_conflict(matrix, policies, containers)

        kano_results = {
            "algorithm": "kano",
            "all_reachable": ar,
            "all_isolated": ai,
            "user_crosscheck": kano.user_crosscheck(matrix, containers, "User"),
            "system_isolation": si,
            "policy_shadow": ps,
            "policy_conflict": pc,
        }

    #with timing("measuring z3 algorithm speed"):
    with timing(""):
        # ar, ai = ksv.all_reach_isolate(gi)
        (_, ar), (_, ai) = ksv.all_reachable_native(gi), ksv.all_isolated_native(gi)
        _, si = ksv.system_isolation(gi, 0)
        (_, ps), (_, pc) = ksv.policy_shadow(gi), ksv.policy_conflict(gi)

        ksv_results = {
            "algorithm": "z3nd",
            "all_reachable": ar,
            "all_isolated": ai,
            "user_crosscheck": ksv.user_crosscheck(gi, "User")[1],
            "system_isolation": si,
            "policy_shadow": ps,
            "policy_conflict": pc,
        }

    '''
    print(kano_results["all_reachable"].symmetric_difference(ksv_results["all_reachable"]))
    print(kano_results["all_isolated"].symmetric_difference(ksv_results["all_isolated"]))
    print(kano_results["user_crosscheck"].symmetric_difference(ksv_results["user_crosscheck"]))
    print(kano_results["system_isolation"].symmetric_difference(ksv_results["system_isolation"]))
    print(kano_results["policy_shadow"].symmetric_difference(ksv_results["policy_shadow"]))
    print(kano_results["policy_conflict"].symmetric_difference(ksv_results["policy_conflict"]))
    '''

if __name__ == "__main__":
    #loop through parameters and run tests
    for i in range(100, 1100, 100):
        podN = i
        policyN = int(i/2)
        keyL = int(i/10)
        userL = 5
        selectedLL = 3 
        allowpodLL = 3
        compare_results(podN_i=podN, policyN_i=policyN, keyL_i=keyL, userL_i=userL, selectedLL_i=selectedLL, allowpodLL_i=allowpodLL)
        print()
