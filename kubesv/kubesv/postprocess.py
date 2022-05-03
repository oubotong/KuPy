"""
Post processing some z3 results to implement similar results as Kano.
"""
from z3 import *
from typing import *
from typing_extensions import *
from bitarray import bitarray
from .constraint import GlobalInfo, get_answer
from .utils import *
from time import perf_counter


def get_z3_bitarray(answer: BoolRef, n_container: int, is_ingress=True) -> List[bitarray]:
    # assume the answer is Or(And(Var0, Var1, ...), ...)
    all_answer = [bitarray('0' * n_container) for _ in range(n_container)]
    pairs = parse_z3_result(answer)
    if pairs is None:
        return all_answer
    for src, dst in pairs:
        if is_ingress:
            all_answer[src][dst] = True
        else:
            all_answer[dst][src] = True
    return all_answer


def all_reachable(matrix: List[bitarray]) -> List[int]:
    all_reachables = []
    for i in range(len(matrix)):
        is_all_reachable = True
        for j in range(len(matrix)):
            if matrix[j][i] != True:
                is_all_reachable = False
                break
        if is_all_reachable:
            all_reachables.append(i)
    return all_reachables


def all_isolated(matrix: List[bitarray]) -> List[int]:
    all_isolated = []
    for i in range(len(matrix)):
        is_all_isolated = True
        for j in range(len(matrix)):
            if matrix[j][i] != False:
                is_all_isolated = False
                break
        if is_all_isolated:
            all_isolated.append(i)
    return all_isolated


def get_all_pairs(gi: GlobalInfo, rel: str):
    rel = gi.get_relation_core(rel)

    src = gi.declare_var('src_pair', gi.pod_sort)
    dst = gi.declare_var('dst_pair', gi.pod_sort)

    fact = [rel(src, dst)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, set()
    
    return sat, parse_z3_result(answer)    


def get_all_edges(gi: GlobalInfo):
    return get_all_pairs(gi, "edge") 


def all_reach_isolate(gi: GlobalInfo):
    rel = gi.get_relation_core("edge")

    src = gi.declare_var('src_edge', gi.pod_sort)
    dst = gi.declare_var('dst_edge', gi.pod_sort)

    fact = [rel(src, dst)]
    sat, answer = get_answer(gi.fp, fact)
    matrix = get_z3_bitarray(answer, len(gi.pods))
    return all_reachable(matrix), all_isolated(matrix)


def all_reachable_native(gi: GlobalInfo):
    is_pod = gi.get_relation_core("is_pod")
    disconnect = gi.get_relation_core("disconnect")

    src = gi.declare_var('src_edge', gi.pod_sort)
    dst = gi.declare_var('dst_edge', gi.pod_sort)

    has_unreachable = Function('has_unreachable', gi.pod_sort, BoolSort())
    gi.register_relation("has_unreachable", has_unreachable, is_core=True)
    all_reachable = Function('all_reachable', gi.pod_sort, BoolSort())
    gi.register_relation("all_reachable", all_reachable, is_core=True)

    gi.add_rule(has_unreachable(dst), [
        is_pod(src),
        disconnect(src, dst)
    ])

    gi.add_rule(all_reachable(dst), [
        is_pod(dst),
        Not(has_unreachable(dst))
    ])

    fact = [all_reachable(dst)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, set()

    return sat, parse_z3_result(answer)


def all_isolated_native(gi: GlobalInfo):
    edge = gi.get_relation_core("edge")
    is_pod = gi.get_relation_core("is_pod")

    src = gi.declare_var('src_edge', gi.pod_sort)
    dst = gi.declare_var('dst_edge', gi.pod_sort)

    has_reachable = Function('has_reachable', gi.pod_sort, BoolSort())
    gi.register_relation("has_reachable", has_reachable, is_core=True)
    all_isolated = Function('all_isolated', gi.pod_sort, BoolSort())
    gi.register_relation("all_isolated", all_isolated, is_core=True)

    gi.add_rule(has_reachable(dst), [
        is_pod(src),
        edge(src, dst)
    ])

    gi.add_rule(all_isolated(dst), [
        is_pod(dst),
        Not(has_reachable(dst))
    ])

    fact = [all_isolated(dst)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, set()

    return sat, parse_z3_result(answer)


def user_crosscheck(gi: GlobalInfo, l: str):
    """
    A container can be reached from other user’s container in the container network
    User is specified by the label. 
    Kano: All constainers should have that label.
    """
    label = gi.get_relation(l)
    is_pod = gi.get_relation_core("is_pod")
    edge = gi.get_relation_core("edge")

    user_violation = Function('user_violation_{}'.format(label), gi.pod_sort, BoolSort())
    gi.register_relation("user_violation_{}".format(label), user_violation, is_core=True)

    sel = gi.declare_var('sel_{}'.format(label), gi.pod_sort)
    random = gi.declare_var('random_{}'.format(label), gi.pod_sort)
    lv0 = gi.declare_var('label_value_0_{}'.format(label), gi.lv_sort)
    lv1 = gi.declare_var('label_value_1_{}'.format(label), gi.lv_sort)

    gi.add_rule(user_violation(sel), [
        is_pod(sel),
        is_pod(random),
        edge(random, sel),
        label(random, lv0),
        label(sel, lv1),
        lv0 != lv1
    ])

    fact = [user_violation(sel)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, []
    
    return sat, parse_z3_result(answer)


def system_isolation(gi: GlobalInfo, idx: int):
    """
    A container is isolated with certain container, usually the kube-system container
    System pod is specified by idx
    Kano: only consider egress edge, not path
    """
    is_pod = gi.get_relation_core("is_pod")
    edge = gi.get_relation_core("edge")
    pod_idx = gi.pod_value(idx)

    system_isolation = Function('system_isolation_{}'.format(idx), gi.pod_sort, BoolSort())
    gi.register_relation("system_isolation_{}".format(idx), system_isolation, is_core=True)

    sel = gi.declare_var('system_iso_sel_{}'.format(idx), gi.pod_sort)

    gi.add_rule(system_isolation(sel), [
        is_pod(sel),
        Not(edge(pod_idx, sel))
    ])

    fact = [system_isolation(sel)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, []
    
    return sat, parse_z3_result(answer)


def policy_shadow(gi: GlobalInfo):
    """
    The connections built by a policy are completely covered by another policy, then this policy may be redundant
    NOTE: this is a general version, not Kano's per pod version
    """
    is_pod = gi.get_relation_core("is_pod")
    is_pol = gi.get_relation_core("is_pol")
    selected_by_pol = gi.get_relation_core("selected_by_pol")
    ingress_allow_by_pol = gi.get_relation_core("ingress_allow_by_pol")
    egress_allow_by_pol = gi.get_relation_core("egress_allow_by_pol")

    policy_shadow = Function('policy_shadow', gi.pol_sort, gi.pol_sort, BoolSort())
    gi.register_relation("policy_shadow", policy_shadow, is_core=True)
    policy_unshadow = Function('policy_unshadow', gi.pol_sort, gi.pol_sort, BoolSort())
    gi.register_relation("policy_unshadow", policy_unshadow, is_core=True)


    p0 = gi.declare_var('policy_shadow_inner', gi.pol_sort)
    p1 = gi.declare_var('policy_shadow_outer', gi.pol_sort)

    select = gi.declare_var('policy_shadow_select', gi.pod_sort)

    gi.add_rule(policy_unshadow(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        selected_by_pol(select, p0),
        Not(selected_by_pol(select, p1))
    ])
    gi.add_rule(policy_unshadow(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        ingress_allow_by_pol(select, p0),
        Not(ingress_allow_by_pol(select, p1))
    ])
    gi.add_rule(policy_unshadow(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        egress_allow_by_pol(select, p0),
        Not(egress_allow_by_pol(select, p1))
    ])

    gi.add_rule(policy_shadow(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        p0 != p1,
        Not(policy_unshadow(p0, p1))        
    ])

    fact = [policy_shadow(p0, p1)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, []
    
    return sat, parse_z3_result(answer)


def policy_conflict(gi: GlobalInfo):
    """
    The connections built by a policy are totally contradict the connections built by another    
    NOTE: this is a general version, not Kano's per pod version
    """
    is_pod = gi.get_relation_core("is_pod")
    is_pol = gi.get_relation_core("is_pol")
    selected_by_pol = gi.get_relation_core("selected_by_pol")
    ingress_allow_by_pol = gi.get_relation_core("ingress_allow_by_pol")
    egress_allow_by_pol = gi.get_relation_core("egress_allow_by_pol")

    policy_conflict = Function('policy_conflict', gi.pol_sort, gi.pol_sort, BoolSort())
    gi.register_relation("policy_conflict", policy_conflict, is_core=True)
    policy_inconflict = Function('policy_inconflict', gi.pol_sort, gi.pol_sort, BoolSort())
    gi.register_relation("policy_inconflict", policy_inconflict, is_core=True)


    p0 = gi.declare_var('policy_conflict_inner', gi.pol_sort)
    p1 = gi.declare_var('policy_conflict_outer', gi.pol_sort)

    select = gi.declare_var('policy_conflict_select', gi.pod_sort)

    gi.add_rule(policy_inconflict(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        selected_by_pol(select, p0),
        selected_by_pol(select, p1)
    ])
    gi.add_rule(policy_inconflict(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        ingress_allow_by_pol(select, p0),
        ingress_allow_by_pol(select, p1)
    ])
    gi.add_rule(policy_inconflict(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        is_pod(select),
        egress_allow_by_pol(select, p0),
        egress_allow_by_pol(select, p1)
    ])

    gi.add_rule(policy_conflict(p0, p1), [
        is_pol(p0),
        is_pol(p1),
        p0 != p1,
        Not(policy_inconflict(p0, p1))        
    ])

    fact = [policy_conflict(p0, p1)]
    sat, answer = get_answer(gi.fp, fact)
    if sat == z3.unsat:
        return sat, []
    
    return sat, parse_z3_result(answer)
