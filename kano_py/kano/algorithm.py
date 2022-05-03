from .model import *


def all_reachable(matrix: ReachabilityMatrix) -> List[int]:
    all_reachables = set()
    for i in range(matrix.container_size):
        if matrix.getcol(i).count() == matrix.container_size:
            all_reachables.add(i)
    return all_reachables


def all_isolated(matrix: ReachabilityMatrix) -> List[int]:
    all_isolated = set()
    for i in range(matrix.container_size):
        if matrix.getcol(i).count() == 0:
            all_isolated.add(i)
    return all_isolated


def user_hashmap(containers: List[Container], label: str) -> Dict[str, bitarray]:
    user_map: Dict[str, bitarray] = DefaultDict(lambda: bitarray('0' * len(containers)))
    for i, container in enumerate(containers):
        user_map[container.getValueOrDefault(label, "")][i] = True
    return user_map


def user_crosscheck(
        matrix: ReachabilityMatrix, 
        containers: List[Container],
        label: str) -> List[int]:
    """
    User cross. 
    A container can be reached from other user’s container in the container network
    """
    user_crosslist = set()
    user_map = user_hashmap(containers, label)
    for i, container in enumerate(containers):
        diff_set = ~ user_map[container.getValueOrDefault(label, "")]
        diff_set &= matrix.getcol(i)
        if diff_set.count() != 0:
            user_crosslist.add(i)
    return user_crosslist


def system_isolation(matrix: ReachabilityMatrix, idx: int) -> List[int]:
    """
    System isolation. 
    A container is isolated with certain container, usually the kube-system container
    """
    isolations = set()
    reachable = matrix.getrow(idx)
    for i in range(matrix.container_size):
        if not reachable[i]:
            isolations.add(i)
    return isolations


def policy_shadow(matrix: ReachabilityMatrix, policies: List[Policy], containers: List[Container]) -> List[Tuple[int, int]]:
    """
    Policy shadow. 
    The connections built by a policy are completely covered by another policy, then this policy may be redundant
    FIXME: this algorithm doesn't seem to be sound (and also described wrongly with conflict!)
    For Pa selects (0, 1), allows (2, 3) and Pb selects (1, 2), allows (3), it add a non-shadowed pair (Pa, Pb)
    Otherwise, it assumes the select group won't have non-subset intersections
    """
    m = len(policies)
    pols = set()
    for i, container in enumerate(containers):
        i_select = container.select_policies
        for j in i_select:
            for k in i_select:
                pj = policies[j]
                pk = policies[k]

                if j == k:
                    continue
                j_allow = pj.working_allow_set
                k_allow = pk.working_allow_set
                if ((j_allow & k_allow) ^ k_allow).count() == 0:
                    pols.add((j, k))
    return pols


def policy_conflict(matrix: ReachabilityMatrix, policies: List[Policy], containers: List[Container]) -> List[Tuple[int, int]]:
    """
    Policy conflict. 
    The connections built by a policy are totally contradict the connections built by another    
    """
    m = len(policies)
    pols = set()
    for i, container in enumerate(containers):
        i_select = container.select_policies
        for j in i_select:
            for k in i_select:
                pj = policies[j]
                pk = policies[k]

                if j == k:
                    continue
                j_disallow = ~ pj.working_allow_set
                k_allow = pk.working_allow_set
                if ((j_disallow & k_allow) ^ k_allow).count() == 0:
                    pols.add((j, k))
    return pols
