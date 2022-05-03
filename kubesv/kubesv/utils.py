from z3 import *
from typing import *
from typing_extensions import *


def parse_z3_var_assignment(assign):
    idx = get_var_index(assign.arg(0))
    num = assign.arg(1).as_long()
    return idx, num


def parse_z3_and_var(assigns):
    results = []
    for i in range(assigns.num_args()):
        assign = assigns.arg(i)
        results.append(parse_z3_var_assignment(assign))
    return results


def parse_z3_or_and(answer: BoolRef) -> Set[Tuple[int, ...]]:
    # assume the answer is Or(And(Var0, Var1, ...), ...)
    all_answer = None
    
    if is_eq(answer):
        return parse_z3_var_assignment(answer)

    if is_and(answer):
        all_answer = [-1 for _ in range(answer.num_args())]
        for i in range(answer.num_args()):
            assign = answer.arg(i)
            idx, num = parse_z3_or_and(assign)
            all_answer[idx] = num
    elif is_or(answer):
        all_answer = set()
        for i in range(answer.num_args()):
            assigns = answer.arg(i)
            result = parse_z3_or_and(assigns)
            if isinstance(result, tuple):
                all_answer.add(result[1])
            else:
                all_answer.add(tuple(result))

    return all_answer


def parse_z3_result(answer: BoolRef):
    result = parse_z3_or_and(answer)
    if isinstance(result, list):
        return {tuple(result)}
    elif isinstance(result, tuple):
        return {result[1]}
    return result