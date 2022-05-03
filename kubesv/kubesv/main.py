from z3 import *

if __name__ == "__main__":
    fp = Fixedpoint()
    fp_options = {
        "ctrl_c": True,
        "engine": "datalog",
        "datalog.generate_explanations": False,
    }
    fp.set(**fp_options)
    fp.help()

    s = BitVecSort(3)
    label = Function('label', s, BoolSort())
    is_vec = Function('is_vec', s, BoolSort())
    not_labeled = Function('not_labeled', s, BoolSort())
    a = Const('a', s)

    fp.register_relation(label, is_vec, not_labeled)
    fp.declare_var(a)
    fp.rule(not_labeled(a), And(*[
        is_vec(a),
        Not(label(a))
    ]))

    v1 = BitVecVal(1, s)
    v2 = BitVecVal(2, s)
    v3 = BitVecVal(3, s)

    fp.fact(is_vec(v1))
    fp.fact(is_vec(v2))
    fp.fact(is_vec(v3))
    fp.fact(label(v1))

    print(fp.to_string([not_labeled(a)]))
    print(fp.query([not_labeled(a)]))
    print(fp.get_answer())
