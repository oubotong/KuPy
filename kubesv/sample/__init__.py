from z3 import BoolRef, BitVecRef
from .example import paper_example

def setup_z3_printer():
    from z3 import z3printer
    z3printer._Formatter.max_depth = 10000
    z3printer._Formatter.max_args = 100000
    z3printer._Formatter.max_visited = 1000000
    z3printer._PP.max_width = 200
    z3printer._PP.bounded = False
    z3printer._PP.max_lines = 1000000
