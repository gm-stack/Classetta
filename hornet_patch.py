#!/usr/bin/env python3

@macrt.hook("math_Abs16", phase="replace")
def abs16(h):
    print(f"!!! abs16 {h}")
    return abs(h.args[0])
