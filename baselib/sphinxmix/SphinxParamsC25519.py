#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
#
# This file is part of sphinxmix.
# 
# sphinxmix is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# sphinxmix is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with sphinxmix.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The LIONESS implementation and the xcounter CTR mode class are adapted
# from "Experimental implementation of the sphinx cryptographic mix
# packet format by George Danezis".


from os import urandom
from hashlib import sha256
import hmac



# Python 2/3 compatibility
from builtins import bytes

from nacl.bindings import crypto_scalarmult_base, crypto_scalarmult

def _expand32(K):
    return (K+b"\x00"*32)[:32]

class Group_C25519:
    "Group operations using Curve 25519"

    def __init__(self):
        pass

    def gensecret(self):
        return urandom(32)

    def expon(self, base, exp):        
        for f in exp:
            base = crypto_scalarmult(_expand32(f), base)
        return base

    def expon_base(self, exp):
        assert len(exp) > 0
        base = crypto_scalarmult_base(_expand32(exp[0]))   
        for f in exp[1:]:
            base = crypto_scalarmult(_expand32(f), base)
        return base


    def makeexp(self, data):
        return data[:32]

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        return len(alpha) == 32

    def printable(self, alpha):
        return alpha

def test_commut():
    G = Group_C25519()
    x0, x1, x2 = [G.gensecret() for _ in range(3) ]
    x2 = x2[:16]

    assert G.expon_base([x0, x1, x2]) == G.expon_base([x2, x1, x0])

    assert G.expon_base([x0, x1, x2]) == G.expon( G.expon_base([x0, x1]), [ x2 ])
    assert G.expon_base([x0, x2]) == G.expon( G.expon_base([x0]), [ x2 ])