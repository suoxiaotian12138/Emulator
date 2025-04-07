#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2017 George Danezis (UCL InfoSec Group)
#
# This file is part of Sphinx.
# 
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.


from . import SphinxException

_master = b"_master_________"
_fragile = b"_fragile________"

# Core Process function -- devoid of any chrome
def ultrix_process(params, secret, header, delta, assoc=b''):
    """ The heart of a Ultrix server, that processes incoming messages.
    It takes a set of parameters, the secret of the server,
    and an incoming message header and body. Optinally some Associated
    data may also be passed in to check their integrity.
        
    """
    p = params
    alpha, beta, gamma, dest_key = header
    
    if params.assoc_len != len(assoc):
        raise SphinxException("Associated data length mismatch: expected %s and got %s." % (params.assoc_len, len(assoc)))

    # Check that alpha is in the group
    if not p.group.in_group(alpha):
        raise SphinxException("Alpha not in Group.")

    # Compute the shared secret
    s = p.group.expon(alpha, [ secret ])
    aes_s = p.get_aes_key(s)
    (header_enc_key, round_mac_key, tag, b_factor) = p.derive_user_keys(k=aes_s, iv = _master, number = 4)
    b = p.group.makeexp(b_factor)

    assert len(beta) == p.max_len - 32

    # Compute the secrets based on the header too
    inner_mac = p.mu(round_mac_key, assoc + gamma + beta)
    root_K, body_K, gamma = p.derive_user_keys(k=inner_mac, iv = _fragile, number = 3)

    # Decrypt the header
    beta_pad = beta + p.zero_pad
    B = p.xor_rho(header_enc_key, beta_pad)

    length = B[0]
    routing = B[1:1+length]
    rest = B[1+length:]

    # Recode the alpha and beta
    alpha = p.group.expon(alpha, [ b ])
    beta = rest[:(p.max_len - 32)]

    # Decode the delta
    dest_key = p.small_perm(root_K, dest_key)
    delta = p.aes_cbc_enc(body_K, delta)

    # Package packet and keys
    ret = (tag, routing, ((alpha, beta, gamma, dest_key), delta), body_K)
    return ret

