#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
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


from os import urandom
from collections import namedtuple
from struct import pack

from tools.Serialization import encode, decode


from .SphinxParams import SphinxParams
from . import SphinxException

from .SphinxClient import Relay_flag, Dest_flag, Surb_flag, pki_entry
from .SphinxClient import pad_body, unpad_body
from .SphinxClient import Nenc, Route_pack, PFdecode, rand_subset
from .SphinxClient import pack_message, unpack_message


ultrix_hdr_record = namedtuple("ultrix_hdr_record", ["alpha", "s", "b", "aes", "hrho", "hmu", "htau"])


def create_header(params, nodelist, keys, assoc=None, secrets = None, gamma=None, dest_key = None):
    """ Internal function, creating a Ultrix header.""" 

    p = params
    max_len = p.max_len
    group = p.group

    node_meta = [pack("b", len(n)) + n for n in nodelist]
    nodelist = nodelist[:-1] # remove the final destination.
    nu = len(nodelist)

    if not params.assoc_len > 0:
        assoc = [b''] * len(nodelist)
    else:
        assert assoc != None

    assert len(assoc) == len(nodelist)
    for assoc_data in assoc:
        assert len(assoc_data) == params.assoc_len
    
    # Accept external secrets too -- derandomize 
    blind_factors = secrets
    if not secrets:
        x = group.gensecret()
        blind_factors = [ x ]

    if not gamma:
        gamma = urandom(16)

    if not dest_key:
        dest_key = urandom(p.k)

    asbtuples = []
    
    alpha0 = group.expon_base(blind_factors[-1:])
    for k in keys:
        alpha = alpha0
        s = group.expon(k, blind_factors)
        aes_s = p.get_aes_key(s)
        (hrho, hmu, htau, b_factor) = p.derive_user_keys(k=aes_s, iv = b"_master_________", number = 4)
        b = p.group.makeexp(b_factor)

        #b = p.hb(aes_s)
        blind_factors += [ b ] 

        hr = ultrix_hdr_record(alpha, s, b, aes_s, hrho, hmu, htau)
        asbtuples.append(hr)

        alpha0 = group.expon(alpha0, [b])

    # Compute the filler strings
    phi = b''
    min_len = (max_len - 32)
    for i in range(1,nu):

        plain = phi + (b"\x00" * (len(node_meta[i])))
        phi = p.xor_rho(asbtuples[i-1].hrho, (b"\x00"*min_len)+plain)
        phi = phi[min_len:]

        min_len -= len(node_meta[i])        
    
    assert len(phi) == sum(map(len, node_meta[1:-1]))

    # Compute the (beta, gamma) tuples
    len_meta = sum(map(len, node_meta[1:]))
    random_pad_len = (max_len - 32) - len_meta
    
    if random_pad_len < 0:
        raise SphinxException("Insufficient space routing info: missing %s bytes" % (abs(random_pad_len))) 

    beta = node_meta[-1] + urandom(random_pad_len)
    beta = p.xor_rho(asbtuples[nu-1].hrho, beta) + phi

    beta_all = [ beta ]
    for i in range(nu-2, -1, -1):
        assert len(beta) == (max_len - 32)
        node_id = node_meta[i+1]

        plain_beta_len = (max_len - 32) - len(node_id)

        plain = node_id + beta[:plain_beta_len]
        beta = p.xor_rho(asbtuples[i].hrho, plain)
        beta_all = [ beta ] + beta_all
        assert len(beta) == (max_len - 32)

    # Compute the cummulative MAC.

    original_gamma = gamma
    root_keys = []
    new_keys = []
    for beta_i, k, assoc_data in zip(beta_all, asbtuples, assoc):
        xgamma = gamma
        round_mac_key = k.hmu
        inner_mac = p.mu(round_mac_key, assoc_data + xgamma + beta_i)

        root_K, body_K, gamma = p.derive_user_keys(inner_mac, b"_fragile________", 3)

        root_keys += [ root_K ]
        new_keys += [ body_K ]

    # Encrypt the dest key
    assert len(root_keys) == len(asbtuples)
    for gK in reversed(root_keys):
        dest_key = p.small_perm_inv(gK, dest_key)

    assert len(beta) == (max_len - 32)
    return (asbtuples[0].alpha, beta, original_gamma, dest_key), new_keys
        

def create_forward_message(params, nodelist, keys, dest, msg, assoc=None):
    """Creates a forward Sphix message, ready to be processed by a first mix. 

    It takes as parameters a node list of mix information, that will be provided to each mix, forming the path of the message;
    a list of public keys of all intermediate mixes; a destination and a message; and optinally an array of associated data (byte arrays)."""

    assert len(dest) <= params.dest_len

    p = params
    nu = len(nodelist)
    assert 0 < len(dest) < 128
    assert p.k + 1 + len(dest) + len(msg) < p.m

    # Compute the header and the secrets
    dest_key = urandom(16)
    dest_inner_key = params.derive_key(dest_key, b"dest_inner______")
    body_inner_key = params.derive_key(dest_key, b"body_inner______")

    # TODO: Encure that changing the body destroys the dest_key.

    enc_dest = p.xor_rho(dest_inner_key, dest)
    assert len(enc_dest) == len(dest)

    final = [ Route_pack((Dest_flag, enc_dest)) ]
    header, secrets = create_header(params, nodelist + final, keys, assoc, dest_key = dest_key)

    payload = pad_body(p.m - p.k, encode(msg))
    mac = p.mu(secrets[nu-1], payload)
    body =  mac + payload

    # Compute the delta values
    delta = p.pi(body_inner_key, body)
    delta = p.aes_cbc_dec(secrets[nu-1], delta)
    for i in range(nu-2, -1, -1):
        delta = p.aes_cbc_dec(secrets[i], delta)
        
    return header, delta

def create_surb(params, nodelist, keys, dest, assoc=None):
    """Creates a Ultrix single use reply block (SURB) using a set of parameters;
    a sequence of mix identifiers; a pki mapping names of mixes to keys; and a final 
    destination. An array of associated data, for each mix on the path, may optionally
    be passed in.

    Returns:
        - A triplet (surbid, surbkeytuple, nymtuple). Where the surbid can be 
          used as an index to store the secrets surbkeytuple; nymtuple is the actual
          SURB that needs to be sent to the receiver.

    """
    p = params
    nu = len(nodelist)
    xid = urandom(p.k)

    # Compute the header and the secrets

    enc_dest = params.xor_rho(xid, dest)

    final = [ Route_pack((Surb_flag, enc_dest)) ]
    header, secrets = create_header(params, nodelist + final, keys, assoc, dest_key = xid )

    ktilde = urandom(p.k)
    keytuple = [ktilde]
    keytuple.extend( secrets)
    return xid, keytuple, (nodelist[0], header, ktilde)

def package_surb(params, nymtuple, message):
    """Packages a message to be sent with a SURB. The message has to be bytes, 
    and the nymtuple is the structure returned by the create_surb call.

    Returns a header and a body to pass to the first mix.
    """
    n0, header0, ktilde = nymtuple

    message = pad_body(params.m - params.k, message)
    mac = params.mu(ktilde, message)
    body = params.xor_rho(ktilde, mac + message )
    return (header0, body)


def receive_forward(params, header, mac_key, routing, delta):
    """ Decodes the body of a forward message, and checks its MAC tag."""
    
    _, _, _, dest_key = header
    _, dest = routing

    dest_inner_key = params.derive_key(dest_key, b"dest_inner______")
    body_inner_key = params.derive_key(dest_key, b"body_inner______")

    # TODO: Encure that changing the body destroys the dest_key.

    dest = params.xor_rho(dest_inner_key, dest)
    delta = params.pii(body_inner_key, delta)

    if delta[:params.k] != params.mu(mac_key, delta[params.k:]):
        raise SphinxException("Modified Body")

    delta = unpad_body(delta[params.k:])
    return dest, decode(delta)

def receive_surb(params, keytuple, delta): 
    """Processes a SURB body to extract the reply. The keytuple was provided at the time of 
    SURB creation, and can be indexed by the SURB id, which is also returned to the receiving user.

    Returns the decoded message.
    """
    p = params
        
    ktilde = keytuple.pop(0)
    nu = len(keytuple)
    for i in range(nu-1, -1, -1):
        delta = p.aes_cbc_dec(keytuple[i], delta)
    delta = p.xor_rho(ktilde, delta)

    if delta[:p.k] == p.mu(ktilde, delta[p.k:]):
        msg = unpad_body(delta[p.k:])
    else:
        raise SphinxException("Modified SURB Body")
    
    return msg

def decode_surb(params, header, enc_dest):
    """ Decode the destination address of the SURB. """
    (_, _, _, xid) = header
    dest = params.xor_rho(xid, enc_dest)
    return dest    

# TESTS

from nacl.bindings import crypto_scalarmult_base


def profile_ultrix_c25519(rep=100, payload_size=1024 * 10):
    r = 5

    from .SphinxParamsC25519 import Group_C25519
    from .UltrixNode import ultrix_process

    group = Group_C25519()
    params = SphinxParams(group=group, header_len = 32+50, body_len=payload_size, assoc_len=4)

    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i)
        x = params.group.gensecret()
        y = crypto_scalarmult_base(x)
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)


    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]

    assoc = [b"XXXX"] * len(nodes_routing)

    import time
    ta = time.time()

    
    t0 = time.time()
    for _ in range(rep):
        header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test", assoc)
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/rep))
    

    t0 = time.time()
    for _ in range(rep):
        x = pkiPriv[use_nodes[0]].x
        ultrix_process(params, x, header, delta, b"XXXX")
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/rep))

    tb = time.time()

    print("Total (for %d repeats): %.2fms" % (rep, (tb-ta)*1000.0))

def test_ultrix_c25519(rep=100, payload_size=1024 * 10):
    r = 5
    from .SphinxParamsC25519 import Group_C25519
    
    group = Group_C25519()
    params = SphinxParams(group=group, header_len = 32+50, body_len=payload_size, assoc_len=4)

    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i)
        x = params.group.gensecret()
        y = crypto_scalarmult_base(x)
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)


    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    assoc = [b"XXXX"] * len(nodes_routing)
    
    print()
    import time
    t0 = time.time()
    for _ in range(rep):
        header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test", assoc)
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/rep))
    T_package = (t1-t0)/rep

    from .UltrixNode import ultrix_process

    t0 = time.time()
    for _ in range(rep):
        x = pkiPriv[use_nodes[0]].x
        ultrix_process(params, x, header, delta, b"XXXX")
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/rep))
    T_process = (t1-t0)/rep

    return T_package, T_process

def test_minimal_ultrix():
    r = 5
    params = SphinxParams(header_len = 32+4*8+32, assoc_len=4)

    # The minimal PKI involves names of nodes and keys
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i) # Nenc(params, bytes([i]))
        x = params.group.gensecret()
        y = params.group.expon(params.group.g, [ x ])
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)

    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    dest = b"bob"
    message = b"this is a test"
    X = [b'A', b'B', b'C', b'D', b'E'] * 2
    assoc = [b"XXX" + X[i] for i in range( len(nodes_routing) )]

    assoc_copy = assoc[:]


    header, delta = create_forward_message(params, nodes_routing, node_keys, dest, message, assoc=assoc)
    
    # Test encoding and decoding

    bin_message = pack_message(params, (header, delta))
    param_dict = { (params.max_len, params.m):params }

    px, (header1, delta1) = unpack_message(param_dict, bin_message)
    assert px == params
    assert header == tuple(header1)
    assert delta == delta1

    # Process message by the sequence of mixes
    from .UltrixNode import ultrix_process
    x = pkiPriv[use_nodes[0]].x

    i = 0
    while True:
        assoc_data = assoc_copy.pop(0)

        ret = ultrix_process(params, x, header, delta, assoc=assoc_data)
        (tag, B, (header, delta), mac_key) = ret
        routing = PFdecode(params, B)

        print("round %d" % i)
        i += 1

        # print("Type: %s" % typex)
        if routing[0] == Relay_flag:
            addr = routing[1]
            x = pkiPriv[addr].x 
        elif routing[0] == Dest_flag:
            assert len(routing) == 2
            # assert delta[:16] == b"\x00" * params.k
            dec_dest, dec_msg = receive_forward(params, header, mac_key, routing, delta)
            assert dec_dest == dest
            assert dec_msg == message

            break
        else:
            print("Error")
            assert False
            break

    # Test the nym creation
    surbid, surbkeytuple, nymtuple = create_surb(params, nodes_routing, node_keys, b"myself", assoc=assoc)
    
    message = b"This is a reply"
    header, delta = package_surb(params, nymtuple, message)

    x = pkiPriv[use_nodes[0]].x
    assoc_copy = assoc[:]

    while True:
        assoc_data = assoc_copy.pop(0)

        ret = ultrix_process(params, x, header, delta, assoc=assoc_data)
        (tag, B, (header, delta), mac_key) = ret
        routing = PFdecode(params, B)

        if routing[0] == Relay_flag:
            flag, addr = routing
            x = pkiPriv[addr].x 
        elif routing[0] == Surb_flag:
            flag, dest = routing
            dest = decode_surb(params, header, dest)
            assert dest == b"myself"            
            myid = header[-1]
            assert myid == surbid
            break

    received = receive_surb(params, surbkeytuple, delta)
    assert received == message
