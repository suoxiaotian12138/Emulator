# -*- coding: utf-8 -*-
"""The ``sphinxmix`` package implements the Sphinx mix packet format core cryptographic functions.

The paper describing sphinx may be found here:

    * George Danezis and Ian Goldberg. Sphinx: A Compact and Provably Secure Mix Format. IEEE Symposium on Security and Privacy 2009. [`link <http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf>`_]


All the ``sphinxmix`` cryptography is encapsulated and within a ``SphinxParams`` object that 
is used by all subsequent functions. To make ``sphinxmix`` use different cryptographic 
primitives simply extend this class, or re-implement it. The default cryptographic primitives 
are ``NIST/SEGS-p224`` curves, ``AES`` and ``SHA256``.

Sending Sphinx messages
-----------------------

To package or process sphinx messages create a new ``SphinxParams`` object:

    >>> # Instantiate a the crypto parameters for Sphinx.
    >>> from sphinxmix.SphinxParams import SphinxParams
    >>> params = SphinxParams()

The ``sphinxmix`` package requires some rudimentary Public Key Information: mix nodes need
an identifier created by ``Nenc`` and the PKI consists of a dictionary mapping node names
to ``pki_entry`` records. Those include secret keys (derived using ``gensecret``) and public 
keys (derived using ``expon``).

    >>> # The minimal PKI involves names of nodes and keys
    >>> from sphinxmix.SphinxClient import pki_entry, Nenc
    >>> pkiPriv = {}
    >>> pkiPub = {}
    >>> for i in range(10):
    ...     nid = i
    ...     x = params.group.gensecret()
    ...     y = params.group.expon(params.group.g, [ x ])
    ...     pkiPriv[nid] = pki_entry(nid, x, y)
    ...     pkiPub[nid] = pki_entry(nid, None, y)

A client may package a message using the Sphinx format to relay over a number of mix servers. 
The function ``rand_subset`` may be used to select a random number of node identifiers; the function
``create_forward_message`` can then be used to package the message, ready to be sent to the 
first mix. Note both destination and message need to be ``bytes``.

    >>> # The simplest path selection algorithm and message packaging
    >>> from sphinxmix.SphinxClient import rand_subset, \\
    ...                                    create_forward_message
    >>> use_nodes = rand_subset(pkiPub.keys(), 5)
    >>> nodes_routing = list(map(Nenc, use_nodes))
    >>> keys_nodes = [pkiPub[n].y for n in use_nodes]
    >>> dest = b"bob"
    >>> message = b"this is a test"
    >>> header, delta = create_forward_message(params, nodes_routing, \\
    ...     keys_nodes, dest, message)

The client may specify any information in the ``nodes_routing`` list, that will
be passed to intermediate mixes. At a minimum this should include information about 
the next mix.

Processing Sphinx messages at a mix
-----------------------------------

The heart of a Sphinx mix server is the ``sphinx_process`` function, that takes the server
secret and decodes incoming messages. In this example the message encode above, is decoded
by the sequence of mixes.

    >>> # Process message by the sequence of mixes
    >>> from sphinxmix.SphinxClient import PFdecode, Relay_flag, Dest_flag, Surb_flag, receive_forward
    >>> from sphinxmix.SphinxNode import sphinx_process
    >>> x = pkiPriv[use_nodes[0]].x
    >>> while True:
    ...     ret = sphinx_process(params, x, header, delta)
    ...     (tag, info, (header, delta), mac_key) = ret
    ...     routing = PFdecode(params, info)
    ...     if routing[0] == Relay_flag:
    ...         flag, addr = routing
    ...         x = pkiPriv[addr].x 
    ...     elif routing[0] == Dest_flag:
    ...         assert receive_forward(params, mac_key, delta) == [dest, message]
    ...         break

It is the responsibility of a mix to record ``tags`` of messages to prevent 
replay attacks. The ``PFdecode`` function may be used to recover routing Information
including the next mix, or any other user specified information.

Single use reply Blocks
-----------------------

A facility provided by Sphinx is the creation and use of Single Use Reply Blocks (SURB)
to route messages back to an anonymous receipient. First a receiver needs to create
a SURB using ``create_surb`` and passes on the ``nymtuple`` structure to the sender, and
storing ``surbkeytuple`` keyed by the identifier ``surbid``:

    >>> from sphinxmix.SphinxClient import create_surb, package_surb
    >>> surbid, surbkeytuple, nymtuple = create_surb(params, nodes_routing, keys_nodes, b"myself")

Using the ``nymtuple`` a sender can package a message to be sent through the network, 
starting at the ``nymtuple[0]`` router:

    >>> message = b"This is a reply"
    >>> header, delta = package_surb(params, nymtuple, message)

The network processes the SURB as any other message, until it is received 
by the last mix in the path:

    >>> x = pkiPriv[use_nodes[0]].x
    >>> while True:
    ...    ret = sphinx_process(params, x, header, delta)
    ...    (tag, B, (header, delta), mac_key) = ret
    ...    routing = PFdecode(params, B)
    ...
    ...    if routing[0] == Relay_flag:
    ...        flag, addr = routing
    ...        x = pkiPriv[addr].x 
    ...    elif routing[0] == Surb_flag:
    ...        flag, dest, myid = routing
    ...        break

The final mix server must sent the ``myid`` and ``delta`` to the destination
``dest``, where it may be decoded using the ``surbkeytuple``.

    >>> from sphinxmix.SphinxClient import receive_surb
    >>> received = receive_surb(params, surbkeytuple, delta)
    >>> assert received == message

Embedding arbitrary information for mixes
-----------------------------------------

A sender may embed arbitrary information to mix nodes, as demonstrated 
by embedding ``b'info'`` to each mix, and ``b'final_info'`` to the final 
mix:

    >>> use_nodes = rand_subset(pkiPub.keys(), 5)
    >>> nodes_routing = [Nenc((n, b'info')) for n in use_nodes]
    >>> keys_nodes = [pkiPub[n].y for n in use_nodes]
    >>> dest = (b"bob", b"final_info")
    >>> message = b"this is a test"
    >>> header, delta = create_forward_message(params, nodes_routing, \\
    ...     keys_nodes, dest, message)

Mixes decode the arbitrary structure passed by the clients, and can interpret
it to implement more complex mixing strategies:

    >>> x = pkiPriv[use_nodes[0]].x
    >>> while True:
    ...     ret = sphinx_process(params, x, header, delta)
    ...     (tag, info, (header, delta), mac_key) = ret
    ...     routing = PFdecode(params, info)
    ...     if routing[0] == Relay_flag:
    ...         flag, (addr, additional_info) = routing
    ...         assert additional_info == b'info'
    ...         x = pkiPriv[addr].x 
    ...     elif routing[0] == Dest_flag:
    ...         [[dest, additional_info], msg] = receive_forward(params, mac_key, delta)
    ...         assert additional_info == b'final_info'
    ...         assert dest == b'bob'
    ...         break


Packaging mix messages to byte strings:
---------------------------------------

The `sphinxmix` package provides functions `pack_message` and `unpack_message` to 
serialize and deserialize mix messages using `msgpack`. Some meta-data about the 
parameter length are passed along the message any may be used to select an appropriate
parameter environment for the decoding of the message.

    >>> from sphinxmix.SphinxClient import pack_message, unpack_message
    >>> bin_message = pack_message(params, (header, delta))
    >>> param_dict = { (params.max_len, params.m):params }
    >>> px, (header1, delta1) = unpack_message(param_dict, bin_message)


"""

VERSION = "0.0.7"

class SphinxException(Exception):
    pass