# -*- coding: utf-8 -*-

"""
Generate trace/generated-helpers.h.
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2016, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@redhat.com"


from tracetool import out
from tracetool.transform import *
import tracetool.vcpu


def generate(events, backend, group):
    events = [e for e in events
              if "disable" not in e.properties]

    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        )

    for e in events:
        if "tcg-exec" not in e.properties:
            continue

        # TCG helper proxy declaration
        fmt = "DEF_HELPER_FLAGS_%(argc)d(%(name)s, %(flags)svoid%(types)s)"
        e_args = tracetool.vcpu.transform_args("tcg_helper_c", e.original, "header")
        args = e_args.transform(HOST_2_TCG_COMPAT, HOST_2_TCG,
                                TCG_2_TCG_HELPER_DECL)
        types = ", ".join(args.types())
        if types != "":
            types = ", " + types

        flags = "TCG_CALL_NO_RWG, "

        out(fmt,
            flags=flags,
            argc=len(args),
            name=e.api() + "_proxy",
            types=types,
            )
