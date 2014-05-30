#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate trace/generated-helpers.c.
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2014, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import out
from tracetool.transform import *


def generate(events, backend):
    events = [e for e in events
              if "disable" not in e.properties]

    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        '#include "qemu-common.h"',
        '#include "trace.h"',
        '#include "exec/helper-proto.h"',
        '',
        )

    for e in events:
        if "tcg-exec" not in e.properties:
            continue

        # tracetool.generate always transforms types to host
        e_args = e.original.args

        values = ["(%s)%s" % (t, n)
                  for t, n in e.args.transform(TCG_2_TCG_HELPER_DEF)]

        out('void %(name_tcg)s(%(args)s)',
            '{',
            '    %(name)s(%(values)s);',
            '}',
            name_tcg="helper_%s_proxy" % e.api(),
            name=e.api(),
            args=e_args.transform(HOST_2_TCG_COMPAT, TCG_2_TCG_HELPER_DEF),
            values=", ".join(values),
            )
