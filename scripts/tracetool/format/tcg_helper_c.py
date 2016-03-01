#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate trace/generated-helpers.c.
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2016, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import Arguments, out
from tracetool.transform import *
import tracetool.vcpu


def vcpu_transform_args(args, mode):
    assert len(args) == 1
    # NOTE: this name must be kept in sync with the one in "tcg_h"
    args = Arguments([(args.types()[0], "__tcg_" + args.names()[0])])
    if mode == "code":
        return Arguments([
            # Does cast from helper requirements to tracing types
            ("CPUState *", "ENV_GET_CPU(%s)" % args.names()[0]),
        ])
    else:
        args = Arguments([
            # NOTE: Current helper code uses TCGv_env (CPUArchState*)
            ("CPUArchState *", args.names()[0]),
        ])
        if mode == "header":
            return args
        elif mode == "wrapper":
            return args.transform(HOST_2_TCG)
        else:
            assert False


def generate(events, backend):
    events = [e for e in events
              if "disable" not in e.properties]

    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        '#include "qemu/osdep.h"',
        '#include "qemu-common.h"',
        '#include "trace.h"',
        '#include "exec/helper-proto.h"',
        '',
        )

    for e in events:
        if "tcg-exec" not in e.properties:
            continue

        e_args_api = tracetool.vcpu.transform_args(
            "tcg_helper_c", e.original, "header").transform(
                HOST_2_TCG_COMPAT, TCG_2_TCG_HELPER_DEF)
        e_args_call = tracetool.vcpu.transform_args(
            "tcg_helper_c", e, "code")

        out('void %(name_tcg)s(%(args_api)s)',
            '{',
            '    %(name)s(%(args_call)s);',
            '}',
            name_tcg="helper_%s_proxy" % e.api(),
            name=e.api(),
            args_api=e_args_api,
            args_call=", ".join(e_args_call.casted()),
            )
