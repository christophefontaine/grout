#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

grcli interface add port p0 devargs net_null0,no-rx=1
grcli interface add port p1 devargs net_null1,no-rx=1
grcli nexthop add l3 iface p0 id 1 address 1.2.3.4
grcli nexthop add l3 iface p1 id 2 address 1.2.3.5
grcli nexthop add group id 10 member 1 weight 3 member 2 weight 4
grcli nexthop internal
#read
grcli nexthop del 1
grcli nexthop internal
#read
grcli nexthop del 2
grcli nexthop internal
#read
grcli interface del p0
grcli interface del p1
