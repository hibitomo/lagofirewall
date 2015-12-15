#!/bin/bash

cd `dirname $0`
ryu-manager --config-file ./ryu/tester.ryu.conf ./ryu/fw_tester.py --test-switch-dir ./tests --test-switch-target 2 --test-switch-tester 3

