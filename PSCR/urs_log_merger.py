#!/usr/bin/env python3
"""urs_log_merger.py"""

import subprocess
import sys

# cat urs-ue-ogs-10ue.res urs-gnb-ogs-10ue.res > urs-all-ogs-10ue.log

def main():
    if len (sys.argv) < 3:
        print ("Usage: sys.argv.[0] <ue_log_prefix> <gbn_log_prefix> <all_log_prefix> <largest num>")
        return 1

    ue_log_prefix = sys.argv[1]
    gbn_log_prefix = sys.argv[2]
    all_log_prefix = sys.argv[3]
    largest_num = int(sys.argv[4])

    num = 1
    cmd = 'cat '+ue_log_prefix+num+'ue.res '+gbn_log_prefix+num+'ue.res > '+all_log_prefix+num+'ue.log'
    returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
    print('returned value:', returned_value)

    # count = largest_num / 5
    # for i in range(0, count):
    #     num = (i+1) * 5
    #     cmd = 'cat '+ue_log_prefix+num+'ue.res '+gbn_log_prefix+num+'ue.res > '+all_log_prefix+num+'ue.log'
    #     returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
    #     print('returned value:', returned_value)

    cmd = 'ls *.log'
    returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
    print('returned value:', returned_value)


if __name__ == "__main__":
    main()
