#!/usr/bin/env python

import re

results = {}

def read_results(filename):
    file = open(filename,'r')
    lines = file.readlines()
    for line in lines:
        v = re.split(',|:',line.strip())
        val = results.get(v[0],[])
        val.append(v[-1])
        results[v[0]] = val
        #print(v[0])
        #print(v[-1])

read_results("chez.txt")
read_results("loko.txt")
read_results("gambit.txt")
read_results("hawk.txt")
def test_num(t):
    try:
        return float(t)
    except ValueError:
        return 0.0
for result in results:
    if len(results[result]) !=4:
        print("ERROR")
    print("makechart(\'{}\', {});").format(result, map(test_num,results[result]))
