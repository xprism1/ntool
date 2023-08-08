#!/usr/bin/python3
import sys
from utils import *

if sys.argv[1] in ['srl_retail2dev', 'cia_dev2retail', 'cia_retail2dev', 'cci_dev2retail', 'cci_retail2dev', 'csu2retailcias']:
    path = sys.argv[2]
    out = ''
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
    eval(sys.argv[1])(path, out)

elif sys.argv[1] in ['ncch_extractall', 'ncch_rebuildall', 'cci_extractall', 'cci_rebuildall', 'cia_extractall', 'cia_rebuildall']:
    path = sys.argv[2]
    dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--dev':
            dev = 1
    eval(sys.argv[1])(path, dev)

elif sys.argv[1] == 'cci2cia':
    path = sys.argv[2]
    out = ''
    cci_dev = cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--cci-dev':
            cci_dev = 1
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cci2cia(path, out, cci_dev, cia_dev)

elif sys.argv[1] == 'cdn2cia':
    path = sys.argv[2]
    out = ''
    title_ver = ''
    cdn_dev = cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--title-ver':
            title_ver = sys.argv[i + 1]
        elif sys.argv[i] == '--cdn-dev':
            cdn_dev = 1
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cdn2cia(path, out, title_ver, cdn_dev, cia_dev)

elif sys.argv[1] == 'cia2cdn':
    path = sys.argv[2]
    out = ''
    titlekey = ''
    cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--titlekey':
            titlekey = sys.argv[i + 1]
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cia2cdn(path, out, titlekey, cia_dev)