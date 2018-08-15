import yaml
import json
import os
import sys
import collections
from io import open
import script


def main():
    xmlfile = open("sysmonout.xml", "r", encoding='utf-8', errors='ignore')
    contents = xmlfile.read()
    script.run_script(contents)


if __name__ == '__main__':
    main()
