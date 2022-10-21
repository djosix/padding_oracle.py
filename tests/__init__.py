import sys
import os


def get_src_dir():
    current_dir = os.path.dirname(__file__)
    src_dir = os.path.join(current_dir, '..', 'src')
    return src_dir


sys.path.insert(0, get_src_dir())
