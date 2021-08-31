# -*- coding: utf-8 -*-

from __future__ import absolute_import

try:
    # python 3 support
    import cPickle as pickle
except ImportError:
    import pickle
from .Utils import deunicodise

class HashCache(object):
    def __init__(self):
        self.inodes = dict()

    def add(self, dev, inode, mtime, size, md5):
        if dev == 0 or inode == 0: return # Windows
        if dev not in self.inodes:
            self.inodes[dev] = dict()
        if inode not in self.inodes[dev]:
            self.inodes[dev][inode] = dict()
        self.inodes[dev][inode][mtime] = dict(md5=md5, size=size)

    def md5(self, dev, inode, mtime, size):
        try:
            d = self.inodes[dev][inode][mtime]
            if d['size'] != size:
                return None
        except Exception:
            return None
        return d['md5']

    def mark_all_for_purge(self):
        for d in tuple(self.inodes):
            for i in tuple(self.inodes[d]):
                for c in tuple(self.inodes[d][i]):
                    self.inodes[d][i][c]['purge'] = True

    def unmark_for_purge(self, dev, inode, mtime, size):
        try:
            d = self.inodes[dev][inode][mtime]
        except KeyError:
            return
        if d['size'] == size and 'purge' in d:
            del self.inodes[dev][inode][mtime]['purge']

    def purge(self):
        for d in tuple(self.inodes):
            for i in tuple(self.inodes[d]):
                for m in tuple(self.inodes[d][i]):
                    if 'purge' in self.inodes[d][i][m]:
                        del self.inodes[d][i]
                        break

    def save(self, f):
        d = dict(inodes=self.inodes, version=1)
        with open(deunicodise(f), 'wb') as fp:
            pickle.dump(d, fp)

    def load(self, f):
        with open(deunicodise(f), 'rb') as fp:
            d = pickle.load(fp)
        if d.get('version') == 1 and 'inodes' in d:
            self.inodes = d['inodes']
