## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import os, os.path
import errno
import random
import pickle

class S3fs(object):
	_sync_attrs = [ "tree" ]

	## These are instance variables - we must
	## catch when they are used uninitialized
	###   _object_name = ...
	###  fsname = ...
	###  tree = ...

	def __init__(self, fsname = None):
		self.n = S3fsObjectName()
		if fsname:
			self.openfs(fsname)

	def mkfs(self, fsname):
		self.fsname = fsname
		self._object_name = self.n.fs(fsname)
		if self.object_exists(self._object_name):
			raise S3fsError("Filesystem '%s' already exists" % fsname, errno.EEXIST)
		root_inode = S3fsInode(self)
		S3fsSync.store(self, root_inode)
		self.tree = { "/" : root_inode.inode_id }
		S3fsSync.store(self, self)
		self.openfs(fsname)
	
	def openfs(self, fsname):
		self.fsname = fsname
		self._object_name = self.n.fs(fsname)
		if not self.object_exists(self._object_name):
			raise S3fsError("Filesystem '%s' does not exist" % fsname, errno.ENOENT)
		S3fsSync.load(self, self)
		print self.tree

	def syncfs(self):
		S3fsSync.store(self, self)
	
	def get_inode(self, path):
		inode_id = self.tree[path]
		inode = S3fsInode(self, inode_id)
		return inode

class S3fsInode(object):
	_fs = None

	## Interface for S3fsSync
	_sync_attrs = [ "properties" ]
	# _object_name = 

	## Properties
	inode_id = None
	properties = {
		"ctime" : 0,
		"mtime" : 0,
		"uid" : 0,
		"gid" : 0,
		"mode" : 0,
	}

	def __init__(self, fs, inode_id = None):
		if not inode_id:
			inode_id = fs.n.rndstr(10)
		self.inode_id = inode_id
		self._object_name = fs.n.inode(fs.fsname, inode_id)
		self._fs = fs
		S3fsSync.try_load(self._fs, self)

	def setprop(self, property, value):
		self.assert_property_name(property)
		self.properties[property] = value
		return value
	
	def getprop(self, property):
		self.assert_property_name(property)
		return self.properties[property]
	
	def assert_property_name(self, property):
		if not self.properties.has_key(property):
			raise ValueError("Property '%s' not known to S3fsInode")

class S3fsLocalDir(S3fs):
	def __init__(self, directory, fsname = None):
		if not os.path.isdir(directory):
			raise IOError("Directory %s does not exist" % directory, errno.ENOENT)
		self._dir = directory

		## SubClass must be set to go before calling parent constructor!
		S3fs.__init__(self, fsname)
	
	def object_exists(self, object_name):
		real_path = os.path.join(self._dir, object_name)
		if os.path.isfile(real_path):	## Is file, all good
			return True
		if os.path.exists(real_path):	## Exists but is not file!
			raise S3fsError("Object %s (%s) is not a regular file" % (object_name, real_path), errno.EINVAL)
		return False

	def object_write(self, object_name, contents):
		real_path = os.path.join(self._dir, object_name)
		f = open(real_path, "wb")
		f.write(contents)
		f.close()

	def object_read(self, object_name):
		real_path = os.path.join(self._dir, object_name)
		f = open(real_path, "rb")
		contents = f.read()
		f.close()
		return contents

class S3fsObjectName(object):
	_rnd_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	_rnd_chars_len = len(_rnd_chars)

	def __init__(self):
		random.seed()

	def rndstr(self, len):
		retval = ""
		while len > 0:
			retval += self._rnd_chars[random.randint(0, self._rnd_chars_len-1)]
			len -= 1
		return retval

	def fs(self, fsname):
		return "fs-%s" % fsname

	def inode(self, fsname, inode_id):
		return "%s-i-%s" % (fsname, inode_id)
	
class S3fsSync(object):
	@staticmethod
	def store(fs, instance, object_name = None):
		if not object_name:
			object_name = instance._object_name
		to_sync = {}
		for attr in instance._sync_attrs:
			if hasattr(instance, attr):
				to_sync[attr] = getattr(instance, attr)
		fs.object_write(object_name, pickle.dumps(to_sync))
		print "Stored object: %s" % (object_name)

	@staticmethod
	def load(fs, instance, object_name = None):
		if not object_name:
			object_name = instance._object_name
		from_sync = pickle.loads(fs.object_read(object_name))
		for attr in instance._sync_attrs:
			if from_sync.has_key(attr):
				setattr(instance, attr, from_sync[attr])
		print "Loaded object: %s" % (object_name)

	@staticmethod
	def try_load(fs, instance, object_name = None):
		if not object_name:
			object_name = instance._object_name
		if fs.object_exists(object_name):
			S3fsSync.load(fs, instance, object_name)
		else:
			print "Nonexist object: %s" % (object_name)

class S3fsError(Exception):
	def __init__(self, message, errno = -1):
		Exception.__init__(self, message)
		self.errno = errno
	
if __name__ == "__main__":
	local_dir = "/tmp/s3fs"
	fsname = "testFs"
	if not os.path.isdir(local_dir):
		os.mkdir(local_dir)

	try:
		fs = S3fsLocalDir(local_dir, fsname)
		print "Filesystem '%s' opened." % fsname
	except S3fsError, e:
		if e.errno == errno.ENOENT:
			print "Filesystem %s does not exist -> mkfs()" % fsname
			fs = S3fsLocalDir(local_dir)
			fs.mkfs(fsname)
		else:
			raise
	root_inode = fs.get_inode("/")
	print "root_inode(%s).mode = 0%o" % (root_inode.inode_id, root_inode.getprop("mode"))
	if root_inode.getprop("mode") == 0:
		root_inode.setprop("mode", 0755)
	S3fsSync.store(fs, root_inode)
