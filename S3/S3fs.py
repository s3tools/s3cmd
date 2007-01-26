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
	fsname = None
	tree = None
	def __init__(self, fsname = None):
		self.n = S3fsObjectName()
		if fsname:
			self.openfs(fsname)

	def mkfs(self, fsname):
		self._object_name = self.n.fs(fsname)
		if self.object_exists(self._object_name):
			raise S3fsError("Filesystem already exists", errno.EEXIST)
		self.fsname = fsname
		root_inode = S3fsInode(self)
		S3fsSync.store(self, root_inode)
		self.tree = { "/" : root_inode.inode_id }
		S3fsSync.store(self, self)
	
	def openfs(self, fsname):
		raise S3fsError("Not implemented", errno.ENOSYS)
	
class S3fsInode(object):
	_fs = None

	## Interface for S3fsSync
	_sync_attrs = [ "properties" ]
	_object_name = None

	## Properties
	inode_id = None
	properties = {
		"ctime" : None,
		"mtime" : None,
		"uid" : None,
		"gid" : None,
		"mode" : None,
	}

	def __init__(self, fs, inode_id = None):
		if not inode_id:
			inode_id = fs.n.rndstr(10)
		self.inode_id = inode_id
		self._object_name = fs.n.inode(fs.fsname, inode_id)
		self._fs = fs

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
	def __init__(self, directory):
		S3fs.__init__(self)
		if not os.path.isdir(directory):
			raise S3fsError("Directory %s does not exist" % directory, errno.ENOENT)
		self._dir = directory
	
	def lock(self):
		pass

	def unlock(self):
		pass

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
			if from_sync.has_key[attr]:
				setattr(instance, attr, from_sync[attr])
		print "Loaded object: %s" % (object_name)

class S3fsError(Exception):
	def __init__(self, message, errno = -1):
		Exception.__init__(self, message)
		self.errno = errno
	
if __name__ == "__main__":
	local_dir = "/tmp/s3fs"
	try:
		fs = S3fsLocalDir(local_dir)
	except S3fsError, e:
		if e.errno == errno.ENOENT:
			os.mkdir(local_dir)
		else:
			raise
	print "RandomStrings = %s %s" % (fs.n.rndstr(5), fs.n.rndstr(10))

	fs.mkfs("testFs")
