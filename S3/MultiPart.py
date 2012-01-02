## Amazon S3 Multipart upload support
## Author: Jerome Leclanche <jerome.leclanche@gmail.com>
## License: GPL Version 2

from Queue import Queue
from threading import Thread
from logging import debug, info, warning, error
from Utils import getTextFromXml

class Worker(Thread):
    """
    Thread executing tasks from a given tasks queue
    """
    def __init__(self, tasks):
        super(Worker, self).__init__()
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            func(*args, **kargs)
            self.tasks.task_done()

class ThreadPool(object):
    """
    Pool of threads consuming tasks from a queue
    """
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """
        Add a task to the queue
        """
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """
        Wait for completion of all the tasks in the queue
        """
        self.tasks.join()

class MultiPartUpload(object):

    MAX_CHUNK_SIZE = 5368709120 # 5GB
    MAX_CHUNKS = 100

    def __init__(self, s3, file, uri):
        self.s3 = s3
        self.file = file
        self.uri = uri
        self.upload_id = None
        self.parts = {}

    def initiate_multipart_upload(self):
        """
        Begin a multipart upload
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadInitiate.html
        """
        request = self.s3.create_request("OBJECT_POST", uri = self.uri, extra = "?uploads")
        response = self.s3.send_request(request)
        data = response["data"]
        s3, key, upload_id = getTextFromXml(data, "Bucket"), getTextFromXml(data, "Key"), getTextFromXml(data, "UploadId")
        self.upload_id = upload_id
        return s3, key, upload_id

    def upload_all_parts(self, num_threads, chunk_size):
        """
        Execute a full multipart upload on a file
        Returns the id/etag dict
        TODO use num_processes to thread it
        """
        if not self.upload_id:
            raise RuntimeError("Attempting to use a multipart upload that has not been initiated.")

        id = 1
        if num_threads > 1:
            debug("MultiPart: Uploading in %d threads" % num_threads)
            pool = ThreadPool(num_threads)
        else:
            debug("MultiPart: Uploading in a single thread")

        while True:
            if id == self.MAX_CHUNKS:
                data = self.file.read(-1)
            else:
                data = self.file.read(chunk_size)
            if not data:
                break
            if num_threads > 1:
                pool.add_task(self.upload_part, data, id)
            else:
                self.upload_part(data, id)
            id += 1

        if num_threads > 1:
            debug("Thread pool with %i threads and %i tasks awaiting completion." % (num_threads, id))
            pool.wait_completion()

    def upload_part(self, data, id):
        """
        Upload a file chunk
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadUploadPart.html
        """
        # TODO implement Content-MD5
        content_length = str(len(data))
        debug("Uploading part %i of %r (%s bytes)" % (id, self.upload_id, content_length))
        headers = { "Content-Length": content_length }
        query_string = "?partNumber=%i&uploadId=%s" % (id, self.upload_id)
        request = self.s3.create_request("OBJECT_PUT", uri = self.uri, headers = headers, extra = query_string)
        response = self.s3.send_request(request, body = data)

        self.parts[id] = response["headers"]["etag"]

    def complete_multipart_upload(self):
        """
        Finish a multipart upload
        http://docs.amazonwebservices.com/AmazonS3/latest/API/index.html?mpUploadComplete.html
        """
        parts_xml = []
        part_xml = "<Part><PartNumber>%i</PartNumber><ETag>%s</ETag></Part>"
        for id, etag in self.parts.items():
            parts_xml.append(part_xml % (id, etag))
        body = "<CompleteMultipartUpload>%s</CompleteMultipartUpload>" % ("".join(parts_xml))

        headers = { "Content-Length": len(body) }
        request = self.s3.create_request("OBJECT_POST", uri = self.uri, headers = headers, extra = "?uploadId=%s" % (self.upload_id))
        response = self.s3.send_request(request, body = body)

        return response

# vim:et:ts=4:sts=4:ai
