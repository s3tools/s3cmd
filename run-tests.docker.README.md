# Running test cases with Docker
## (The  markdown formatting in this file is best viewed on Github)

### tl;dr

* Place a valid .s3cfg file in the root project directory.
* `docker build -t s3cmd-tests --build-arg pyVersion=3.6 -f run-tests.dockerfile .`  
Note the trailing period and substitute your desired Python version as needed.
* `docker run --rm s3cmd-tests`

### More Details

The included run-tests.dockerfile allows contributors to easily test their changes with Python versions that aren't installed locally.

Docker must, of course, be installed on your system if it is not already. See https://docs.docker.com/install/ for instructions.

To begin, build the Dockerfile into an image for the Python version you wish to test against.  The build must be repeated whenever your source changes, but the Python image itself will be cached.  To build:

* Place a valid .s3cfg file in the root project directory.  While .s3cfg has been added to the .gitignore to avoid sending your credentials to public repositories, you should still make sure you remove it when your testing is complete.

* Run `docker build -t s3cmd-tests -f run-tests.dockerfile .` (the trailing period is required)

  This will:

  * Download the latest Python Docker image
  * Add a testuser group and account
  * Copy the .s3cfg into the user's home directory (/home/testuser)
  * Copy the entire project folder into /home/testuser/src/s3cmd
  * Install s3cmd dependencies (as root)

The main purpose of this Dockerfile is to allow you to run with multiple Python versions.  To see the Docker Python images available, visit [Docker Hub](https://hub.docker.com/_/python).  Most of the Linux variants should be usable, but the "alpine" variants will result in the smallest downloads and images.  For example:

`docker build -t s3cmd-tests --build-arg pyVersion=3.8.1-alpine3.11 -f run-tests.dockerfile .`

After successfully building the image, you can run it with `docker run --rm s3cmd-tests`.  This will execute the run-tests.py script in the Docker container with your .s3cfg credentials.

Normal `run-tests.py` options may appended.  For example:

`docker run --rm s3cmd-tests --bucket-prefix mytests`

Additional notes:

* If you would like to enter a shell in the container, use `docker run -i -t --rm --entrypoint sh s3cmd-tests`.
  * `bash` may be specified if you are using a Python image that supports it (not Alpine).
* If it has been a few days since your last usage, you should check for updates to the upstream Python docker image using `docker pull python` or `docker pull python:3.7` (substituting your desired version)
* Rebuilding does not over-write a previous image, but instead creates a new image and "untags" the previous one.  Use `docker images` to show all the images on your system, and `docker image prune` to cleanup unused, untagged images.  Please use this command carefully if you have other Docker images on your system.
* When testing is completed, remove unused Python images with `docker rmi python:3.7`, substituting the tag/version you wish to remove. `docker images` will list the images on your system.
