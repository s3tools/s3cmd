ARG pyVersion=latest
FROM python:${pyVersion}
ARG pyVersion
RUN addgroup testuser \
  && adduser \
     --home /home/testuser \
     --ingroup testuser \
     --disabled-password \
     --gecos "" \
     testuser

USER testuser
RUN mkdir /home/testuser/src
WORKDIR /home/testuser/src
COPY --chown=testuser ./ s3cmd
COPY --chown=testuser .s3cfg /home/testuser/
USER root
WORKDIR /home/testuser/src/s3cmd
RUN pip install .
USER testuser

ENTRYPOINT ["python","run-tests.py"]

RUN echo Built with Python version $(python --version)
