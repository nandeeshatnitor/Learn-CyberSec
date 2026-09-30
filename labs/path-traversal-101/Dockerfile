# DELIBERATELY VULNERABLE teaching application. Built locally, never pulled, never deployed
# anywhere except inside an isolated lab container.
FROM python:3.12-alpine
COPY app/server.py /opt/lab/app/server.py
COPY docs/ /opt/lab/docs/
COPY start.sh restart.sh /opt/lab/
RUN chmod 0755 /opt/lab/start.sh /opt/lab/restart.sh
# The lab user has no home directory contents and no shell history; the platform overrides the
# user with the same numeric ids at run time as well.
RUN addgroup -g 10001 lab && adduser -D -u 10001 -G lab -h /lab lab
USER 10001:10001
WORKDIR /lab
