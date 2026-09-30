# Throw-away image the platform uses to prove a lab network is isolated. It contains only Python
# and the probe script and runs unprivileged like every lab container.
FROM python:3.12-alpine
COPY probe.py /opt/probe/probe.py
USER 10001:10001
ENTRYPOINT ["python", "/opt/probe/probe.py"]
