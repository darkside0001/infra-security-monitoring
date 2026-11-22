# "Outside attacker" view: runs on the edge network only, like a client on the
# Internet. Ships the author's own tools web-sec-check and nmap-report.
# (Port scans use the instrumentisto/nmap image, see scripts/verify.sh.)
FROM python:3.13-alpine
RUN pip install --no-cache-dir \
      "https://github.com/darkside0001/web-sec-check/archive/refs/heads/main.tar.gz" \
      "https://github.com/darkside0001/nmap-report/archive/refs/heads/main.tar.gz"
COPY probe.py /usr/local/bin/probe.py
