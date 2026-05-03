FROM python:3.12.0-slim-bookworm
WORKDIR /app

# Disable stdout/stderr buffering so ``docker logs`` shows server output
# in real time. Without this, prints/log-stream messages can sit in the
# buffer indefinitely and the container looks silent.
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app

RUN pip install -r requirements.txt

COPY config.py /app/config.py
COPY phxd /app/phxd
COPY server /app/server
COPY shared /app/shared
COPY support /app/support
COPY configure_phxd.py /app/configure_phxd.py

# 5500 = control connection (HLServer); 5501 = file transfer port
# (HLFileServer binds to SERVER_PORT + 1). Both must be published with
# `-p` at `docker run` time, otherwise downloads fail with
# "Failed to connect for file transfer: Connection refused".
EXPOSE 5500/tcp
EXPOSE 5501/tcp

RUN [ "python", "configure_phxd.py" ]
CMD [ "python", "phxd" ]
