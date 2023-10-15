FROM python:3.12.0-slim-bookworm
WORKDIR /app

COPY requirements.txt /app

RUN pip install -r requirements.txt

COPY config.py /app/config.py
COPY phxd /app/phxd
COPY server /app/server
COPY shared /app/shared
COPY support /app/support
COPY configure_phxd.py /app/configure_phxd.py

EXPOSE 5500/tcp

RUN [ "python", "configure_phxd.py" ]
CMD [ "python", "phxd" ]
