FROM python:2
MAINTAINER Cat'Killer <catkiller@catkiller.org>

RUN pip install twisted

WORKDIR /app

COPY config.py /app/config.py
COPY phxd /app/phxd
COPY server /app/server
COPY shared /app/shared
COPY support /app/support
COPY configure_phxd.py /app/configure_phxd.py

EXPOSE 5500/tcp

RUN [ "python", "configure_phxd.py" ]
CMD [ "python", "phxd" ]
