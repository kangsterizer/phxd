FROM python:2-alpine
MAINTAINER Cat'Killer <catkiller@catkiller.org>

# The "exec" plugins are all written in bash and won't
# work with bourne. Install bash to ensure they work.
RUN apk add --no-cache bash

# gcc and other build tools not in alpine. Add them as virtual packages, build Twisted and delete them.
RUN apk add --no-cache --virtual .build-deps gcc musl-dev
RUN pip install --upgrade pip
RUN pip install typing
RUN pip install twisted
RUN apk del .build-deps

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
