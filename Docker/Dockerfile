FROM python:3.8-alpine3.12

RUN apk update && \
	apk add --no-cache --upgrade bash\
    	openssl-dev \
		libffi-dev \
		libc-dev \
        gcc \
		rust \
        cargo \
        wget

RUN pip install -U pyamiibo

WORKDIR /data

COPY script.sh /usr/local/bin/prepare-amiibo
RUN chmod +x /usr/local/bin/prepare-amiibo

ENTRYPOINT [ "prepare-amiibo" ]

