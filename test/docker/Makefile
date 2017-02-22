TARGET_DIR=/usr/local
TAG=tokenbinding
HTTP_PORT=8080
HTTPS_PORT=4433

all: build run

build:
	docker build -t $(TAG) .

run:
	docker run -p $(HTTP_PORT):$(HTTP_PORT) -p $(HTTPS_PORT):$(HTTPS_PORT) -it $(TAG) /bin/bash -c "$(TARGET_DIR)/bin/apachectl start && tail -f $(TARGET_DIR)/logs/error_log"
