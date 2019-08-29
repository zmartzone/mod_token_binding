FROM ubuntu:bionic
MAINTAINER hans.zandbelt@zmartzone.eu

RUN apt-get clean && apt-get --fix-missing update
RUN apt-get update && apt-get install -y apt-utils build-essential autoconf automake libtool-bin
RUN apt-get install -y wget pkg-config git subversion python
RUN apt-get install -y libssl-dev libpcre3-dev libexpat1-dev

WORKDIR /root
ENV TARGET_DIR /usr/local

RUN mkdir mod_token_binding
COPY . mod_token_binding/

#
# Apache HTTPd 2.4.x >= 2.4.26 for OpenSSL 1.1.x support
# need Apache sources for mod_ssl_openssl.h
#
ENV HTTPD_VERSION    2.4.41
ENV APR_VERSION      1.7.0
ENV APR_UTIL_VERSION 1.6.1

RUN wget http://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.gz && tar zxvf httpd-${HTTPD_VERSION}.tar.gz
RUN cd httpd-${HTTPD_VERSION}/srclib/ && wget http://archive.apache.org/dist/apr/apr-${APR_VERSION}.tar.gz && tar zxvf apr-${APR_VERSION}.tar.gz && ln -s apr-${APR_VERSION} apr
RUN cd httpd-${HTTPD_VERSION}/srclib/ && wget http://archive.apache.org/dist/apr/apr-util-${APR_UTIL_VERSION}.tar.gz && tar zxvf apr-util-${APR_UTIL_VERSION}.tar.gz && ln -s apr-util-${APR_UTIL_VERSION} apr-util
RUN cd httpd-${HTTPD_VERSION} && ./buildconf && ./configure --enable-ssl=shared --with-ssl=${TARGET_DIR} --prefix=${TARGET_DIR} --with-included-apr && make install

#RUN LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/apache2
#RUN apt-get update && apt-get install -y apache2 apache2-dev

#
# Google's token_bind library with a patch to expose the negotiated version function
#
ENV TOKEN_BIND_TAG v0.1.1

RUN git clone https://github.com/zmartzone/token_bind.git
RUN cd token_bind && git checkout -b ${TOKEN_BIND_TAG} ${TOKEN_BIND_TAG}

#
# mod_token_binding
#
#RUN git clone https://github.com/zmartzone/mod_token_binding.git
RUN cd mod_token_binding && ./autogen.sh && ./configure --with-token-binding=/root/token_bind --with-apxs2=${TARGET_DIR}/bin/apxs && make && make install

#
# web server configuration
#
RUN  if [ -f mod_token_binding/test/docker/server.crt ] ; then cp mod_token_binding/test/docker/server.crt ${TARGET_DIR}/conf/ && cp mod_token_binding/test/docker/server.key ${TARGET_DIR}/conf/; else cd ${TARGET_DIR}/conf/ && /usr/bin/openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj '/CN=localhost'; fi
COPY test/docker/httpd.conf ${TARGET_DIR}/conf/
COPY test/docker/httpd-ssl.conf ${TARGET_DIR}/conf/extra/
