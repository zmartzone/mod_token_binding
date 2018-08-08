FROM ubuntu:16.04
MAINTAINER hans.zandbelt@zmartzone.eu

RUN apt-get clean && apt-get --fix-missing update
RUN apt-get update && apt-get install -y apt-utils build-essential autoconf automake libtool-bin
RUN apt-get update && apt-get install -y git subversion wget
RUN apt-get update && apt-get install -y python libpcre3-dev libexpat1-dev
RUN apt-get update && apt-get install -y pkg-config

WORKDIR /root
ENV TARGET_DIR /usr/local

RUN mkdir mod_token_binding
COPY . mod_token_binding/

#
# OpenSSL 1.1.x patched with Google's token_bind custom_ext_resume.patch
#
ENV OPENSSL_VERSION 1.1.0h

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
RUN tar zxvf openssl-${OPENSSL_VERSION}.tar.gz
RUN cd openssl-${OPENSSL_VERSION} && patch -p1 < ../mod_token_binding/openssl-custom_ext_resume.patch
RUN cd openssl-${OPENSSL_VERSION} && ./config --prefix=${TARGET_DIR} && make && make install_sw

#
# Apache HTTPd 2.4.x >= 2.4.26 for OpenSSL 1.1.x support
#
ENV HTTPD_VERSION    2.4.34
ENV APR_VERSION      1.6.3
ENV APR_UTIL_VERSION 1.6.1

RUN wget http://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.gz && tar zxvf httpd-${HTTPD_VERSION}.tar.gz
RUN cd httpd-${HTTPD_VERSION}/srclib/ && wget http://archive.apache.org/dist/apr/apr-${APR_VERSION}.tar.gz && tar zxvf apr-${APR_VERSION}.tar.gz && ln -s apr-${APR_VERSION} apr
RUN cd httpd-${HTTPD_VERSION}/srclib/ && wget http://archive.apache.org/dist/apr/apr-util-${APR_UTIL_VERSION}.tar.gz && tar zxvf apr-util-${APR_UTIL_VERSION}.tar.gz && ln -s apr-util-${APR_UTIL_VERSION} apr-util
RUN cd httpd-${HTTPD_VERSION} && ./buildconf && ./configure --enable-ssl=shared --with-ssl=${TARGET_DIR} --prefix=${TARGET_DIR} --with-included-apr && make install

#
# Google's token_bind library with a patch to expose the negotiated version function
#
RUN git clone https://github.com/zmartzone/token_bind.git
RUN cd token_bind && git checkout expose-negotiated-version

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
