FROM ubuntu:16.04
MAINTAINER hans.zandbelt@zmartzone.eu

RUN apt-get clean && apt-get --fix-missing update
RUN apt-get update && apt-get install -y apt-utils build-essential autoconf automake libtool-bin
RUN apt-get update && apt-get install -y git subversion wget
RUN apt-get update && apt-get install -y python libpcre3-dev libexpat1-dev
RUN apt-get update && apt-get install -y pkg-config

WORKDIR /root
ENV TARGET_DIR /usr/local

#
# OpenSSL 1.1.x
#
ENV OPENSSL_VERSION 1.1.0g

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
RUN tar zxvf openssl-${OPENSSL_VERSION}.tar.gz
RUN cd openssl-${OPENSSL_VERSION} && wget -O - https://raw.githubusercontent.com/zmartzone/token_bind/master/example/custom_ext_resume.patch | patch -p1
RUN cd openssl-${OPENSSL_VERSION} && ./config --prefix=${TARGET_DIR} && make && make install_sw

#
# Apache HTTPd 2.4.x patched for token binding support in mod_ssl
#
ENV HTTPD_VERSION 2.4.29

RUN wget http://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.gz
RUN tar zxvf httpd-${HTTPD_VERSION}.tar.gz
RUN cd httpd-${HTTPD_VERSION}/srclib/ && svn co http://svn.apache.org/repos/asf/apr/apr/branches/1.6.x apr 
RUN cd httpd-${HTTPD_VERSION}/srclib/ && svn co http://svn.apache.org/repos/asf/apr/apr-util/branches/1.6.x apr-util
RUN cd httpd-${HTTPD_VERSION} && wget -O - https://raw.githubusercontent.com/zmartzone/mod_token_binding/master/httpd-mod_ssl-token-binding-extension.patch | patch -p1
RUN cd httpd-${HTTPD_VERSION} && ./buildconf && ./configure --enable-ssl=shared --with-ssl=${TARGET_DIR} --prefix=${TARGET_DIR} --with-included-apr && make install

#
# mod_token_binding
#
RUN git clone https://github.com/zmartzone/token_bind.git
RUN cd token_bind && git checkout expose-negotiated-version
RUN git clone https://github.com/zmartzone/mod_token_binding.git
RUN cd mod_token_binding && ./autogen.sh && ./configure --with-token-binding=/root/token_bind --with-apxs2=${TARGET_DIR}/bin/apxs && make install

#
# web server configuration
#
RUN cd ${TARGET_DIR}/conf/ && /usr/bin/openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj '/CN=localhost'
COPY httpd.conf ${TARGET_DIR}/conf/
COPY httpd-ssl.conf ${TARGET_DIR}/conf/extra/
