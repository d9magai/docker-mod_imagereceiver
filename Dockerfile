FROM centos
MAINTAINER d9magai

RUN yum update -y && yum install -y epel-release && yum clean all
RUN yum update -y && yum install -y \
    gcc-c++ \
    make \
    httpd-devel \
    apr-util-mysql \
    && yum clean all

COPY mod_dbd_test.conf  /etc/httpd/conf.d/mod_dbd_test.conf
COPY src /opt/dbd_test_build
WORKDIR /opt/dbd_test_build
RUN make && apxs -A -i -a -n 'dbd_test' mod_dbd_test.so && make clean

EXPOSE 80
CMD ["/usr/sbin/httpd", "-D", "FOREGROUND"] 

