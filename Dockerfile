FROM d9magai/opencv
MAINTAINER d9magai

RUN yum update -y && yum install -y epel-release && yum clean all
RUN yum update -y && yum install -y \
    httpd-devel \
    libapreq2-devel \
    json-c-devel \
    && yum clean all

COPY mod_imagereceiver.conf  /etc/httpd/conf.d/mod_imagereceiver.conf
COPY form.html /var/www/html/form.html

COPY src /opt/imagereceiver_build
WORKDIR /opt/imagereceiver_build
RUN make && apxs -A -i -a -n 'imagereceiver' mod_imagereceiver.so && make clean

EXPOSE 80
ENTRYPOINT ["/usr/sbin/httpd"]
CMD ["-D", "FOREGROUND"]

