FROM d9magai/awssdkcpp
MAINTAINER d9magai

ENV OPENCV_PREFIX /opt/opencv
ENV OPENCV_SRC_DIR $OPENCV_PREFIX/src
ENV OPENCV_VERSION 3.0.0
ENV OPENCV_ARCHIVE_URL https://github.com/Itseez/opencv/archive/$OPENCV_VERSION.tar.gz

RUN yum update -y && yum install -y \
    make \
    cmake \
    gcc-c++ \
    && yum clean all

RUN mkdir -p $OPENCV_SRC_DIR \
    && curl -sL $OPENCV_ARCHIVE_URL | tar xz -C $OPENCV_SRC_DIR \
    && cd $OPENCV_SRC_DIR/opencv-$OPENCV_VERSION \
    && cmake . \
       -DCMAKE_INSTALL_PREFIX=$OPENCV_PREFIX \
       -DBUILD_DOCS=OFF \
       -DBUILD_EXAMPLES=OFF \
       -DBUILD_TESTS=OFF \
       -DBUILD_PERF_TESTS=OFF \
       -DBUILD_WITH_DEBUG_INFO=OFF \
    && make -s \
    && make -s install \
    && rm -rf $OPENCV_SRC_DIR

RUN echo "$OPENCV_PREFIX/lib" > /etc/ld.so.conf.d/opencv.conf && ldconfig
ENV PKG_CONFIG_PATH $OPENCV_PREFIX/lib/pkgconfig/:$PKG_CONFIG_PATH

RUN yum update -y && yum install -y epel-release && yum clean all
RUN yum update -y && yum install -y \
    httpd-devel \
    libapreq2-devel \
    && yum clean all

COPY mod_imagereceiver.conf  /etc/httpd/conf.d/mod_imagereceiver.conf
COPY form.html /var/www/html/form.html

COPY src /opt/imagereceiver_build
WORKDIR /opt/imagereceiver_build
RUN make && apxs -A -i -a -n 'imagereceiver' mod_imagereceiver.so && make clean

EXPOSE 80
CMD ["/usr/sbin/httpd", "-D", "FOREGROUND"] 

