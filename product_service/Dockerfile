FROM ubuntu
ENV TZ=Europe/Moscow
RUN apt-get clean && apt-get update -y 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata git sudo build-essential autoconf libtool libssl-dev zlib1g-dev librdkafka-dev pkg-config cmake gcc git g++ mysql-client libmysqlclient-dev libboost-all-dev libssl-dev && apt-get clean
RUN git clone -b master https://github.com/pocoproject/poco.git && cd poco && mkdir cmake-build && cd cmake-build && cmake .. && make -j2 && sudo make install && cd .. && cd ..
RUN sudo ldconfig
run git clone https://github.com/blackSunRiseE/hl_mai_lab_01.git
RUN cd ./hl_mai_lab_01 && mkdir build && cd build && cmake  .. && make product_service
ENTRYPOINT [ "hl_mai_lab_01/build/product_service" ]