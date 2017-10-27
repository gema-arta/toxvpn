FROM ubuntu:16.04

RUN apt-get update && apt-get install -y -qq  apt-transport-https wget lsb-release
RUN echo "deb https://pkg.tox.chat/debian stable $(lsb_release -cs)" | tee /etc/apt/sources.list.d/tox.list
RUN wget -qO - https://pkg.tox.chat/debian/pkg.gpg.key | apt-key add -
RUN apt-get update -qq && apt-get install -y -qq git libcap-dev libnl-route-3-dev libnl-3-dev libjansson-dev libsodium-dev libtox-dev gcc-5 g++-5 make