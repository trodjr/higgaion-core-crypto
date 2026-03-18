FROM gcr.io/oss-fuzz-base/base-builder@sha256:67a869a73d8ef15ef3852682e44885d2fa55fde2df97ae95f86ae09b0f9764c9
RUN apt-get update && apt-get install -y make cmake
COPY . $SRC/higgaion-core-crypto
WORKDIR $SRC/higgaion-core-crypto
COPY .clusterfuzzlite/build.sh $SRC/
