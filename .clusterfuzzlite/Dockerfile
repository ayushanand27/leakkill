FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:58f80c90a90944b68b8e70b98e38997ee9396225311cfb0f3aea78671446ab4e
COPY . $SRC/leakkill
WORKDIR $SRC/leakkill
COPY .clusterfuzzlite/build.sh $SRC/
