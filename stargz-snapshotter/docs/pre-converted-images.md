# Trying pre-converted images

We have several pre-converted stargz images on Github Container Registry (`ghcr.io/stargz-containers`), mainly for benchmarking purpose.
This document lists them.

:information_source: You can build eStargz from Dockerfile using BuildKit, [using Docker Buildx](../README.md#building-estargz-images-using-buildkit) or [Kaniko](../README.md#building-estargz-images-using-kaniko).

:information_source: You can convert arbitrary images into eStargz optimized for your workload, using [`ctr-remote` command](/docs/ctr-remote.md).

:information_source: You can convert arbitrary images into eStargz on the registry-side, using [`estargz.kontain.me`](https://estargz.kontain.me).

## Pre-converted images

:information_source: You can request new pre-converted images from our CI repository ([`github.com/stargz-containers/image-ci`](https://github.com/stargz-containers/image-ci)).

In the following table, image names listed in `Image Name` contain the following suffixes based on the type of the image.

- `org`: Legacy image copied from `docker.io/library` without optimization. Layers are normal tarballs.
- `esgz`: eStargz-formatted version of the `org` images. `ctr-remote images optimize` command is used for the optimization.

`Optimized Workload` column describes workloads used for building `esgz` images. We optimized these images for benchmarking which is based on [HelloBench](https://github.com/Tintri/hello-bench) so we specified "hello-world"-like workloads for the command. See [benchmarking script](/script/benchmark/hello-bench/src/hello.py) for the exact command option specified for `ctr-remote images optimize`. 

|Image Name|Optimized Workload|
---|---
|`ghcr.io/stargz-containers/alpine:3.15.3-org`|Executing `echo hello` on the shell|
|`ghcr.io/stargz-containers/alpine:3.15.3-esgz`|Executing `echo hello` on the shell|
|`ghcr.io/stargz-containers/drupal:9.3.9-org`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/drupal:9.3.9-esgz`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/fedora:35-org`|Executing `echo hello` on the shell|
|`ghcr.io/stargz-containers/fedora:35-esgz`|Executing `echo hello` on the shell|
|`ghcr.io/stargz-containers/gcc:11.2.0-org`|Compiling and executing a program which prints `hello`|
|`ghcr.io/stargz-containers/gcc:11.2.0-esgz`|Compiling and executing a program which prints `hello`|
|`ghcr.io/stargz-containers/golang:1.18-org`|Compiling and executing a program which prints `hello`|
|`ghcr.io/stargz-containers/golang:1.18-esgz`|Compiling and executing a program which prints `hello`|
|`ghcr.io/stargz-containers/jenkins:2.60.3-org`|Code execution until up and ready message (`Jenkins is fully up and running`) is printed|
|`ghcr.io/stargz-containers/jenkins:2.60.3-esgz`|Code execution until up and ready message (`Jenkins is fully up and running`) is printed|
|`ghcr.io/stargz-containers/jruby:9.3.4-org`|Printing `hello`|
|`ghcr.io/stargz-containers/jruby:9.3.4-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/node:17.8.0-org`|Printing `hello`|
|`ghcr.io/stargz-containers/node:17.8.0-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/perl:5.34.1-org`|Printing `hello`|
|`ghcr.io/stargz-containers/perl:5.34.1-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/php:8.1.4-org`|Printing `hello`|
|`ghcr.io/stargz-containers/php:8.1.4-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/pypy:3.9-org`|Printing `hello`|
|`ghcr.io/stargz-containers/pypy:3.9-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/python:3.10-org`|Printing `hello`|
|`ghcr.io/stargz-containers/python:3.10-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/r-base:4.1.3-org`|Printing `hello`|
|`ghcr.io/stargz-containers/r-base:4.1.3-esgz`|Printing `hello`|
|`ghcr.io/stargz-containers/redis:6.2.6-org`|Code execution until up and ready message (`Ready to accept connections`) is printed|
|`ghcr.io/stargz-containers/redis:6.2.6-esgz`|Code execution until up and ready message (`Ready to accept connections`) is printed|
|`ghcr.io/stargz-containers/rethinkdb:2.4.1-org`|Code execution until up and ready message (`Server ready`) is printed|
|`ghcr.io/stargz-containers/rethinkdb:2.4.1-esgz`|Code execution until up and ready message (`Server ready`) is printed|
|`ghcr.io/stargz-containers/tomcat:10.1.0-jdk17-openjdk-bullseye-org`|Code execution until up and ready message (`Server startup`) is printed|
|`ghcr.io/stargz-containers/tomcat:10.1.0-jdk17-openjdk-bullseye-esgz`|Code execution until up and ready message (`Server startup`) is printed|
|`ghcr.io/stargz-containers/postgres:14.2-org`|Code execution until up and ready message (`database system is ready to accept connections`) is printed|
|`ghcr.io/stargz-containers/postgres:14.2-esgz`|Code execution until up and ready message (`database system is ready to accept connections`) is printed|
|`ghcr.io/stargz-containers/wordpress:5.9.2-org`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/wordpress:5.9.2-esgz`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/mariadb:10.7.3-org`|Code execution until up and ready message (`mysqld: ready for connections`) is printed|
|`ghcr.io/stargz-containers/mariadb:10.7.3-esgz`|Code execution until up and ready message (`mysqld: ready for connections`) is printed|
|`ghcr.io/stargz-containers/php:8.1.4-apache-bullseye-org`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/php:8.1.4-apache-bullseye-esgz`|Code execution until up and ready message (`apache2 -D FOREGROUND`) is printed|
|`ghcr.io/stargz-containers/rabbitmq:3.9.14-org`|Code execution until up and ready message (`Server startup complete`) is printed|
|`ghcr.io/stargz-containers/rabbitmq:3.9.14-esgz`|Code execution until up and ready message (`Server startup complete`) is printed|
|`ghcr.io/stargz-containers/elasticsearch:8.1.1-org`|Code execution until up and ready message (`started`) is printed|
|`ghcr.io/stargz-containers/elasticsearch:8.1.1-esgz`|Code execution until up and ready message (`started`) is printed|
|`ghcr.io/stargz-containers/nixos/nix:2.3.12-org`|Executing `echo hello` on the shell|
|`ghcr.io/stargz-containers/nixos/nix:2.3.12-esgz`|Executing `echo hello` on the shell|

## lazy-pulling-enabled KinD node image

You can enable lazy pulling of eStargz on [KinD](https://github.com/kubernetes-sigs/kind) using our prebuilt node image [`ghcr.io/containerd/stargz-snapshotter:${VERSION}-kind`](https://github.com/orgs/containerd/packages/container/package/stargz-snapshotter) namespace.

Example:

```console
$ kind create cluster --name stargz-demo --image ghcr.io/containerd/stargz-snapshotter:0.12.1-kind
```

Please refer to README for more details.
