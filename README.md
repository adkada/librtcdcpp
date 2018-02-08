librtcdcpp - A Simple WebRTC DataChannels Library
=================================================

librtcdcpp is a simple C++ implementation of the WebRTC DataChannels API.

It was originally written by [Andrew Gault](https://github.com/abgault) and [Nick Chadwick](https://github.com/chadnickbok), and was inspired in no small part by [librtcdc](https://github.com/xhs/librtcdc)

Its goal is to be the easiest way to build native WebRTC DataChannels apps across PC/Mac/Linux/iOS/Android.

Why
---

Because building the WebRTC libraries from Chromium can be a real PITA, and slimming it down to just DataChannels can be really tough.

Dependencies
------------

 - libnice - https://github.com/libnice/libnice
 - GnuTLS - https://www.gnutls.org/ or OpenSSL - https://www.openssl.org/

Submodules:
 - usrsctp - https://github.com/sctplab/usrsctp
 - spdlog - https://github.com/gabime/spdlog

Building
--------

### Linux:
```
  git submodule update --init --recursive
  make
```
 
**TODO**: deb and rpm packages

### Mac:

**TODO**

### Windows:

**TODO**

Licensing
---------

BSD style - see the accompanying LICENSE file for more information

