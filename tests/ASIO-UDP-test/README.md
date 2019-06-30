# Demo code from ASIO C++ library tutorials
Modified from:
 - https://think-async.com/Asio/asio-1.13.0/doc/asio/tutorial/tutdaytime5/src.html
 - https://think-async.com/Asio/asio-1.13.0/doc/asio/tutorial/tutdaytime6/src.html

# How to compile and run the server

## Install ASIO C++ development lib
- Install ASIO C++ headers on Debian / Ubuntu
    sudo apt install libasio-dev
- Install ASIO C++ headers on CentOS 7.6
    # login as root
    yum install epel-release && yum install asio-devel
- Install ASIO C++ headers on Fedora 30
    # login as root
    dnf install asio-devel

## Compile and run
    g++ -g -O0 -pthread -std=c++11 -c udp_daytime_server.cpp -lpthread
    ./a.out

Or `make && ./udp_daytime_server`

### Execute command ncat as an UDP client
`nc` or `ncat` can be used as an UDP client to talk with the UDP daytime server through UDP port 8013.
Example:
```
[liuqun@localhost ASIO-UDP-test]$ nc -u 127.0.0.1 8013
send anything here...
Sun Jun 30 17:57:14 2019
```
