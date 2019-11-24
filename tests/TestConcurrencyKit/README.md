# 1. Setup build dependencies

## Ubuntu
sudo apt install gcc cmake libck-dev

## CentOS-7.7
```
# log in CentOS as root...
yum install epel-release
yum install gcc cmake3 ck-devel
alias cmake=cmake3
```

# 2. Build
```
cmake . -DCMAKE_BUILD_TYPE=Debug
make
```

# Known issues
1. CentOS 7.6及更低版本无法安装最新版本cmake3，导致本程序无法编译。
