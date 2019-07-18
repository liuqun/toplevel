# 用法
使用make命令生产CA私钥以及根证书，并签发证书给服务器和客户
```
make
```

# Notice
- The commands used in Makefile to generate certificates are not supposed to be
good practice.
You should ONLY use them in a testing environment!
- 此处生成的证书有效期被设置为100年, 请勿用于生产环境!
