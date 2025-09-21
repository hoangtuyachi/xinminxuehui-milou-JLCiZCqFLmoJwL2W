> 漏洞描述：远程主机支持使用提供中等强度加密的 SSL 密码。Nessus 将中等强度视为密钥长度为 64 至 112 位的任何加密，或使用 3DES 加密套件的加密。如果攻击者位于同一物理网络，其将非常容易避开中等强度加密。（[Nessus](https://github.com)是一款广泛使用的网络漏洞扫描工具，用于发现和评估计算机系统和网络中的安全漏洞。它是一款功能强大的商业工具，由Tenable Network Security开发和维护。）

  漏洞攻击原理：SWEET32是针对使用64位分组密码的SSL/TLS协议的漏洞，攻击者可利用碰撞攻击导致信息泄露。该漏洞利用64位分组密码在CBC模式下的特性，当加密大量数据后可能出现密文块碰撞（即相同输入），从而推导明文。 ‌

[![image](https://img2024.cnblogs.com/blog/3413000/202509/3413000-20250921164303208-449676902.png)](https://img2024.cnblogs.com/blog/3413000/202509/3413000-20250921164303208-449676902.png)

  方便个人测试SSL协议漏洞的工具及使用：

bash

```
wget https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2.zip -O testssl.zip
# 一个完全开源的工具，在github上由Dirk Wetter 发起并维护，纯 bash 脚本，不需要安装额外依赖。
# 检测目标服务器的 TLS/SSL 协议、加密套件、漏洞情况（比如 Heartbleed、SWEET32、POODLE、LOGJAM 等）
# 不需要检测的节点都安装这个脚本，他是通过网络进行握手去检测使用的协议。

unzip testssl.zip && cd testssl.sh-3.2 

yum install -y bind-utils
# apt install -y dnsutils

./testssl.sh :
```

  我目前扫描出的漏洞端口是6443，即K8S集群中ApiServer的协议漏洞，发现我的K8S集群版本比较老，当时可能为了兼容一些老的TLS/SSL协议，并未料到这些协议后面发现了漏洞。（至于要扫描哪些端口，需要进行判断，常见的如443、8443、6443、2379、3306、9200、9443等，任何 TCP 服务端口都可能启用 TLS，可以使用`ss -lntp`找出监听的TCP端口，然后写进脚本里全部检查一遍最为可靠）。

[![image](https://img2024.cnblogs.com/blog/3413000/202509/3413000-20250921164326980-1998778353.png)](https://img2024.cnblogs.com/blog/3413000/202509/3413000-20250921164326980-1998778353.png)

  解决办法：①修改ApiServer参数配置，指定协议种类 ②升级K8S集群版本(通常代价会很大)

bash

```
vim /etc/kubernetes/manifests/kube-apiserver.yaml

--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
--tls-min-version=VersionTLS12

# 修改 manifest 目录下的文件会自动重启，不需要人工重启
kubectl get pods -n kube-system | grep kube-apiserver
```



\_\_EOF\_\_

![](https://github.com/nanxi-xz)NanXi - **本文链接：** [https://github.com/nanxi-xz/p/19080793](https://github.com):[悠兔机场](https://xinnongbo.com)
- **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
- **版权声明：** 本博客所有文章除特别声明外，均采用 [BY-NC-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
- **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
