## 多种方式开启简易的http服务

### 1.使用python

使用python在虚拟机之间传文件，只需要服务端安装python即可</br>
服务端：
```shell
(python2):python2 -m SimpleHTTPServer 9999；
(python3):python3 -m http.server 9999
```
Linux客户端命令行下载文件：wget http://<span></span>192.168.100.100:9999/abc.txt</br>
Windows客户端网址输入即下载文件：http://<span></span>192.168.100.100:9999/abc.txt

### 2.使用PHP
```shell
php -S 0.0.0.0:8080
```
