## Linux入侵排查思路
### 一、账号安全
**基本使用：**
#### 1、用户信息文件/etc/passwd
```shell
root:x:0:0:root:/root:/bin/bash
account:password:UID:GID:GECOS:directory:shell
```
用户名：密码：用户ID：组ID：用户说明：家目录：登陆之后shell
注意：无密码只允许本机登陆，远程不允许登陆
#### 2、影子文件/etc/shadow
```shell
root:$6$oGs1PqhL2p3ZetrE$X7o7bzoouHQVSEmSgsYN5UD4.kMHx6qgbTqwNVC5oOAouXvcjQSt.Ft7ql1WpkopY0UV9ajBwUt1DpYxTCVvI/:16809:0:99999:7:::
```
用户名：加密密码：密码最后一次修改日期：两次密码的修改时间间隔：密码有效期：密码修改到期到的警告天数：密码过期之后的宽限天数：账号失效时间：保留

who 查看当前登录用户（tty本地登陆 pts远程登录）
w 查看系统信息，想知道某一时刻用户的行为
uptime 查看登陆多久、多少用户，负载

**入侵排查：**
#### 1、查询特权用户特权用户(uid 为0)
```shell
[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd
```
#### 2、查询可以远程登录的帐号信息
```shell
[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow
```
#### 3、除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通帐号应删除sudo权限
```shell
[root@localhost ~]# more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=
```
#### 4、禁用或删除多余及可疑的帐号
```shell
usermod -L useruserdel useruserdel -r user 禁用帐号，帐号无法登录，/etc/shadow第二栏为!开头删除user用户将删除user用户，并且将/home目录下的user目录一并删除
```

### 二、历史命令
**基本使用：**
通过.bash_history查看帐号执行过的系统命令
#### 1、root的历史命令
```shell
histroy
```
#### 2、打开/home各帐号目录下的.bash_history，查看普通帐号的历史命令
为历史的命令增加登录的IP地址、执行命令时间等信息：
1）保存1万条命令
```shell
sed -i 's/^HISTSIZE=1000/HISTSIZE=10000/g' /etc/profile
```
2）在/etc/profile的文件尾部添加如下行数配置信息：
```shell
######jiagu history xianshi#########
USER_IP=`who -u am i 2>/dev/null | awk '{print $NF}' | sed -e 's/[()]//g'`
if [ "$USER_IP" = "" ]
then
USER_IP=`hostname`
fi
export HISTTIMEFORMAT="%F %T $USER_IP `whoami` "
shopt -s histappend
export PROMPT_COMMAND="history -a"
######### jiagu history xianshi ##########
```
3）source /etc/profile让配置生效
生成效果： 1 2018-07-10 19:45:39 192.168.204.1 root source /etc/profile
3、历史操作命令的清除：history -c
但此命令并不会清除保存在文件中的记录，因此需要手动删除.bash_profile文件中的记录。

**入侵排查**
进入用户目录下
```shell
cat .bash_history >> history.txt
```

### 三、端口
使用netstat 网络连接命令，分析可疑端口、IP、PID
```shell
netstat -antlp|more
```
查看下pid所对应的进程文件路径，
运行ls -l /proc/$PID/exe或file /proc/$PID/exe（$PID 为对应的pid 号）

### 四、进程
使用ps命令，分析进程
```shell
ps aux | grep pid
```

### 五、开机启动项
**基本使用：**
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/linux.png>

查看运行级别命令 runlevel
系统默认允许级别
```shell
vi /etc/inittab
id=3：initdefault 系统开机后直接进入哪个运行级别
```
开机启动配置文件
```shell
/etc/rc.local
/etc/rc.d/rc[0~6].d
```
例子:当我们需要开机启动自己的脚本时，只需要将可执行脚本丢在/etc/init.d目录下，然后在/etc/rc.d/rc*.d中建立软链接即可
```shell
root@localhost ~]# ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh
```
此处sshd是具体服务的脚本文件，S100ssh是其软链接，S开头代表加载时自启动；如果是K开头的脚本文件，代表运行级别加载时需要关闭的。

**入侵排查：**
启动项文件： 
```shell
more /etc/rc.local /etc/rc.d/rc[0~6].d ls -l /etc/rc.d/rc3.d/
```

### 六、定时任务
**基本使用**
#### 1、利用crontab创建计划任务
基本命令
```shell
crontab -l 	列出某个用户cron服务的详细内容
Tips：		默认编写的crontab文件会保存在 (/var/spool/cron/用户名 例如: /var/spool/cron/root
crontab -r 	删除每个用户cront任务(谨慎：删除所有的计划任务)
crontab -e 	使用编辑器编辑当前的crontab文件
如：*/1 * * * * echo "hello world" >> /tmp/test.txt 每分钟写入文件
```
#### 2、利用anacron实现异步定时任务调度
使用案例
每天运行 /home/backup.sh脚本： 
```shell
vi /etc/anacrontab @daily 10 example.daily /bin/bash /home/backup.sh
```
当机器在 backup.sh 期望被运行时是关机的，anacron会在机器开机十分钟之后运行它，而不用再等待 7天。

**入侵排查：**
重点关注以下目录中是否存在恶意脚本
```shell
/var/spool/cron/*
/etc/crontab
/etc/cron.d/*
/etc/cron.daily/*
/etc/cron.hourly/*
/etc/cron.monthly/*
/etc/cron.weekly/
/etc/anacrontab
/var/spool/anacron/*
小技巧：more /etc/cron.daily/* 查看目录下所有文件
```

### 七、服务
**服务自启动**
#### 第一种修改方法：
```shell
chkconfig [--level 运行级别] [独立服务名] [on|off]
chkconfig –level 2345 httpd on 开启自启动
chkconfig httpd on （默认level是2345）
```
#### 第二种修改方法：
修改/etc/re.d/rc.local 文件
加入 /etc/init.d/httpd start
#### 第三种修改方法：
使用ntsysv命令管理自启动，可以管理独立服务和xinetd服务。

**入侵排查**
1、查询已安装的服务：
#### RPM包安装的服务
```shell
chkconfig --list 		查看服务自启动状态，可以看到所有的RPM包安装的服务
ps aux | grep crond 	查看当前服务
```
系统在3与5级别下的启动项
中文环境
```shell
chkconfig --list | grep "3:启用\|5:启用"
```
英文环境
```shell
chkconfig --list | grep "3:on\|5:on"
```
#### 源码包安装的服务
查看服务安装位置 ，一般是在/user/local/
service httpd start
搜索/etc/rc.d/init.d/ 查看是否存在

### 八、系统日志
日志默认存放位置：/var/log/
查看日志配置情况：more /etc/rsyslog.conf
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/linux1.png>
**日志分析技巧：**
#### 1、定位有多少IP在爆破主机的root帐号：
```shell
grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
```
定位有哪些IP在爆破：
```shell
grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-
4][0-9]|[01]?[0-9][0-9]?)"|uniq -c
```
爆破用户名字典是什么？
```shell
grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print"$1\n";}'|uniq -c|sort -nr
```
#### 2、登录成功的IP有哪些：
```shell
grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
```
登录成功的日期、用户名、IP：
```shell
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
```
#### 3、增加一个用户kali日志：
```shell
Jul 10 00:12:15 localhost useradd[2382]: new group: name=kali, GID=1001
Jul 10 00:12:15 localhost useradd[2382]: new user: name=kali, UID=1001, GID=1001,
home=/home/kali
, shell=/bin/bash
Jul 10 00:12:58 localhost passwd: pam_unix(passwd:chauthtok): password changed for kali
#grep "useradd" /var/log/secure
```
#### 4、删除用户kali日志：
```shell
Jul 10 00:14:17 localhost userdel[2393]: delete user 'kali'
Jul 10 00:14:17 localhost userdel[2393]: removed group 'kali' owned by 'kali'
Jul 10 00:14:17 localhost userdel[2393]: removed shadow group 'kali' owned by 'kali'
# grep "userdel" /var/log/secure
```
#### 5、su切换用户：
```shell
Jul 10 00:38:13 localhost su: pam_unix(su-l:session): session opened for user good by root(uid=0)
```
sudo授权执行:
```shell
sudo -l
Jul 10 00:43:09 localhost sudo:good : TTY=pts/4 ; PWD=/home/good ; USER=root ;
COMMAND=/sbin/shutdown -r now
```
