# Linux常用命令
### (一)网络
```shell
vi /etc/sysconfig/network-scripts/ifcfg-ens88   --编辑网络配置文件
systemctl status network    --查看网络状态
systemctl start network     --启用网络  
systemctl stop network      --停止网络    
systemctl restart network   --重启网络
```

### (二)防火墙
```shell
firewall-cmd --zone=public --add-port=端口号/tcp --permanent   --防火墙开启某端口号
systemctl status firewalld    --查看防火墙状态
firewall-cmd --reload         --重启防火墙
```

### (三)MySQL数据库
```sql
update user set password=password(“123”) where user=“root”;     --更改数据库root用户密码
flush privileges    --刷新权限
```

### (四)用户
| 命令 | 用户（user） | 备注 | 用户组（group） | 备注
:-: | :- | :-: | :- | :-:
新建 | useradd 用户名 |  | groupadd 组名 | | 
新建 | useradd -g 组名 用户名 | 创建用户并指定组名 | groupadd -g 组编号 组名 | 创建用户组并指定组编号|
删除 | userdel 用户名 | 选项-r同时删除家目录 | groupdel 组名 | | 
修改 | usermod -l 新用户名 用户名 | 修改用户名 | groupmod -n 新组名 组名 | 修改用户组名|
修改 | usermod -g 组名 用户名 | 修改用户所在组 | groupmod -g 组编号 组名 | 修改用户组编号| 
修改 | passwd 用户名 | 修改/设置用户密码 | gpasswd 组名 | 修改/设置用户组密码|
查询 | whoami | 当前用户 | groups | 当前用户组| 

### (五)压缩与解压
```shell
tar [选项] 源文件或目录（打包）/压缩包（解打包）      
    --选项-c，将多个文件或目录打包；-f，指定包的文件名或者指定解压的tar包的包名；-v，显示过程；-x，对tar包作解打包操作；-t，只查看tar包内容，不作解打包操作
    
常见解压/压缩命令
tar （注：tar是打包，不是压缩！）
解包：tar xvf FileName.tar
打包：tar cvf FileName.tar DirName

.gz
解压1：gunzip FileName.gz
解压2：gzip -d FileName.gz
压缩：gzip FileName

.tar.gz 和 .tgz
解压：tar zxvf FileName.tar.gz
压缩：tar zcvf FileName.tar.gz DirName

.bz2
解压1：bzip2 -d FileName.bz2
解压2：bunzip2 FileName.bz2
压缩： bzip2 -z FileName

.tar.bz2
解压：tar jxvf FileName.tar.bz2
压缩：tar jcvf FileName.tar.bz2 DirName

.bz
解压1：bzip2 -d FileName.bz
解压2：bunzip2 FileName.bz
压缩：未知

.tar.bz
解压：tar jxvf FileName.tar.bz
压缩：未知

.Z
解压：uncompress FileName.Z
压缩：compress FileName

.tar.Z
解压：tar Zxvf FileName.tar.Z
压缩：tar Zcvf FileName.tar.Z DirName

.zip
解压：unzip FileName.zip
压缩：zip FileName.zip DirName

.rar
解压：rar x FileName.rar
压缩：rar a FileName.rar DirName
```

### (六)查看文件
```shell
cat [选项] 文件名      --显示文件内容。
    选项-a，等于-vET集合；-E，列出每行结尾回车符$；-n，所有行编号；-b，对非空行编号；-T，显示Tab键^I；-V，列出特殊字符
more [选项] 文件名     --分页显示文件内容。
    选项-f，计算实际行数，而不是自动换行后的行数；+n，从第n行显示文件内容，n表示数字；-n，一次显示的行数，n表示数字
head [选项] 文件名     --显示文件前n行。
    选项-nK，显示文件前K行内容，如果-K则表示显示除了文件最后K行外剩余全部内容；-cK，显示文件前K个字节的内容，同上；-v，显示文件名
tail [选项] 文件名     --显示文件后n行。
    选项-nK，表示输出最后K行，如果是-n+K表示从文件第K行输出；-cK，输出文件最后K个字节内容，-c+K表示从文件第K个字节开始输出；-f，输出文件变化后新增加的数据
```

### (七)rabbitmq
>重启rabbitmq服务通过两个命令来实现：</br>
>>rabbitmqctl stop ：停止rabbitmq</br>
>>rabbitmq-server restart : 重启rabbitmq</br>
