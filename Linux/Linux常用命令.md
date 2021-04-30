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
firewall-cmd --reload     --重启防火墙
```

### (三)MySQL数据库
```sql
update user set password=password(“123”) where user=“root”;     --更改数据库root用户密码
flush privileges    --刷新权限
```

### (四)用户name 
| 命令 | 用户（user） | 备注 | 用户组（group） | 备注
:-: | :-: | :-: | :-: | :-:
新建 | useradd 用户名 |  | groupadd 组名 | | 
新建 | useradd -g 组名 用户名 | 创建用户并指定组名 | groupadd -g 组编号 组名 | 创建用户组并指定组编号|
删除 | userdel 用户名 | 选项-r同时删除家目录 | groupdel 组名 | | 
修改 | usermod -l 新用户名 用户名 | 修改用户名 | groupmod -n 新组名 组名 | 修改用户组名|
修改 | usermod -g 组名 用户名 | 修改用户所在组 | groupmod -g 组编号 组名 | 修改用户组编号| 
修改 | passwd 用户名 | 修改/设置用户密码 | gpasswd 组名 | 修改/设置用户组密码|
查询 | whoami | 当前用户 | groups | 当前用户组| 

### (五)压缩与解压
```shell
grep [选项] 模式 文件名      --选项-c，将多个文件或目录打包；-f，指定包的文件名或者指定解压的tar包的包名；-v，显示过程；-x，对tar包作解打包操作；-t，只查看tar包内容，不作解打包操作

```

### (六)查看文件
```shell
cat [选项] 文件名      --显示文件内容。选项-a，等于-vET集合；-E，列出每行结尾回车符$；-n，所有行编号；-b，对非空行编号；-T，显示Tab键^I；-V，列出特殊字符
more [选项] 文件名     --分页显示文件内容。选项-f，计算实际行数，而不是自动换行后的行数；+n，从第n行显示文件内容，n表示数字；-n，一次显示的行数，n表示数字
head [选项] 文件名     --显示文件前n行。选项-nK，显示文件前K行内容，如果-K则表示显示除了文件最后K行外剩余全部内容；-cK，显示文件前K个字节的内容，同上；-v，显示文件名
tail [选项] 文件名     --显示文件后n行。选项-nK，表示输出最后K行，如果是-n+K表示从文件第K行输出；-cK，输出文件最后K个字节内容，-c+K表示从文件第K个字节开始输出；-f，输出文件变化后新增加的数据
```
