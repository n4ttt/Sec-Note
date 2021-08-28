## docker概述



## docker安装

安装文档官方地址：



## docker命令

### 帮助命令

```shell
docker version			docker版本
docker info				docker系统信息
docker 命令 --help		docker帮助命令
```

帮助文档地址：https://docs.docker.com/engine/reference/commandline/docker/

### 镜像命令

docker images	查看所有本地的主机上的镜像

```shell
[root@dodo~]#docker images
REPOSITORY         TAG         IMAGE ID       CREATED         SIZE
rmi-codebase_rmi   latest      a0efff767205   7 days ago      488MB

# 解释
REPOSITORY	镜像的仓库源
TAG      	镜像的标签   
IMAGE ID    镜像的id   
CREATED     镜像的创建时间    
SIZE		镜像的大小

# 可选项
-a,--all		# 列出所有的镜像
-q,--quiet		# 只显示镜像的id
```

docker search 	搜索镜像

```shell
docker search 

# 可选项，通过收藏进行过滤
--failter=stars=3000		搜索出来的镜像stars大于3000的
```

docker pull	下载镜像

```shell
# 下载镜像，
docker pull 镜像名[:tag]
# 不使用tag，默认下载latest
# 可选项
```

docker rmi	删除镜像

```shell
docker rmi -f 镜像id		#删除指定镜像
docker rmi -f 容器id 容器id 容器id		# 删除多个容器
docker rmi -f $(docker images -aq)		# 删除全部容器
```



### 容器命令

**说明：有了镜像才能创建容器**

**创建容器并启动**

```shell
yudocker run [可选参数] image

# 参数说明
--name="name"		容器名字，用来区分容器
-d					后台运行
-it					交互方式运行，进入容器查看内容
-p					指定容器端口，-p 8080:8080
	-p ip:主机端口:容器端口
	-p 主机端口:容器端口（常用）
	-p 容器端口
	容器端口
-P					随机指定端口

# 测试，启动并进入容器
[root@dodo~]#docker run -it nginx /bin/bash
root@4172b7ee88b0:/# 

# 从容器中退出回主机
root@4172b7ee88b0:/# exit
exit
```

**列出所有运行的容器**

```shell
# docker ps 命令
	# 列出当前正在运行的容器
-a	# 列出当前正在运行的容器+带出历史运行过的容器
-n=? # 显示最近创建的容器
-q  # 只显示容器编号
```

**退出容器**

```shell
exit		# 直接容器停止并退出
ctrl + p + q	# 容器不停止退出
```

**删除容器**

```shell
docker rm 容器id					# 删除指定容器，不能删除正在运行的容器，强制删除 rm -f
docker rm -f $(docker ps -aq)		# 删除全部容器
docker ps -a -q|xargs docker rm		# 删除所有容器
```

**启动停止容器的操作**

```shell
docker start		# 启动容器
docker restart		# 重启容器
docker stop			# 停止当前正在运行的容器
docker kill			# 强制停止当前容器
```

### 常用其他命令

**后台启动容器**

```shell
# 命令 docker run -d 镜像名

# 问题：发现docker ps ,发现容器停止了

# 常见的坑：docker容器使用后台运行，就必须要有一个前台进程，docker发现没有应用，就会自动停止

```

**查看日志命令**

```shell
docker logs

# 显示日志
-tf				# 显示日志
--tail number	# 要显示日志条数
[root@dodo~]#docker logs -tf --tail 10 a0211adcd3d0
```

**查看容器中的进程信息**

```shell
# 命令：docker top 容器id

[root@dodo~]#docker top b59e7086cc30
UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD
root                19459               19432               0                   00:05               pts/0               00:00:00            /bin/bash
```

**查看镜像元数据**

```shell
# 命令：docker inspect 容器id
```

**进入当前正在运行下容器**

```shell
# 容器通常后台运行使用，需要进入容器，修改配置，则需要进入容器

# 方式一命令：docker exec -it 容器id /bin/bash
[root@dodo~]#docker exec -it b59e7086cc30 /bin/bash
root@b59e7086cc30:/# 

#方式二命令：docker attach 容器id
[root@dodo~]#docker attach b59e7086cc30
root@b59e7086cc30:/# 

区别：docker exec进入容器后新打开一个终端，可以在里面操作（常用）；docker attach进入容器正在执行的终端，不会启动新的进程。
```

**从容器内拷贝文件到主机上**
```shell
docker cp 容器id:容器内路径 主机目录
[root@dodo~]#docker cp a0211adcd3d0:/root/111.java /opt/
```

### docker可视化
#### **什么是portainer？**

docker run -d -p 8088:9000 \

--restart=always -v /var/run/docker.sock:/var/run/docker.sock --privileged=true portainer/portainer


## docker镜像

**镜像是什么？**

镜像是一种轻量级、可执行的独立软件包，用来打包软件运行环境和基于运行环境开发的软件，它包含运行这个软件所需的所有内容，包括代码、运行时、库、环境变量和配置文件。

**镜像加载原理？**

**分层理解**

<u>docker镜像都是只读的，当容器启动时，一个新的可写层被加载到镜像的顶部。</u>

这一层就是容器层，容器之下都是镜像层。

**commit镜像**

```shell
docker commit	提交容器成为一个新的副本

# 命令和git原理类似
docker commit -m="提交的描述信息" -a="作者" 容器id 目标镜像名:[TAG]
```

## 容器数据卷

### 什么是容器数据卷

docker理念：

将应用和环境打包成一个镜像。

数据？数据在容器中，如果容器删除，数据就会丢失！需求：数据可以持久化。

容器之间可以有一个数据共享的技术，docker容器中产生的数据，同步到本地。

这就是卷技术，目录的挂载，将我们的容器内的目录，挂载到Linux上面！

### 使用数据卷

方式一：直接使用命令挂载 -v

```shell
docker run -it -v 主机目录：容器目录

# 测试

```


## dockerfile

## docker网络
