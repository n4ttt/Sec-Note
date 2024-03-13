### 文件解析概念
是指当服务器收到一个HTTP请求的时候，web容器首先会根据文件的后缀名，决定如何处理这个请求；当服务器获取到所请求的页面后缀(.php)后，接下来就会在服务端寻找可以处理这类后缀名的应用程序，如果找不到就直接把这个文件返还给客户端。

### 漏洞利用与防御
由于中间件本身缺陷，在对上传文件进行解析时会出现一些不可预料的错误从而导致被利用，进行文件上传绕过。

### 常见解析漏洞：
apache解析漏洞、IIS6.0解析漏洞、 PHP CGI解析漏洞、Nginx解析漏洞
#### （一）apache解析漏洞
1.多后缀
存在版本：apache1.x和apache2.x

2.配置问题导致漏洞
（1）apache的conf里有配置AddHandler php5-script.php，则只有文件名包含php，都能以php执行；
（2）apache的conf里有配置AddType application/x-httpd-php.jpg，即使文件后缀是jpg，也能以php执行。

3.htaccess文件解析

#### （二）IIS6.0解析漏洞
1.目录解析
网站目录下创建.asp或者.asa的文件夹，上传任意文件都被作为asp文件解析。
2.文件解析
服务器默认不解析;后面内容，所以xxx.asp;.html文件作为asp文件解析。
3.其他解析文件类型
asa、cer、cdx都作为asp文件类型来解析

#### （三）IIS7.0/IIS7.5/Nginx 1.x畸形解析漏洞（PHP CGI解析漏洞）
利用条件：
（1）fast-CGI运行模式
（2）php.ini里cgi.fix_pathinfo=1（默认为1）
（3）取消勾选php-cgi.exe程序的“Invoke handler only if request is mapped to”
