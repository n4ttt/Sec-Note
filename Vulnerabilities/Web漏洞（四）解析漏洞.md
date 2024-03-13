### 文件解析概念
是指当服务器收到一个HTTP请求的时候，web容器首先会根据文件的后缀名，决定如何处理这个请求；</br>
当服务器获取到所请求的页面后缀(.php)后，接下来就会在服务端寻找可以处理这类后缀名的应用程序，如果找不到就直接把这个文件返还给客户端。

### 漏洞利用与防御
由于中间件本身缺陷，在对上传文件进行解析时会出现一些不可预料的错误从而导致被利用，进行文件上传绕过。

### 常见解析漏洞：
apache解析漏洞、IIS6.0解析漏洞、 PHP CGI解析漏洞、Nginx解析漏洞
#### （一）apache解析漏洞
**1.多后缀**</br>
• 存在版本：apache1.x和apache2.x</br>
• 解析规则：从右向左开始判断解析，如果后缀名为不可识别文件解析，就再往左判断，如果都不认识, 则会暴露其源码</br>
• 举例：</br>
可以上传一个 test.php.aaa.bbb 文件，绕过验证且服务器依然会将其解析为php</br>
访问 /test.php.aaa.bbb，由于Apache不认识aaa和bbb，会从右向左一直遍历到后缀.php为止</br>
• Apache 能够识别的文件在 mime.types 文件可以查看</br>
• 修复方案：后缀验证尽量使用白名单的方式，这样即使使用不存在的后缀名，也无法绕过</br>


**2.配置问题导致漏洞**</br>
• 漏洞产生原因：</br>
（1）apache的conf里有配置AddHandler php5-script.php，则只有文件名包含php，都能以php执行；</br>
（2）apache的conf里有配置AddType application/x-httpd-php.jpg，即使文件后缀是jpg，也能以php执行。</br>
• 修复方案</br>
① 在 apache 配置文件中，禁止 .php. 这样的文件执行，配置文件里面加入</br>
② 用伪静态能解决这个问题，重写类似.php.*这类文件，打开 apache 的 httpd.conf 找到</br>


**3.htaccess文件解析**</br>
• .htaccess 文件可以配置很多事情，如是否开启站点的图片缓存、自定义错误页面、自定义默认文档、等等。但我们这里只关心 .htaccess 文件的一个作用—— MIME 类型修改</br>
• 如果Apache中 .htaccess 可被执行并可被上传，那么可以尝试在.htaccess中写入</br>
```
<FilesMatch "shell.jpg"> SetHandler application/x-httpd-php </FilesMatch>
```
该语句会让 Apache 把 shell.jpg 文件当作 php 文件来解析</br>
• 另一种写法是：</br>
```
AddTypeapplication/x-httpd-php .xxx
```
如果写入，就成功地使该 .htaccess 文件所在目录及其子目录中的后缀为 .xxx 的文件被Apache当做php文件</br>


#### （二）IIS6.0解析漏洞
**1.目录解析**</br>
网站目录下创建.asp或者.asa的文件夹，上传任意文件都被作为asp文件解析。</br>
• 形式：/xx.asp/xx.jpg</br>
• 原理：在网站下创建文件夹名字为.asp、.asa的文件夹，其目录内的任何扩展名的文件都被当作asp文件来解析并执行。因此只要攻击者只需通过该漏洞上传图片马，不用修改后缀名</br>


**2.文件解析**</br>
服务器默认不解析;后面内容，所以xxx.asp;.html文件作为asp文件解析。</br>
• 形式：/xx.asp;.jpg（利用特殊符号 ";"）</br>
• 原理：在iis6.0下，服务器默认不解析；号后面的内容，所以 xx.asp;.jpg 被解析为asp脚本</br>


**3.其他解析文件类型**</br>
asa、cer、cdx都作为asp文件类型来解析</br>
• 形式：/test.asa、/ test.cer、 /test.cdx</br>
• 原理： iis6.0 默认的可执行文件除了asp还包含这三种asa、cer、cdx，会将这三种扩展名文件解析为asp文件</br>

Ø 修复：</br>
• 目前尚无微软官方补丁，可以通过自己编写正则，阻止上传 xx.asp;.jpg 类型的文件名• 做好权限设置，限制用户创建文件夹</br>


#### （三）IIS7.0/IIS7.5/Nginx 1.x畸形解析漏洞（PHP CGI解析漏洞）
• 利用条件：</br>
（1）fast-CGI运行模式</br>
（2）php.ini里cgi.fix_pathinfo=1（默认为1）</br>
（3）取消勾选php-cgi.exe程序的“Invoke handler only if request is mapped to”</br>
• 形式：如果在一个文件路径 /xx.jpg 后面加上 /xx.php 会将 /xx.jpg/xx.php 解析为php 文件。</br>
• 修复方法：</br>
1. 配置php.ini里cgi.fix_pathinfo=0,并重启服务器</br>
2. 在模块映射中勾选请求限制</br>

#### （四）Nginx < 8.03 空字节代码执行漏洞
• 影响版本：0.5，0.6，0.7 <= 0.7.65，0.8 <= 0.8.37</br>
• 原理：在使用 PHP-FastCGI 执行php的时候，URL里面在遇到 %00空字节 时与FastCGI 处理不一致，导致可以在图片中嵌入PHP代码然后通过访问xxx.jpg%00.php 来执行其中的代码</br>
• 恶意用户发出请求 http://example.com/file.ext％00.php 就会将 file.ext 作为PHP 文件解析</br>
• 修复方法：</br>
1. 在nginx中配置，禁止在上传目录下执行php。或在fcgi.conf 配置加如下代码：</br>
2. 升级到最新版的nginx</br>
