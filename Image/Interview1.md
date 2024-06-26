#### ✸ 1.说一下三次握手和四次挥手？
1.客户端请求连接服务器，建立连接！</br>
2.服务器接受客户端请求，建立连接！</br>
3.客户端向服务端发出确认，双方建立连接。</br>

1.数据连接结束后，客户端发出释放报文</br>
2.服务端发出确认，A-B连接释放</br>
3.B没有数据发给A，其应用程序就通知TCP释放连接</br>
4.客户端发出确认，TCP连接就关闭了

#### ✸ 7.当你在浏览器输入一个网址按回车之后发生了什么
1.DNS解析</br>
DNS根据域名查询IP地址的过程为：</br>
浏览器缓存 --> 操作系统缓存 --> 路由器缓存-->本地（ISP）域名服务器缓存 --> 根域名服务器。</br>
2.进行TCP连接</br>
浏览器终于得到了IP以后，向服务器发送TCP连接，TCP连接经过三次握手。</br>
3.浏览器发送HTTP请求</br>
4.服务器处理请求</br>
服务器收到浏览器的请求以后，会解析这个请求（读请求头），然后生成一个响应头和具体响应内容。</br>
5.浏览器解析渲染页面</br>
6.关闭TCP连接</br>
当数据完成请求到返回的过程之后，根据Connection的Keep-Alive属性可以选择是否断开TCP连接，经过4次挥手TCP断开。</br>

#### ✸ 2.HTTP状态码
https://www.runoob.com/http/http-status-codes.html</br>

各类别常见状态码：</br>
2xx （3种）</br>
200 OK：表示从客户端发送给服务器的请求被正常处理并返回；</br>
204 No Content：表示客户端发送给服务端的请求得到了成功处理，但在返回的响应报文中不含实体的主体部分（没有资源可以返回）；</br>
206 Patial Content：表示客户端进行了范围请求，并且服务器成功执行了这部分的GET请求，响应报文中包含由Content-Range指定范围的实体内容。</br>
3xx （5种）</br>
301 Moved Permanently：永久性重定向，表示请求的资源被分配了新的URL，之后应使用更改的URL；</br>
302 Found：临时性重定向，表示请求的资源被分配了新的URL，希望本次访问使用新的URL；</br>
       301与302的区别：前者是永久移动，后者是临时移动（之后可能还会更改URL）</br>
303 See Other：表示请求的资源被分配了新的URL，应使用GET方法定向获取请求的资源；</br>
      302与303的区别：后者明确表示客户端应当采用GET方式获取资源</br>
304 Not Modified：表示客户端发送附带条件（是指采用GET方法的请求报文中包含if-Match、If-Modified-Since、If-None-Match、If-Range、If-Unmodified-Since中任一首部）的请求时，服务器端允许访问资源，但是请求为满足条件的情况下返回改状态码；</br>
307 Temporary Redirect：临时重定向，与303有着相同的含义，307会遵照浏览器标准不会从POST变成GET；（不同浏览器可能会出现不同的情况）；</br>
4xx （4种）</br>
400 Bad Request：表示请求报文中存在语法错误；</br>
401 Unauthorized：未经许可，需要通过HTTP认证；</br>
403 Forbidden：服务器拒绝该次访问（访问权限出现问题）</br>
404 Not Found：表示服务器上无法找到请求的资源，除此之外，也可以在服务器拒绝请求但不想给拒绝原因时使用；</br>
5xx （2种）</br>
500 Inter Server Error：表示服务器在执行请求时发生了错误，也有可能是web应用存在的bug或某些临时的错误时；</br>
503 Server Unavailable：表示服务器暂时处于超负载或正在进行停机维护，无法处理请求；</br>

#### ✸ 3.HTTP有哪些方法，get和post方法区别有哪些
get/post/request，</br>
(1)	get是从服务器上获取数据，post是向服务器传送数据；</br>
(2)	get传送的数据量较小，不能大于2KB。post传送的数据量较大，一般被默认为不受限制</br>
(3)	get安全性非常低，post安全性较高。</br>
GET请求只能进行url编码，而POST支持多种编码方式。</br>

#### ✸ 4.端口问题
6379	redis</br>
7001	weblogic</br>

#### ✸ 5.常用一些端口有哪些安全问题

#### ✸ 6.路由器、交换机的一些配置情况

#### ✸ 8.SQL注入的产生原理及分类和防范方法
分类：安装数据库分类，语句分类（select，insert等），按照位置分类（get/post/http header）

#### ✸ 9.SQL注入原理，产生条件，如何修复
原理：用户输入的内容传到web应用，没有经过过滤或者严格的过滤，被带入到了数据库中进行执行</br>
条件：用户能够控制自己的输入，没有严格过滤</br>
危害：</br></br>
（1）数据库信息泄露</br>
（2）网页篡改</br>
（3）恶意数据操作，删表，插入数据等</br>
修复：</br>
（1）用户输入验证</br>
（2）关键字转义</br>
（3）加密敏感数据</br>
（4）数据库权限控制：根据程序要求为特定的表设置特定的权限，如程序只需要select权限则只赋予select查询权限；</br>
（5）目录权限限制：WEB目录应至少遵循“可写目录不可执行，可执行目录不可写”的原则。</br>

#### ✸ 10.SQL注入里面的时间盲注，具体用到哪些函数？
length()/	sleep()/	ascii()/	substr()	benchmark()

#### ✸ 11.宽字节产生原理及解决办法？
宽字节注入是在GBK编码格式的数据库中，针对敏感符号前添加斜杠这种过滤方式，利用两个字节构成一个汉字的原理，我们在敏感符号前加%81-%FE之间的URL编码，与斜杠/（%5C）共同组成一个汉字，从而吃掉斜杠/，保证payload中的其他部分正常运行的一种注入方式。</br>
防御（两条合起来使用）（1）使用mysql_set_charset(GBK)指定字符集</br>
（2）使用mysql_real_escape_string进行转义</br>

#### ✸ 12.简要说明XSS漏洞分类及其危害
分类：反射性、存储型、DOM型</br>
危害：</br>
（1）窃取用户cookie，键盘记录</br>
（2）XSS配合其他漏洞getshell</br>
（3）刷流量，执行弹窗广告，强制发送电子邮件</br>
（4）传播蠕虫病毒</br>
防御：</br>
（1）基于特征的的防御（关键字匹配，特征匹配）：对所有提交信息进行规则匹配检查；</br>
（2）基于代码修改的防御。</br>

#### ✸ 13.CSRF、SSRF和重放攻击有什么区别？
CSRF是跨站请求伪造攻击，由客户端发起</br>
SSRF是服务器端请求伪造，由服务器发起</br>
重放攻击是将截获的数据包进行重放，达到身份认证等目的</br>

#### ✸ 14.CSRF 和 XSS 和 XXE 有什么区别，以及修复方式？
（1）XSS是跨站脚本攻击，用户提交的数据中可以构造代码来执行，从而实现窃取用户信息等攻击。</br>
修复方式：对字符实体进行转义、使用HTTP Only来禁止JavaScript读取Cookie值、输入时校验、浏览器与Web应用端采用相同的字符编码。</br>
（2）CSRF是跨站请求伪造攻击，XSS是实现CSRF的诸多手段中的一种，是由于没有在关键操作执行时进行是否由用户自愿发起的确认。</br>
修复方式：筛选出需要防范CSRF的页面然后嵌入Token、再次输入密码、检验Referer</br>
（3）XXE是XML外部实体注入攻击，XML中可以通过调用实体来请求本地或者远程内容，和远程文件保护类似，会引发相关安全问题，例如敏感文件读取。</br>
修复方式：XML解析库在调用时严格禁止对外部实体的解析。</br></br>

#### ✸ 15.同源策略，跨域请求（CSRF中讲）
同源就是两个站有相同的协议、域名、端口；</br>
JSONP 是一种非官方的跨域数据交互协议。</br>
CORS 是 HTTP 的一部分，它允许服务端来指定哪些主机可以从这个服务端加载资源。</br>
JSON和JSONP区别：</br>
（1）定义不同：JSON是一种基于文本的数据交换方式（不支持跨域），而JSONP是一种非官方跨域数据交互协议。</br>
（2）核心不同：json的核心是通过XmlHttpRequest获取非本页内容，而jsonp的核心则是动态添加<script>标签来调用服务器提供的js脚本。</br>

#### ✸ 16.XXE漏洞
原理：XXE漏洞也叫XML外部实体注入。由于没有禁止外部实体的加载,攻击者可以加载恶意外部文件，而应用程序解析输入的XML数据时,解析了攻击者伪造的外部实体导致产生XML漏洞。</br>
防御方式</br>
	1.禁止使用外部实体,例如ibxml_disable_entry_loader(true)</br>
	2.过滤用户提交的XML数据,防止出现非法内容</br>

#### ✸ 17.反序列化（在命令执行中讲）
序列化是将对象转换为可存储或传输的形式（把对象变成可以传输的字符串），反序列化就是将序列化之后的流还原为对象。</br>
魔法函数致使反序列化过程变得可控：_construct();_destruct();_sleep();_weakup();_toString()</br>
PHP反序列化漏洞防御：严格过滤unserialize函数的参数，及unserialize后的变量内容。</br>
Java反序列化漏洞</br>
由于很多站点或者RMI仓库等接口处存在java的反序列化功能，攻击者可以通过构造特定的恶意对象序列化后的流，让目标反序列化，从而达到自己的恶意预期行为，包括命令执行，甚至getshell等等。</br>
Apache Commons Collections是一个Collections收集器框架，提供诸如list、set、queue等功能对象。接口类是InvokerTransformer可以通过调用java的反射机制来调用任意函数。</br>
防御：在InvokerTransformer进行反序列化之前进行一个安全检查</br>

#### ✸ 18.伪协议（文件包含中讲PHP伪协议，phar）


#### ✸ 20.中间件解析漏洞产生的原因
原因：由于中间件本身缺陷，在对上传文件进行解析时会出现一些不可预料的错误从而导致被利用，进行文件上传绕过。

#### ✸ 21.服务器对HTML和后端脚本（PHP）是怎样解析的？

#### ✸ 22.说一下业务逻辑漏洞
#### ✸ 23.常见逻辑漏洞了解过吗
#### ✸ 24.说出至少三种业务逻辑漏洞，以及修复方式？
（1）密码找回漏洞中存在密码允许暴力破解、存在通用型找回凭证、可以跳过验证步骤、找回凭证可以拦包获取等方式来通过厂商提供的密码找回功能来得到密码</br>
（2）身份认证漏洞中最常见的是会话固定攻击和 Cookie 仿冒，只要得到 Session 或 Cookie 即可伪造用户身份</br>
（3）验证码漏洞中存在验证码允许暴力破解、验证码可以通过 Javascript 或者改包的方法来进行绕过</br>

#### ✸ 25.用过wireshark吗？用burpsuite抓过包吗？
（1）Fiddler 是以代理web服务器的形式工作的,它使用代理地址:127.0.0.1, 端口:8888. 当开启Fiddler会自动设置代理， 退出的时候它会自动注销代理。</br>
（2）wireshark是捕获机器上的某一块网卡的网络包。</br>

Buipsuite插件</br>
Autorize —— 强大的越权自动化测试工具</br>
在插件中设置一个低权限账号的 cookie，使用高权限的账户浏览所有功能。插件会自动用低权限账号重放请求，</br>
Turbo Intruder —— 短时间发送大量请求，增强版的intruder</br>

#### ✸ 26.sqlmap的参数
#### ✸ 27.sqlmap中tamper里面绕waf脚本如何工作的

#### ✸ 28.burpsuite常见功能
代理抓包改包，Repeater（重放），编码解码，爆破，Compater（比较）

#### ✸ 29.AWVS为什么不能扫描一些逻辑漏洞？

网络漏洞扫描工具，它通过网络爬虫测试你的网站安全，检测流行安全漏洞

#### ✸ 31.Nmap参数

#### ✸ 32.MSF、CS

#### ✸ 33.渗透测试方法，流程
信息收集：whois查询注册信息，真实IP、子域名查询、C段、旁站，指纹识别（web容器版本、服务器版本、cms版本、数据库版本、CDN、WAF），端口扫描，目录扫描等等；</br>
指纹时别：</br>
web容器：Apache,Nginx,IIS,Tomcat,Weblogic</br>
web应用：Wordpress，seacms，dedecms</br>
web服务器语言：PHP，Java，.NET，Nodejs</br>
web后端框架：ThinkPHP，Strust2，Spring Boot，Laravel(PHP)，CakePHP，Django，Ruby on Rails，Flask(Python)，Express(Node.js)</br>
web前端框架：Vue，angularjs，react，Highcharts</br>
web前端语言：Javascript，CSS，Jquery</br>
web运营商：移动，联通</br>
第三方内容：youtube</br>
CDN运营商：阿里云，电信</br>

渗透测试：</br>
（1）这里可以使用AWVS等大型漏洞扫描软件测试，与手工测试结合使用；</br>
（2）针对收集的信息进行相对应的测试。比如有无敏感信息泄露（后台用户密码，数据库配置文件备份文件密码等），端口爆破，解析漏洞尝试，cms版本的漏洞查询与测试；</br>
（3）接下来进行web漏洞方面测试，SQL注入，XSS，CSRF，命令执行，文件包含等等漏洞，</br>
（4）最后看有无逻辑漏洞。</br>
提权与权限维持：getshell后进行提权，然后后门植入权限维持</br>
痕迹清除：最后擦除自己渗透的痕迹，比如命令history、sql注入语句的历史、爆破历史、用户登录登出历史等等</br>
复测并撰写报告：最后写出此次渗透测试的报告。</br>

#### ✸ 34、如果注入将单引号过滤了，该怎么绕过？

#### ✸ 35、SQLmap的参数--os-shell，那么利用条件是什么？

#### ✸ 36.上传shell的有哪些具体方法

#### ✸ 37.发现 demo.jsp?uid=110 注入点，你有哪几种思路获取 webshell，哪种是优选？
（1）有写入权限的，构造联合查询语句使用using INTO OUTFILE，可以将查询的输出重定向到系统的文件中，这样去写入 WebShell</br>
（2）使用 sqlmap –os-shell 原理和上面一种相同，来直接获得一个 Shell，这样效率更高</br>
（3）通过构造联合查询语句得到网站管理员的账户和密码，然后扫后台登录后台，再在后台通过改包上传等方法上传 Shell</br>

#### ✸ 38.shell反弹

#### ✸ 39.内网/APP渗透了解过吗

#### ✸ 40..后渗透方面问题
后渗透框架


#### ✸ 41.代码审计
54

#### ✸ 42.反爬虫机制

#### ✸ 43.python代码怎么样？能够独立写出exp吗？

#### ✸ 44.你具体的实战经验，举例说说

#### ✸ 45.在win2003服务器中建立一个 .zhongzi文件夹用意何为？
隐藏文件夹，为了不让管理员发现你传上去的工具。

#### ✸ 46.审查元素得知网站所使用的防护软件，你觉得怎样做到的？
在敏感操作被拦截，通过界面信息无法具体判断是什么防护的时候，F12看HTML体部 比如护卫神就可以在名称那看到<hws>内容<hws>。</br>

#### ✸ 47.后台修改管理员密码处，原密码显示为*。你觉得该怎样实现读出这个用户的密码？
审查元素 把密码处的password属性改成text就明文显示了

#### ✸ 48.目标站发现某txt的下载地址为Client Validation，你有什么思路？
在file=后面尝试输入index.php下载他的首页文件，然后在首页文件里继续查找其他网站的配置文件，可以找出网站的数据库密码和数据库的地址。

#### ✸ 49.目标站禁止注册用户，找回密码处随便输入用户名提示：“此用户不存在”，你觉得这里怎样利用？
先爆破用户名，再利用被爆破出来的用户名爆破密码。</br>
其实有些站点，在登陆处也会这样提示；所有和数据库有交互的地方都有可能有注入。</br>

#### ✸ 50:某个防注入系统，在注入时会提示：
系统检测到你有非法注入的行为。 已记录您的ip xx.xx.xx.xx 时间:2016:01-23 提交页面:test.asp?id=15 提交内容:and 1=1。</br>
如何利用这个防注入系统拿shell？</br>
在URL里面直接提交一句话，这样网站就把你的一句话也记录进数据库文件了 这个时候可以尝试寻找网站的配置文件 直接上菜刀链接。具体文章参见：一句话木马在防注入中的重生-= 奇闻录-笑 =。</br>

#### ✸ 51.如何突破注入时字符被转义？
宽字符注入；hex编码绕过

#### ✸ 52.脏牛提权原理：
该漏洞具体为，Linux内核的内存子系统在处理写入时复制（copy-on-write, COW）时产生了竞争条件（race condition）。恶意用户可利用此漏洞，来获取高权限，对只读内存映射进行写访问。（A race condition was found in the way the Linux kernel’s memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings.）
竞争条件，指的是任务执行顺序异常，可导致应用崩溃，或令攻击者有机可乘，进一步执行其他代码。利用这一漏洞，攻击者可在其目标系统提升权限，甚至可能获得root权限。

#### ✸ 53.mysql的网站注入，5.0以上和5.0以下有什么区别？
mysql5.0以下没有information_schema这个系统表，无法列表名等，只能暴力跑表名。</br>
mysql5.0以下是多用户单操作，5.0以上是多用户多操做。</br>

#### ✸ 54、讲一下代码审计的思路。
（1）拿到源码安装网站，浏览网站大局</br>
（2）通读代码：</br>
查看网站节构（浏览源码文件夹了解大致目录）—看关键文件代码—看配置文件—读首页文件—追踪涉及到的文件</br>
（3）定向功能分析法：根据程序的逻辑结合网页浏览，猜测验证可能存在的漏洞</br>
（4）敏感函数参数回溯法：根据敏感函数逆向追踪参数传递过程</br>

#### ✸ 55、用过哪些工具，除了awvs等还有哪些厂商的扫描器？
漏洞扫描器代表：Nessus，不仅可以检查系统漏洞，还可以检查一部分的配置失误。</br>
WEB应用扫描器：appscan、webinspect。主要检测WEB应用数据提交、信息泄露等问题，对于系统、网络的基础情况一般不关注。</br>

#### ✸ 56、注入写入webshell需要绝对路径，一般怎么去找绝对路径？
（1）错误的url get参数，可能返回网站路径</br>
（2）搜索引擎获取：语法搜索页面报错内容，可能获取到网站路径</br>
Site:test.com warning</br>
Site:test.com "fatal error"</br>
（3）文件读取漏洞，读取配置文件获得</br>
（4）phpinfo信息中的DOCUMENT_ROOT参数获取</br>
（5）phpmyadmin爆路径：/phpmyadmin/themes/darkblue_orange/layout.inc.php</br>

#### ✸ 57丶http头部都有哪些常见的字段？
Accept 　　　　　　设置接受的内容类型</br>
Accept-Charset 　　设置接受的字符编码</br>
Accept-Encoding 　　设置接受的编码格式</br>
Accept-Datetime 　　设置接受的版本时间</br>
Connection 　　　　设置当前连接和hop-by-hop协议请求字段列表的控制选项</br>
Content-Length　　设置请求体的字节长度</br>
Content-Type 　　　设置请求体的MIME类型（适用POST和PUT请求）</br>
Cookie 　　　　　　设置服务器使用Set-Cookie发送的http cookie</br>
Date 　　　　　　　设置消息发送的日期和时间</br>
Expect 　　　　　　标识客户端需要的特殊浏览器行为</br>
Forwarded 　　　　披露客户端通过http代理连接web服务的源信息</br>
From 　　　　　设置发送请求的用户的email地址</br>
Host 　　设置服务器域名和TCP端口号，如果使用的是服务请求标准端口号，端口号可以省略</br>
Referer 　设置前一个页面的地址，并且前一个页面中的连接指向当前请求，意思就是如果当前请求是在A页面中发送的，那么referer就是A页面的url地址</br>
User-Agent 　　　用户代理的字符串值</br>
Via 　　　　　　　通知服务器代理请求</br>
X-Forwarded-For 　一个事实标准，用来标识客户端通过HTTP代理或者负载均衡器连接的web服务器的原始IP地址</br>

#### ✸ 58、当一个网站发现已经被入侵了，你该怎么处理？

#### ✸ 59、路由器与交换机的工作原理。

#### ✸ 60、nmap的都有哪些扫描模式？

#### ✸ 61、nmap的tcp扫描是怎么判断扫描结果的。

#### ✸ 62、当遇到防火墙waf，都有哪些绕过的方法？

#### ✸ 63、xxe漏洞有了解吗，是什么原理呢？

#### ✸ 64、python脚本有写过么？讲讲你是怎么写的。
爬虫脚本，举例

#### ✸ 65、用过哪些抓包软件？wireshark是如何抓取指定流量？

#### ✸ 66、中间件的漏洞都有哪些？

#### ✸ 67、提权一般都有哪些方法？









权限维持的方法</br>
msf有哪些常用的功能，你经常使用哪些功能或者模块</br></br>
cs和msf有什么不同，你觉得哪个好用一点</br>
UAC是什么？怎么bypass UAC</br>
说一下win2003-win2016分别如何获取hash</br>
说一下win2003-win2016分别如何获取明文密码</br>
获取hash有哪些常用的方式</br>
linux系统如何获取hash，怎么破解</br>
内网如何进行信息收集</br>
内网转发是什么意思？原理是什么</br>
端口转发有哪些常用工具？什么情形下可以用到端口转发</br>
反弹shell有什么用，有哪些常用工具</br>
代理转发和端口转发、shell反弹有什么不一样，为什么要进行代理转发</br>
代理转发有什么常用工具</br>
服务器只开放了80端口，能不能进行代理转发？用什么方式？</br>
服务器只开放了22端口，能不能进行代理转发？用什么方式？</br>
DNS欺骗原理是什么？你觉得什么情形下可以用到DNS欺骗</br>
拿下一台windows主机，你会搜集哪些信息，怎么搜集</br>
拿下一台linux主机，你会搜集哪些信息，怎么搜集</br>
DC和AD是什么</br>
说一下NTLM协议，基于这个协议你没有什么攻击方式</br>
域环境如何提权</br>
域环境如何获取hash</br>
域环境如何获取明文密码</br>
黄金票据和白银票据的原理和利用方式，有什么区别</br>
windows下cmd如何远程下载文件</br>
reverse_tcp和bind_tcp区别</br>
说说windows系统和linux系统提权</br>
sqlserver只有db_owner权限如何利用</br>
Windows、Linux、数据库的加固降权思路，任选其一</br>
mysql UDF提权5.1以上版本和5.1以下有什么区别,以及需要哪些条件?</br>
内网机器无法直接连接外网，是什么原因造成的，如何解决内网机器远控上线的问题？</br>
域环境中，如何快速定位安装了sqlserver数据库的机器</br>
powershell用过吗？你用过哪些powershell工具？</br>
有哪些常见的免杀方式？</br>
某台内网机器连接外网需要先连接代理服务器，你想要这台机器的远控正常上线，怎么做？</br>
tcp协议无法出网，造成内网数据无法传到外网，你有没有解决办法？</br>
