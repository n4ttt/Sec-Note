## CSRF漏洞原理
跨站请求伪造(Cross-site request forgery),攻击者利用用户已经获得的web应用程序的身份验证,诱导其执行非本意的操作。</br>
CSRF攻击两个条件</br>
（1）用户登录受信任网站A,并在本地生成cookie</br>
（2）在不登出A的情况下,访问危险网站B

## CSRF漏洞危害
（1）以用户名义发送邮件，发消息，盗取账户，购买商品，虚拟货币转账等；</br>
（2）个人隐私泄露以及财产安全问题

## CSRF漏洞利用
### （1）GET类型的CSRF
GET型CSRF利用只需要一个HTTP请求，</br>
正常HTTP请求页面：http://<span></span>www.aaa.com/csrf.php?aaa=111</br>
修改后的请求页面为：http://<span></span>www.aaa.com/csrf.php?aaa=222，此页面发出一次请求，即完成一次攻击。

### （2）POST类型的CSRF
利用方式通常就是一个自动提交的表单，如：
```
<form action=http://www.aaa.com/csrf.php method=POST>
<input type=”text” name=”a” value=”111”>
</form>
<script> document.forms[0].submit();</script>
```
访问该页面后，表单会自动提交，相当于用户完成了一次POST操作。

### CSRF漏洞利用（POST请求JSON入参格式）
详见(CSRF漏洞利用（POST请求JSON入参格式）)[https://github.com/n4ttt/Sec-Note/blob/main/Vulnerabilities/CSRF%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%EF%BC%88POST%E8%AF%B7%E6%B1%82JSON%E5%85%A5%E5%8F%82%E6%A0%BC%E5%BC%8F%EF%BC%89.md]
### （3）CSRF与XSS漏洞结合起来利用
攻击者可以通XSS来触发CSRF攻击，触发方法是将攻击语句复制到XSS漏洞中，即可执行成功。</br>
参考payload：
```
<img src=’http://192.168.11.11/DVWA/vulnerabilities/scrf?password_new=pass&password_conf=pass&Change=Change#’ alt=’over’>
```
触发效果：退出后，密码被更改

## CSRF漏洞防御
（1）验证referer字段----如果是其他网站的话,就有可能是CSRF攻击,则拒绝该请求</br>
（2）添加token验证----可以在HTTP请求中以参数的形式加入一个随机产生的token,并在服务器建立一个拦截器来验证这个token,如果请求中没有token或者不正确,则有可能是CSRF攻击而拒绝其请求.</br>
（3）二次验证----在转账等关键操作之前提供当前用户的密码或者验证码.</br>
（4）养成良好上网习惯----不要随意点击链接和图片,及时退出长时间不使用的登录账户,安装安全防护软件.

## CSRF与XSS区别：
### （1）原理角度
XSS是将恶意代码插入到HTML页面中，当用户浏览页面时，插入的HTML代码会被执行，从而达到最终目的；

### （2）其他角度
CSRF比XSS漏洞危害更高，相对XSS而言较难防御</br>
XSS有局限性，而CSRF没有局限性</br>
XSS针对客户端，而XSRF针对服务端</br>
XSS是利用合法用户获取其信息，而CSRF是伪造成合法用户发起请求。
