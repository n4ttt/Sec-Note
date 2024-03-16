## XSS原理：
跨站脚本攻击（Cross Site Script），攻击者往web页面或者url里插入恶意JavaScript脚本代码，如果web应用程序对于用户输入的内容没有过滤，那么当正常用户浏览该网页的时候，恶意代码会被执行，从而达到恶意攻击正常用户的目的。

## 漏洞产生条件：
（1）用户可以控制的输入点</br>
（2）输入能返回到前端页面上被浏览器当成脚本语言解析执行

## XSS分类：
反射性XSS：存储区（URL）；插入点（HTML）</br>
存储型XSS：存储区（后端数据库）；插入点（HTML）</br>
DOM型XSS：存储区（URL/后端数据库/前端储存）；插入点（前端JavaScript）

## 利用方式：
### XSS平台：在线XSS平台或自己搭建的XSS平台
### beef软件
### XSS变形：
** 1.利用<>构造html/JS: **
```
<script>alert(/xss/)</script>
```
** 2.伪协议方式构造XSS：** </br>
```
<a href="javascript:alert(/xss/)>touch me</a>
<a href="javascript:alert(/xss/)>touch me</a>
```
** 3.事件利用：** </br>
```
<img src='./smile.jpg' onmouseover='alert(/xss/)'>
<input type="text" onkeydown="alert(/xss/)">
<input type="text" onkeyup="alert(/xss/)">
<input type="button" onclick="alert(/xss/)">
<img src='#' onerror='alert(/xss/)'>
 ```
** 4.利用CSS触发XSS（过时）** </br>
行内样式</br>
```
<div style='backgroud-image:url(javascript(/xss/))'>
```
页内样式</br>
  ```
<style>=Body{backgroud-image:url(javascript(/xss/))}</style>
```
外部样式</br>
  ```
<link rel="stylesheet" type="text/css" href="./xss.css"><div>hello<div>
```
** 5.其他标签以及手法**</br>
```
<svg onload="alert(/xss/)"></br>
<input onfocus=alert(/xss/) autofocus></br>
```
### XSS绕过
（1）大小写转换</br>
（2）引号使用：HTML中对引号使用不敏感，但是过滤函数对引号很严格</br>
（3）左斜杠（/）代替空格</br>
（4）双写绕过：<scri<script>pt></br>
（5）对标签属性值进行转码，用来绕过过滤</br>
（6）拆分跨站</br>
（7）css中的变形

## 漏洞危害：
（1）窃取用户cookie，冒充用户身份进入网站</br>
（2）键盘记录</br>
（3）客户端信息探查</br>
（4）XSS getshell</br>
（5）劫持用户会话，执行任意操作</br>
（6）刷流量，执行弹窗广告</br>
（7）传播蠕虫病毒……

## 漏洞防御：
（1）使用XSS filter，过滤用户（客户端）提交的有害信息；</br>
（2）输入过滤，对所有用户输入的内容都有进行过滤；</br>
（3）输入验证，对用户提交的信息进行有效验证（是否包含合法字符、字符串长度限制、是否符合特殊格式要求等等）</br>
（4）输出编码（htmlspecialchars函数），HTML编码主要是用对应的HTML实体代替字符。
