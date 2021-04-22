# Java代码审计-常规漏洞
### **概述**
*Java代码审计，常规漏洞XXE（外部实体注入）。*
### **一、漏洞-XXE**
**介绍**<br>
XML文档结构包括XML声明、DTD文档类型定义（可选）、文档元素。文档类型定义(DTD)的作用是定义 XML 文档的合法构建模块。DTD 可以在 XML 文档内声明，也可以外部引用。<br>
- 当允许引用外部实体时，恶意攻击者即可构造恶意内容访问服务器资源,如读取passwd文件：
```java
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [
<!ENTITY test SYSTEM "file:///ect/passwd">]>
<msg>&test;</msg>
```
**漏洞示例**<br>
以org.dom4j.io.SAXReader为例，仅展示部分代码片段：
```java
String xmldata = request.getParameter("data");
SAXReader sax = new SAXReader();
// 创建一个SAXReader对象
Document document = sax.read(new ByteArrayInputStream(xmldata.getBytes()));
// 获取document对象,如果文档无节点，则会抛出Exception提前结束
Element root = document.getRootElement(); //获取根节点
List rowList = root.selectNodes("//msg");
Iterator<?> iter1 = rowList.iterator();
if (iter1.hasNext()) {
    Element beanNode = (Element) iter1.next();
    modelMap.put("success",true);
    modelMap.put("resp",beanNode.getTextTrim());
}
...
```
**代码审计**<br>
XML解析一般在导入配置、数据传输接口等场景可能会用到，涉及到XML文件处理的场景可留意下XML解析器是否禁用外部实体，从而判断是否存在XXE。部分XML解析接口如下：
```java
javax.xml.parsers.DocumentBuilder
javax.xml.stream.XMLStreamReader
org.jdom.input.SAXBuilder
org.jdom2.input.SAXBuilder
javax.xml.parsers.SAXParser
org.dom4j.io.SAXReader 
org.xml.sax.XMLReader
javax.xml.transform.sax.SAXSource 
javax.xml.transform.TransformerFactory 
javax.xml.transform.sax.SAXTransformerFactory 
javax.xml.validation.SchemaFactory
javax.xml.bind.Unmarshaller
javax.xml.xpath.XPathExpression
...
```
**修复建议**<br>
使用XML解析器时需要设置其属性，禁止使用外部实体，以上例中SAXReader为例，安全的使用方式如下:
```java
sax.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
sax.setFeature("http://xml.org/sax/features/external-general-entities", false);
sax.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
其他XML解析器的安全使用方式可以参考：*https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html*
