## Java反序列化漏洞
### 原理
序列化是将对象转换为可存储或传输的形式（把对象变成可以传输的字符串），反序列化就是将序列化之后的流还原为对象。</br>
魔法函数致使反序列化过程变得可控：_construct();_destruct();_sleep();_weakup();_toString()</br>
PHP反序列化漏洞防御：严格过滤unserialize函数的参数，及unserialize后的变量内容。</br>

**JAVA WEB中的序列化和反序列化**</br>
·  java.io.ObjectOutputStream 代表对象输出流，它的 writeObject() 方法可对参数指定的对象进行序列化，把得到的字节序列写到一个目标输出流中</br>

·  java.io.ObjectInputStream 代表对象输入流，它的 readObject() 方法从一个源输入流中读取字节序列，再把它们反序列化为一个对象，并将其返回</br>

只有实现了 Serializable 和 Externalizable 接口的类的对象才能被序列化和反序列化。Externalizable 接口继承自 Serializable 接口，实现 Externalizable 接口的类完全由自身来控制反序列化的行为，而实现 Serializable 接口的类既可以采用默认的反序列化方式，也可以自定义反序列化方式。</br>

对象序列化包括如下步骤：</br>

创建一个对象输出流，它可以包装一个其他类型的目标输出流，如文件输出流</br>
通过对象输出流的 writeObject() 方法将对象进行序列化</br>
对象反序列化的步骤如下：</br>

创建一个对象输入流，它可以包装一个其他类型的源输入流，如文件输入流</br>
通过对象输入流的 readObject() 方法将字节序列反序列化为对象</br>

**Java反序列化漏洞</br>**
由于很多站点或者RMI仓库等接口处存在java的反序列化功能，攻击者可以通过构造特定的恶意对象序列化后的流，让目标反序列化，从而达到自己的恶意预期行为，包括命令执行，甚至getshell等等。</br></br>

例如Apache Commons Collections是一个Collections收集器框架，其中某个接口类InvokerTransformer可以通过调用java的反射机制来调用任意函数，实现任意代码执行。</br>
**防御**：在InvokerTransformer进行反序列化之前进行一个安全检查</br>
✸ Apache-CommonsCollections 是众多Java 反序列化漏洞中重要的Gadget，请简单描述 CommonsCollections(3.1) 为什么能用来执行任意命令</br>
参考解答：</br>
CommonsCollections组件中存在一个可以进行反射调用的方法（InvokerTransform）它具备反射调用的能力且参数完全可控！，此方法在反序列化对象的时候没有进行任何校验，导致可以反序列化任意类（如 Runtime ），通过构造恶意代码，即可实现任意命令执行。

✸ Fastjson反序列化原理
fastjson的功能就是将json格式转换为类、字符串等供下一步代码的调用，或者将类、字符串等数据转换成json数据进行传输，有点类似序列化的操作。

### 分类
常见的Java反序列化漏洞包括：</br>

1、Apache Commons Collections 反序列化漏洞（CVE-2015-7501）</br>
https://www.cnblogs.com/200knownsec/p/9082071.html</br>

2、Spring RMI反序列化漏洞</br>

3、shiro反序列化漏洞</br>
https://baijiahao.baidu.com/s?id=1738226401734568279&wfr=spider&for=pc</br>

4、fastjson反序列化</br>
https://javasec.org/java-vuls/FastJson.html

5、WebLogic XMLDecoder 反序列化漏洞（CVE-2017-10271）</br>

6、WebSphere 反序列化漏洞（CVE-2017-2894）</br>

7、JBoss Intercepting Class Loaders 反序列化漏洞（CVE-2015-7502）</br>

8、Xstream反序列化</br>
https://github.com/Cryin/Paper/blob/master/Xstream%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%BF%AE%E5%A4%8D%E6%96%B9%E6%A1%88.md</br>

### 漏洞利用



### 漏洞修复

