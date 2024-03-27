## Java反序列化漏洞
### 原理
序列化是将对象转换为可存储或传输的形式（把对象变成可以传输的字符串），反序列化就是将序列化之后的流还原为对象。</br>
魔法函数致使反序列化过程变得可控：_construct();_destruct();_sleep();_weakup();_toString()</br>
PHP反序列化漏洞防御：严格过滤unserialize函数的参数，及unserialize后的变量内容。</br>

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



### 漏洞利用



### 漏洞修复

