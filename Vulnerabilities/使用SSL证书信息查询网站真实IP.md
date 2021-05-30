# 使用SSL证书信息查询网站真实IP 
- 工具：[censys](https://censys.io/ipv4)</br>
- 使用指导文档：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/censys%20(1).png height="350" width="700"></br>

### **查询网站真实IP步骤**
（1）使用censys引擎，网站证书的搜索查询参数为：parsed.names:xxx.com，只显示有效证书的查询参数为:tags.raw:trusted。</br>
（2）在Censys上选择Certificates，用多个参数的组合进行查询：</br>
```shell
parsed.names: baidu.com and tags.raw: trusted
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/censys%20(2).png height="350" width="700"></br>
（3）逐个查看搜索结果，打开某个结果，点击右侧Explore，点击What’s using this certificate? > IPv4 Hosts即可查看到IP：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/censys%20(3).png height="350" width="700"></br>
（4）使用该证书的IPv4主机列表，真实IP就存在结果中。</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/censys%20(4).png height="350" width="700"></br>
