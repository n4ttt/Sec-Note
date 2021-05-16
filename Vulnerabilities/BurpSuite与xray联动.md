# BurpSuite与xray联动
## (一)Xray参数配置
***xray命令：***
```shell
xray_windows_amd64.exe webscan --listen 127.0.0.1:9998 --html-output 111.html
-h 帮助  
--listen 监听端口   
--html-output 将扫描结果导出到html文件
```
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities1.png>

## (二)BurpSuite配置代理服务器
在用户选项中添加代理服务器，填入端口和ip地址，如下图所示：</br>
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities2.png>

## (三)联动使用
- （1）按照步骤（一）开启xray，xray属于被动扫描，经过其监听的端口流量会被xray进行扫描
- （2）按照步骤（二）配置BurpSuite的代理服务器；BurpSuite的每个传出请求会被发送到此代理服务器；
- （3）访问目标网站，在BurpSuite的Target选项上找到目标网站，右键，开始爬虫扫描；xray就会自动扫描；
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities3.png>
- xray扫描结束，将结果文件打开进行分析。
<img src=https://github.com/nathanzeng001/Sec-Note/blob/main/Image/Vulnerabilities4.png>
