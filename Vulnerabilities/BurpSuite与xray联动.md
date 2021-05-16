# BurpSuite与xray联动
## (一)Xray参数配置
***xray命令：***
```shell
xray_windows_amd64.exe webscan --listen 127.0.0.1:9998 --html-output 111.html
    选项：-h 帮助  --listen 监听端口   --html-output 将扫描结果导出到html文件
```


## (二)BurpSuite配置代理服务器
在用户选项中添加代理服务器，填入端口和ip地址，如下图所示：</br>


