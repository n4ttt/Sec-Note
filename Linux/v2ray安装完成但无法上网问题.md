v2ray安装过程没问题，但是安装之后发现本地无论怎么更改配置信息，都无法连接服务器进行上网。</br>

**（添加防火墙规则可以解决）**</br>

本文说的是安装之后不能连接的情况，不是因为国内网络原因导致的不能访问，如果是因为可能被–墙导致的无法连接，可以通过下面链接进行排查：服务器端口或服务无法访问解决办法
从服务器中查看v2ray的运行状态，发现v2ray是运行着的：</br>
```
root@VJP:~# systemctl status v2ray
● v2ray.service - V2Ray Service
   Loaded: loaded (/etc/systemd/system/v2ray.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2018-01-03 19:11:26 CST; 1s ago
 Main PID: 16814 (v2ray)
    Tasks: 6 (limit: 4915)
   CGroup: /system.slice/v2ray.service
           └─16814 /usr/bin/v2ray/v2ray -config /etc/v2ray/config.json

Jan 03 19:11:26 VJP systemd[1]: Started V2Ray Service.
Jan 03 19:11:26 VJP v2ray[16814]: V2Ray v3.5 (die Commanderin) 20171228
Jan 03 19:11:26 VJP v2ray[16814]: An unified platform for anti-censorship.
```
再查看端口占用，发现v2ray并没有监听我们的公网IP，只监听了一个IPV6：
```
root@xxx:~# netstat -apn | grep v2ray
tcp6       0      0 :::21xxx                :::*                    LISTEN      22194/v2ray
unix  3      [ ]         STREAM     CONNECTED     788043   22194/v2ray
```
看来可能是v2ray获取IP导致的问题，这样我们能不能指定IP让v2ray去监听？</br>

按照文档中说的，我们可以在配置文件中添加一个listen字段，用于指定v2ray监听指定的IP。</br>

v2ray默认配置文件在/etc/v2ray/conf.json，我们只需编辑这个文件并添加一行就行了：</br>
```
vim /etc/v2ray/config.json

{
  "log" : {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbound": {
    "port": 21xxx,
    "protocol": "vmess",
        "listen":"12.34.56.78", <------就是这一行
    "settings": {
      "clients": [
        {
          "id": "e59b0cba-204c-4d58-85a5-xxxxxxxxxxxxxxx",
          "level": 1,
          "alterId": 64
        }
      ]
    }
  },
  "outbound": {
    "protocol": "freedom",
    "settings": {}
  },
  "outboundDetour": [
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "strategy": "rules",
    "settings": {
      "rules": [
        {
          "type": "field",
          "ip": [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "::1/128",
            "fc00::/7",
            "fe80::/10"
          ],
          "outboundTag": "blocked"
        }
      ]
    }
  }
```
将上述listen字段中的12.34.56.78替换成真实IP，保存，退出，然后用v2ray测试配置文件是否正确：</br>
```
root@xxx:/etc/v2ray# /usr/bin/v2ray/v2ray --test --config /etc/v2ray/config.json
V2Ray v3.5 (die Commanderin) 20171228
An unified platform for anti-censorship.
Configuration OK.
```
这样表示配置文件没什么问题，重启即可：</br>
```
systemctl restart v2ray
```
再次检查v2ray的端口监听情况：</br>
```
root@xxx:~# netstat -apn | grep v2ray
tcp        0      0 104.238.xxx.xxx:191xx   0.0.0.0:*               LISTEN      16814/v2ray
unix  3      [ ]         STREAM     CONNECTED     3918255  16814/v2ray
```
这样，v2ray就配置成功了。</br>
