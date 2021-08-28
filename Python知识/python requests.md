## python requests
### 一、requests几种使用方式
```python
import requests
r = requests.get('https://api.github.com/events')
r = requests.post('http://httpbin.org/post', data = {'key':'value'})
r = requests.put('http://httpbin.org/put', data = {'key':'value'})
r = requests.delete('http://httpbin.org/delete')
r = requests.head('http://httpbin.org/get')
r = requests.options('http://httpbin.org/get')
```
### 二、爬取百度主页
```python
import requests

response = requests.get(url='https://www.baidu.com/')
response.encoding = 'utf-8'
print(response)  # <Response [200]>
# 返回响应状态码
print(response.status_code)  # 200
# 返回响应文本
# print(response.text)
print(type(response.text))  # <class 'str'>
#将爬取的内容写入xxx.html文件
with open('baidu.html', 'w', encoding='utf-8') as f:
    f.write(response.text)
```
### 三、GET请求讲解
#### params请求参数
```python
import requests
from urllib.parse import urlencode
#以百度搜索“蔡徐坤”为例
# url = 'https://www.baidu.com/s?wd=%E8%94%A1%E5%BE%90%E5%9D%A4'
'''
方法1：
url = 'https://www.baidu.com/s?' + urlencode({"wd": "蔡徐坤"})
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36'
}
response = requests.get(url，headers）
'''
#方法2：
url = 'https://www.baidu.com/s?'
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36'
}
# 在get方法中添加params参数
response = requests.get(url, headers=headers, params={"wd": "蔡徐坤"})
print(url) # https://www.baidu.com/s?wd=%E8%94%A1%E5%BE%90%E5%9D%A4
# print(response.text)
with open('xukun.html', 'w', encoding='utf-8') as f:
    f.write(response.text)
```
#### cookies参数使用
携带登录cookies破解github登录验证<br>
方法一：在请求头中拼接cookies<br>
```python
import requests

# 请求url
url = 'https://github.com/settings/emails'

# 请求头
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36',
    # 在请求头中拼接cookies
    # 'Cookie': 'has_recent_activity=1; _ga=GA1.2.1416117396.1560496852; _gat=1; tz=Asia%2FShanghai; _octo=GH1.1.1728573677.1560496856; _device_id=1cb66c9a9599576a3b46df2455810999; user_session=1V8n9QfKpbgB-DhS4A7l3Tb3jryARZZ02NDdut3J2hy-8scm; __Host-user_session_same_site=1V8n9QfKpbgB-DhS4A7l3Tb3jryARZZ02NDdut3J2hy-8scm; logged_in=yes; dotcom_user=TankJam; _gh_sess=ZS83eUYyVkpCWUZab21lN29aRHJTUzgvWjRjc2NCL1ZaMHRsdGdJeVFQM20zRDdPblJ1cnZPRFJjclZKNkcrNXVKbTRmZ3pzZzRxRFExcUozQWV4ZG9kOUQzZzMwMzA2RGx5V2dSaTMwaEZ2ZDlHQ0NzTTBtdGtlT2tVajg0c0hYRk5IOU5FelYxanY4T1UvVS9uV0YzWmF0a083MVVYVGlOSy9Edkt0aXhQTmpYRnVqdFAwSFZHVHZQL0ZyQyt0ZjROajZBclY4WmlGQnNBNTJpeEttb3RjVG1mM0JESFhJRXF5M2IwSlpHb1Mzekc5M0d3OFVIdGpJaHg3azk2aStEcUhPaGpEd2RyMDN3K2pETmZQQ1FtNGNzYnVNckR4aWtibkxBRC8vaGM9LS1zTXlDSmFnQkFkWjFjanJxNlhCdnRRPT0%3D--04f6f3172b5d01244670fc8980c2591d83864f60'
}
github_res = requests.get(url, headers=headers)
```
方法二：将cookies做为get的一个参数<br>
```python
import requests
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36'}
cookies = {
    'Cookie': 'has_recent_activity=1; _ga=GA1.2.1416117396.1560496852; _gat=1; tz=Asia%2FShanghai; _octo=GH1.1.1728573677.1560496856; _device_id=1cb66c9a9599576a3b46df2455810999; user_session=1V8n9QfKpbgB-DhS4A7l3Tb3jryARZZ02NDdut3J2hy-8scm; __Host-user_session_same_site=1V8n9QfKpbgB-DhS4A7l3Tb3jryARZZ02NDdut3J2hy-8scm; logged_in=yes; dotcom_user=TankJam; _gh_sess=ZS83eUYyVkpCWUZab21lN29aRHJTUzgvWjRjc2NCL1ZaMHRsdGdJeVFQM20zRDdPblJ1cnZPRFJjclZKNkcrNXVKbTRmZ3pzZzRxRFExcUozQWV4ZG9kOUQzZzMwMzA2RGx5V2dSaTMwaEZ2ZDlHQ0NzTTBtdGtlT2tVajg0c0hYRk5IOU5FelYxanY4T1UvVS9uV0YzWmF0a083MVVYVGlOSy9Edkt0aXhQTmpYRnVqdFAwSFZHVHZQL0ZyQyt0ZjROajZBclY4WmlGQnNBNTJpeEttb3RjVG1mM0JESFhJRXF5M2IwSlpHb1Mzekc5M0d3OFVIdGpJaHg3azk2aStEcUhPaGpEd2RyMDN3K2pETmZQQ1FtNGNzYnVNckR4aWtibkxBRC8vaGM9LS1zTXlDSmFnQkFkWjFjanJxNlhCdnRRPT0%3D--04f6f3172b5d01244670fc8980c2591d83864f60'
}

github_res = requests.get(url, headers=headers, cookies=cookies)

print('15622792660' in github_res.text)
```
### 四、response响应
```python
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.76 Mobile Safari/537.36',
}

response = requests.get('https://www.github.com', headers=headers)

# response响应
print(response.status_code)  # 获取响应状态码
print(response.url)  # 获取url地址
print(response.text)  # 获取文本
print(response.content)  # 获取二进制流
print(response.headers)  # 获取页面请求头信息
print(response.history)  # 上一次跳转的地址
print(response.cookies)  # # 获取cookies信息
print(response.cookies.get_dict())  # 获取cookies信息转换成字典
print(response.cookies.items())  # 获取cookies信息转换成字典
print(response.encoding)  # 字符编码
print(response.elapsed)  # 访问时间
```
### 五、requests高级用法
#### 1、文件上传
```python
import requests
url = "http://httpbin.org/post"
files= {"files":open("test.jpg","rb")}
response = requests.post(url,files=files)
print(response.text)
```
#### 2、获取cookie
```python
import requests
response = requests.get('https://www.baidu.com')
print(response.cookies)
for key,value in response.cookies.items():
    print(key,'==',value)
```
#### 3、会话维持
cookie的一个作用就是可以用于模拟登陆，做会话维持<br>
```python
import requests
session = requests.session()
session.get('http://httpbin.org/cookies/set/number/12456')
response = session.get('http://httpbin.org/cookies')
print(response.text)
```
#### 4、证书验证
关闭证书验证,消除验证证书的警报<br>
```python
from requests.packages import urllib3
import requests
 
urllib3.disable_warnings()
response = requests.get('https://www.12306.cn',verify=False)
print(response.status_code)
````
#### 5、超时设置
```python
# 超时设置
# 两种超时:float or tuple
# timeout=0.1  # 代表接收数据的超时时间
# timeout=(0.1,0.2)  # 0.1代表链接超时  0.2代表接收数据的超时时间

import requests

response = requests.get('https://www.baidu.com',
                        timeout=0.0001)
```
#### 6、使用代理
```python
# 官网链接: http://docs.python-requests.org/en/master/user/advanced/#proxies

# 代理设置:先发送请求给代理,然后由代理帮忙发送(封ip是常见的事情)
import requests
proxies={
    # 带用户名密码的代理,@符号前是用户名与密码
    'http':'http://tank:123@localhost:9527',
    'http':'http://localhost:9527',
    'https':'https://localhost:9527',
}
response=requests.get('https://www.12306.cn',
                     proxies=proxies)
print(response.status_code)


# 支持socks代理,安装:pip install requests[socks]
import requests
proxies = {
    'http': 'socks5://user:pass@host:port',
    'https': 'socks5://user:pass@host:port'
}
respone=requests.get('https://www.12306.cn',
                     proxies=proxies)

print(respone.status_code)
```
