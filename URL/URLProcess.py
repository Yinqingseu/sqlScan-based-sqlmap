#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#SQL注入检测URL处理类：判断url是否可注入、是否稳健、是否可连接
#SQL注入测试网站：http://testphp.vulnweb.com/artists.php?artist=1
import threading
import sys
import re
import urlparse
reload(sys)
sys.setdefaultencoding("utf-8")

#伪静态URL判断，处理：加"*"
#入口参数为url添加位置：所有数字后面添加"*"，静态网址名后添加"*"
#返回添加了"*"的url,
def staticURLProcess(url):
    urlList = urlparse.urlparse(url)
    # print 'path:',urlList.path
    pathList = urlList.path.split("/")[1:]  # 获取、分解url路径组成,第一个为空格
    # print 'pathList:',pathList
    returnList = []
    # 传入url域名
    domain = [urlList.scheme, '://', urlList.netloc]
    domain = ''.join(domain)
    # print domain
    returnList.append(domain)
    #处理url的path部分：
    # url中存在静态网页后缀 处理/xx/id/4422sd.(html)
    netSuffix = 'html|htm|shtml|stm|shtm'  # 静态网址后缀名
    if re.search(netSuffix, url): #静态网址名后添加"*"
        suffix = "." + re.search(netSuffix, url).group()  # 获取匹配的网页后缀
        # 处理url的每一个目录名：
        for i in pathList:
            if re.search(netSuffix, i):  # 去除静态url后缀，静态网页的名称后添加*
                i = re.sub('\.html|\.htm|\.shtml|\.stm|\.shtm', '', i)  # 将静态网页后缀替换为空
                returnList.append(i + "*")
            elif i.isdigit():  # 纯数字目录后添加"*"
                returnList.append(i + "*")
            else:
                returnList.append(i)
        url = '/'.join(returnList) + suffix  # /连接url各个部分
        return url
    else:# url中不存在静态网页后缀：/xx/id/4422
        flag = 0 #标记是否存在数字型目录
        for i in pathList:
            if i.isdigit():
                flag = 1
                returnList.append(i+"*")
            else:
                returnList.append(i)
        # print 'returnLsit:',returnList
        url = '/'.join(returnList)
        # print 'joindeUrl:',url
        if flag == 0:
            return None
        else:
            return url

# 检查url中是否含有"*",有则去除"*"标记
# 返回：去除"*"的url
def removeTag(url):
    if '*' in url:
        return ''.join(url.split('*'))
    else:
        return url

#URL处理类
class URLProcess(threading.Thread):
    def __init__(self,url):
        self.url = url
        threading.Thread.__init__(self)
        self.injectedUrl = ''
    # 判断url是否GET可注入（是否含参）
    # 可注入返回True;否则返回False
    # 两种含参url:1. http://xxx.xxx.xxx/?id=xxx&name=xxx  2. http://xxx.xxx.xxx/xx/id/xx(.html|.htm)
    def injectableUrl(self):
        if '?' in self.url:  #非伪静态URL含参判断
            return self.url
        elif staticURLProcess(self.url): #伪静态url判断并标记
            return staticURLProcess(self.url)
        else:#不可注入的url
            return None

    def run(self): #线程创建后会直接运行run函数
        self.injectedUrl = self.injectableUrl()

    def getDatas(self):
        return self.injectedUrl

if __name__ == '__main__':
    url = 'http://web.safe.com/scan/holeshow/id/1.html'
    url1 = 'http://www.cnitpm.com/pm1/34523/id/42462'
    url2 = 'http://www.cnitpm.com'
    t = URLProcess(url)
    print 'injectableUrl:',t.injectableUrl()
    print 'removeTag:',removeTag(t.injectableUrl())