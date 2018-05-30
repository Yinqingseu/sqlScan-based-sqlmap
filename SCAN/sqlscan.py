#!/usr/bin/python
# -*-coding:utf-8-*-
import re
import urlparse
import requests
import urllib2
import Queue
import gzip,StringIO
import threading
import time
import json
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import os
#SQL注入扫描脚本
'''—————————全局变量定义 ————————————————————————————'''
crawlUrl = [] #从爬虫模块获取的测试url
deadUrl = [] #存放死链
testUrl = [] #crawlUrl经URL处理模块获得的可注入URL(存在"*"标记)
safeUrl = [] #存放不可注入url
holeUrl = [] #存在漏洞的url  [url1,url2...]，去除"*"标记
staticUrl = [] #存放伪静态url
holeMethod = [] #url对应验证方法 [get,post]
holePayload = [] #url对应验证payload，[[payload1,payload2],[payload3,payload4]] 列表嵌套列表
holePayloadType = [] #payload对应请求类型 [[1,2,3],[1,2]]
injectedPayloads = {} #存放 可注入url：payloads，payloads:type
scanDatas = {} #存放扫描结果

'''
多线程爬取URL BEGIN
广度优先遍历：根据用户配置爬虫目标网站下全部可用url
入口参数：url,depth,thread
返回：爬取的全部url，列表存储
'''
deadUrl = [] #存放死链
crawledUrl = [] #存放全部爬取过的url，避免重复爬取
#多线程爬取类，获得多线程函数参数
#入口参数：url,depth,thread. depth = 0则无需进行爬虫
#返回：爬取的url列表
class CrawlThread(threading.Thread):
    def __init__(self,url):
        threading.Thread.__init__(self)
        self.url = url
        self.linklist = ''
    # 目标url存活性判断:
    # 存活返回 True;否则返回False
    def urlStatus(self,url):
        try:
            headers = {
                'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'Referer': urlparse.urlparse(url).netloc,
                'Accept-encoding': 'gzip'
                }  # 加入用户代理头部，应对一些网站的反爬虫机制
            request = urllib2.Request(url, headers=headers)
            status = urllib2.urlopen(request,timeout=10).getcode()
            if status == 200:
                return True
            else:
                deadUrl.append(url)
                return False
        except:
            return False
    #判断url域名是否为当前域名
    def judgeDomain(self,testLink):
        domain = urlparse.urlparse(self.url).netloc #当前域名
        if domain == urlparse.urlparse(testLink).netloc:
            return True
        else:
            return False

    # 读取整个网页
    def getHtml(self, url):
        try:
            headers = {
                'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'Referer': urlparse.urlparse(url).netloc,
                'Accept-encoding': 'gzip'}  # 加入用户代理头部，应对一些网站的反爬虫机制
            request = urllib2.Request(url, headers=headers)  # 去除url中‘#’后的内容
            html = urllib2.urlopen(request).read()
            fEncode = urllib2.urlopen(request).info().get('Content-Encoding')
            if fEncode == 'gzip':
                html = gzip.GzipFile(fileobj=StringIO.StringIO(html), mode="r").read()
            return html
        except:
            return None

    # 爬取url页面下的全部链接，多线程作用的函数
    def getLink(self,url):
        try:
            tmpLinks = []
            html = self.getHtml(url)
            #正则表达式获取网页链接：href= src= action=后面的链接
            pattern = r"(?<=href=\").+?(?=\")|(?<=href=\').+?(?=\')|(?<=src=\').+?(?=\')|(?<=src=\").+?(?=\")|(?<=action=\').+?(?=\')|(?<=action=\").+?(?=\")"
            links = re.findall(pattern,html)  # 返回一个列表
            ###获取<a>中href的值
            bad_links = {None, '', '#', ' '}  # 无用链接列表
            bad_protocol = {'javascript', 'mailto', 'tel', 'telnet'}  # 无用的头部协议，如javascript等
            right_protocol = {'http', 'https'}  # 存放正确的协议头部
            linklist = []  # 存放正常的链接
            for link in links:
                if link in bad_links or link.split(':')[0] in bad_protocol:  #去除无用链接
                    continue
                elif link.split(':')[0] in right_protocol:  #绝对地址处理
                    if self.judgeDomain(link):#域名相同
                        link = link.split('#')[0] #若url中有#，去掉#后的内容
                        linklist.append(link)
                else:#相对地址处理
                    link = urlparse.urljoin(self.url, link).split('#')[0]  # 若url中有#，去掉#后的内容
                    linklist.append(link) #相对变绝对
            # 去除重复链接 set()函数
            linklist = list(set(linklist))
            if linklist:
                for link in linklist:
                    if self.urlStatus(link) and link not in crawledUrl: #url存活性判断，去除死链
                        tmpLinks.append(link)
                        crawledUrl.append(link)
                return tmpLinks
            else:#不再存在未爬取链接
                return None
        except:
            return None

    def run(self): #线程创建后会直接运行run函数
        self.linklist = self.getLink(self.url)

    def getDatas(self):
        return self.linklist

#广度遍历，爬取指定深度全部url
def crawlDepth(url,depth,maxThread):
    threadpool = [] #线程池
    if depth == 0:
        return crawledUrl.append(url)
    else:
        nowDepth = 1
        th = CrawlThread(url)#获得深度为1时的全部url
        th.setDaemon(True)
        th.start()
        th.join()
        datas = th.getDatas()
        if datas:
            testLinks = Queue.deque(datas)
        else:#该网址不存在可爬虫链接
            return None
        while nowDepth < depth and testLinks:
            nowDepth = nowDepth + 1
            tmpLinks = []
            while testLinks:
                while len(threadpool) < maxThread:
                    if testLinks:
                        t = CrawlThread(testLinks.pop())
                        t.setDaemon(True)
                        threadpool.append(t)
                        t.start()
                    else:
                        break
                for thread in threadpool:#等待线程结束
                    thread.join()
                    #取出线程数据
                    tmp = thread.getDatas()
                    if tmp:
                        tmpLinks.extend(tmp)
                threadpool = []
            if tmpLinks:
                testLinks = list(set(tmpLinks))
            else:
                testLinks = Queue.deque([])
        return crawledUrl


# 秒数转时分秒函数
def sectohms(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return "%02d:%02d:%02d" %(h, m, s)
'''—————————爬虫模块 END—————————————————————————————'''

'''—————————URL处理模块 BEGIN——————————————————————————'''
#伪静态URL判断，处理：加"*"
#入口参数为url添加位置：所有数字后面添加"*"，静态网址名后添加"*"
#返回添加了"*"的url,
def staticURLProcess(url):
    try:
        urlList = urlparse.urlparse(url)
        pathList = urlList.path.split("/")[1:] # 获取、分解url路径组成，第一个值为空格
        returnList = []
        # 传入url域名
        domain = [urlList.scheme, '://', urlList.netloc]
        domain = ''.join(domain)
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
            url = '/'.join(returnList)
            if flag == 0:
                return None
            else:
                return url
    except:
        pass

#检查url中是否含有"*",有则去除"*"标记
#返回：去除"*"的url
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
'''—————————URL处理模块 END——————————————————————————'''

'''—————————扫描处理模块 BEGIN——————————————————————————'''
class AutoSqli(object):
    """使用sqlmapapi的方法进行与sqlmapapi建立的server进行交互"""
    def __init__(self,target='', data='', referer='', cookie=''):
        super(AutoSqli, self).__init__()
        self.server = 'http://127.0.0.1:8775'
        if self.server[-1] != '/':
            self.server = self.server + '/'
        self.target = target
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.data = data
        self.referer = referer
        self.cookie = cookie
        self.start_time = time.time()

    # 新建扫描任务
    def taskNew(self):
        self.taskid = json.loads(requests.get(self.server + 'task/new').text)['taskid']
        # 得到taskid,根据这个taskid来进行其他的
        if len(self.taskid) > 0:
            return True
        return False

    # 删除扫描任务
    def taskDelete(self):
        if json.loads(requests.get(self.server + 'task/' + self.taskid + '/delete').text)['success']:
            return True
        return False

    # 扫描任务开始
    def scanStart(self):
        headers = {'Content-Type': 'application/json'}
        # 需要扫描的地址
        payload = {'url': self.target}
        url = self.server + 'scan/' + self.taskid + '/start'
        # http://127.0.0.1:8775/scan/xxxxxxxxxx/start
        t = json.loads(requests.post(url, data=json.dumps(payload), headers=headers).text)
        self.engineid = t['engineid']
        if len(str(self.engineid)) > 0 and t['success']:
            return True
        return False

    # 扫描任务的状态
    def scanStatus(self):
        self.status = json.loads( requests.get(self.server + 'scan/' + self.taskid + '/status').text)['status']
        if self.status == 'running':
            return 'running'
        elif self.status == 'terminated':
            return 'terminated'
        else:
            return 'error'

    #解析扫描结果，获取payload和注入类型
    #datas:扫描结果的data数据=requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
    def getPayloads(self,datas):
        payloads = datas[1]['value'][0]['data'] #所确认漏洞的测试向量集
        dicts = {} #存放使用的测试向量集
        for key,value in payloads.items():
            if key == '1':
                dicts['布尔型注入'] = value['payload']
            if key == '2':
                dicts['基于错误的盲注'] = value['payload']
            if key == '3':
                dicts['内联查询注入'] = value['payload']
            if key =='4':
                dicts['堆查询注入'] = value['payload']
            if key == '5':
                dicts['基于时间的盲注'] = value['payload']
            if key == '6':
                dicts['UNION查询注入'] = value['payload']
        return dicts

    # 解析扫描结果，获获取注入请求方式
    # datas:扫描结果的data数据=requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
    def getRequestMethod(self,datas):
        place = datas[1]['value'][0]['place']
        return place

    #扫描结果
    def scanResults(self):
        self.data = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
        if len(self.data) == 0:
            safeUrl.append(self.target) #存入不可注入url
            return None
        else:
            payloads = self.getPayloads(self.data)
            holeUrl.append(removeTag(self.target)) #去除注入标记，存入可注入url
            holeMethod.append(self.getRequestMethod(self.data)) #存入注入位置
            for key in payloads:
                # 存入可注入url及payload信息，可能存在一个url对应多个payload，字典一键多值解决方案
                injectedPayloads.setdefault(removeTag(self.target),[]).append(payloads[key])
                injectedPayloads[payloads[key]] = key
            return payloads #数据类型为list


    # 扫描的设置,主要的是参数的设置
    def optionSet(self):
        headers = {'Content-Type': 'application/json'}
        option = {#参数设置
            "smart": True,
            "threads": 10, #设置扫描线程数
            "retries":0,
            # "getUsers":True,
            # "getDbs":True, #获取数据库
            # "ignoreRedirects":True, #忽视重定向
        }
        url = self.server + 'option/' + self.taskid + '/set'
        t = json.loads(requests.post(url, data=json.dumps(option), headers=headers).text)

    # 停止扫描任务
    def scanStop(self):
       t = json.loads(requests.get(self.server + 'scan/' + self.taskid + '/stop').text)['success']

    # 杀死扫描任务进程
    def scanKill(self):
        t=json.loads(requests.get(self.server + 'scan/' + self.taskid + '/kill').text)['success']

    def run(self):
        if not self.taskNew():
            return False
        self.optionSet() #sqlmap扫描设置
        if not self.scanStart():
            return False
        while CrawlThread(removeTag(self.target)).urlStatus(removeTag(self.target)):
            if self.scanStatus() == 'running':
                continue
            elif self.scanStatus() == 'terminated':
                break
            else:
                break
            if time.time() - self.start_time > 30000: #响应超时的处理
                error = True
                self.scanStop()
                self.scanKill()
                break

        self.scanResults()
        # self.taskDelete() #删除扫描任务
'''—————————扫描处理模块 END——————————————————————————————————'''

'''—————————MANAGER 获取配置信息，爬虫、扫描——————————————————————————'''
if __name__ == '__main__':
    #获取用户扫描配置信息
    # sys.argv 用来获取命令行参数，0：代码本身文件路径，传递的参数从1开始
    params = sys.argv[1]  # {url:11111,depth:1,threads:2}
    params = params.split(',')
    url = params[0].split('url:')[1]
    depth = int(params[1].split(':')[1])
    threads = int(params[2].split(':')[1])
    # print url,depth,threads
    # url = 'http://web.safe.com/scan/holeshow/id/1'
    # depth = 0
    # threads = 10

    #—爬虫&URL处理 BEGIN——
    crawlDepth(url,depth,threads)
    for i in crawledUrl:  # 可以加入多线程处理
        link = URLProcess(i).injectableUrl()
        if link:  # URL可注入
            testUrl.append(link)
        else:
            continue
    # print 'testUrl：',testUrl
    # —爬虫&URL处理 END——
    if testUrl:
        for item in testUrl:
            AutoSqli(item).run()

    # print 'holeUrl:',holeUrl
    # 扫描结束存储数据
    if len(holeUrl) >= 0:
        for i in holeUrl:
            payloads = []
            types = []
            payloadNum = len(injectedPayloads[i])
            for j in xrange(payloadNum):
                types.append(injectedPayloads[injectedPayloads[i][j]])  # 单个url对应的payloads类型，存入列表中
                payloads.append(injectedPayloads[i][j])  # 各个类型对应的payload，存入列表中
            # 列表嵌套列表
            holePayloadType.append(types)
            holePayload.append(payloads)

    # ——————要传递的扫描信息放到字典里——————————————
    scanDatas['crawled_num'] = len(crawledUrl) #爬取链接数
    scanDatas['link_num'] = len(testUrl)  # 扫描链接数
    scanDatas['links'] = testUrl  # 具体扫描链接
    scanDatas['hole_num'] = len(holeUrl)  # 漏洞总数
    scanDatas['hole_links'] = holeUrl  # 漏洞对应的链接,","分隔
    scanDatas['hole_payload'] = holePayload  # 漏洞对应的payload
    scanDatas['hole_payload_type'] = holePayloadType  # 漏洞对应的payload类型
    scanDatas['hole_request_method'] = holeMethod  # 漏洞测试请求方式
    scanDatas = json.dumps(scanDatas)  # json编码
    print scanDatas  # 传值给scan/execSQLScan

