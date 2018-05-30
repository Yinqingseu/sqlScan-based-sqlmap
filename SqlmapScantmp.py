#!/usr/bin/python
# -*-coding:utf-8-*-
from Crawl import objectCrawl #引入爬虫模块包
from URL import URLProcess #引入URL处理包
import requests
import time
import json
import threading
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
#SQL注入扫描调试脚本
'''—————————全局变量定义 ————————————————————————————'''
crawlUrl = [] #从爬虫模块获取的测试url
deadUrl = [] #存放死链
testUrl = [] #crawlUrl经URL处理模块获得的可注入URL
safeUrl = [] #存放不可注入url
holeUrl = [] #存在漏洞的url  [url1,url2...]
staticUrl = [] #存放伪静态url
holeMethod = [] #url对应验证方法 [get,post]
holePayload = [] #url对应验证payload，[[payload1,payload2],[payload3,payload4]] 列表嵌套列表
holePayloadType = [] #payload对应请求类型 [[1,2,3],[1,2]]
injectedPayloads = {} #存放 可注入url：payloads，payloads:type
scanDatas = {} #存放扫描结果
'''—————————扫描处理模块 BEGIN————————————————————————————————————'''
class AutoSqli(object):
    """
    使用sqlmapapi的方法进行与sqlmapapi建立的server进行交互
    """
    def __init__(self, target='', data='', referer='', cookie=''):
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
        #print '创建新任务ID:' + self.taskid
        # 得到taskid,根据这个taskid来进行其他的
        if len(self.taskid) > 0:
            return True
        return False

    # 删除扫描任务
    def taskDelete(self):
        if json.loads(requests.get(self.server + 'task/' + self.taskid + '/delete').text)['success']:
            #print '任务号[%s]已删除 ' % (self.taskid)
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
            print '开始扫描URL:', self.target
            return True
        return False

    # 扫描任务的状态
    def scanStatus(self):
        self.status = json.loads( requests.get(self.server + 'scan/' + self.taskid + '/status').text)['status']
        if self.status == 'running':
            #print '扫描状态：扫描进行中...'
            return 'running'
        elif self.status == 'terminated':
            #print '扫描状态：扫描结束！'
            return 'terminated'
        else:
            #print '扫描状态：扫描发生错误！'
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

    #扫描结果
    def scanResults(self):
        self.data = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
        if len(self.data) == 0:
            safeUrl.append(self.target) #存入不可注入url
            print self.target,' 不存在注入漏洞:\t'
            return None
        else:
            print self.target ,' 存在注入漏洞\t'
            payloads = self.getPayloads(self.data)
            holeUrl.append(self.target) #存入可注入url
            for key in payloads:
                # 存入可注入url及payload信息，可能存在一个url对应多个payload，字典一键多值解决方案
                injectedPayloads.setdefault(self.target,[]).append(payloads[key])
                injectedPayloads[payloads[key]] = key
                #print '注入类型类型：',key
                #print '测试payload:',payloads[key]
            return payloads #数据类型为list


    # 扫描的设置,主要的是参数的设置
    def optionSet(self):
        headers = {'Content-Type': 'application/json'}
        option = {#参数设置
            "smart": True,
            "threads":10, #设置扫描线程数
            # "getUsers":True,
            # "getDbs":True, #获取数据库
            "ignoreRedirects":True, #忽视重定向
            #...
        }
        url = self.server + 'option/' + self.taskid + '/set'
        t = json.loads(requests.post(url, data=json.dumps(option), headers=headers).text)
        print t

    # 停止扫描任务
    def scanStop(self):
        json.loads(requests.get(self.server + 'scan/' + self.taskid + '/stop').text)['success']

    # 杀死扫描任务进程
    def scanKill(self):
        json.loads(requests.get(self.server + 'scan/' + self.taskid + '/kill').text)['success']

    def run(self):
        if not self.taskNew():
            return False
        self.optionSet() #sqlmap扫描设置
        if not self.scanStart():
            return False
        while True:
            if self.scanStatus() == 'running':
                continue
            elif self.scanStatus() == 'terminated':
                break
            else:
                break
            print time.time() - self.start_time
            if time.time() - self.start_time > 3000: #响应超时的处理
                error = True
                self.scanStop()
                self.scanKill()
                break
        self.scanResults()
        #self.taskDelete() #删除扫描任务
        print '扫描时间：',
        print time.time() - self.start_time
'''—————————扫描处理模块 END————————————————————————————————————'''

if __name__ == '__main__':
    # begin_time = time.time() #扫描开始时间
    #获取用户扫描配置信息
    # sys.argv 用来获取命令行参数，0：代码本身文件路径，传递的参数从1开始
    # ————————————Manage程序 BEGIN————————————————————————————————
    #测试url：
    url = 'http://web.safe.com/scan/holeshow/id/1*'
    url1 = 'http://testphp.vulnweb.com/artists.php?artist=2'
    #url2 = 'http://testphp.vulnweb.com/'
    #url3 = 'http://testphp.vulnweb.com/listproducts.php?cat=2'
    url4 = "http://web.safe.com/scan/HoleUpShow/id/2017022614594929497*"
    '''
    print '正在爬取网站链接......'
    crawlUrl = CrawlThread(url,threads,depth). 根据用户配置，爬虫模块开始处理，获取url存入testUrl列表中BEGIN
    print '网站链接爬取完毕'
    print '开始处理URL......'
    for i in crawlUrl:
        urlResults = URLProcess.URLProcess(i)
        if urlResults.isInjectable(): #URL可注入
            testUrl.append(i)
        else:
            continue
     print 'URL处理完毕'
     print '开始扫描......'
    '''

    testUrl = [url4,url,url1] #爬虫模块获取的扫描链接
    for item in testUrl:
        t = AutoSqli(item)
        t.run()
    #扫描结束存储数据
    if len(holeUrl) >= 0:
        for i in holeUrl:
            payloads = []
            types = []
            payloadNum = len(injectedPayloads[i])
            for j in xrange(payloadNum):
                types.append(injectedPayloads[injectedPayloads[i][j]]) #单个url对应的payloads类型，存入列表中
                payloads.append(injectedPayloads[i][j]) #各个类型对应的payload，存入列表中
            #列表嵌套列表
            holePayloadType.append(types)
            holePayload.append(payloads)
    #——————要传递的扫描信息放到字典里——————————————
    scanDatas['link_num'] = len(testUrl)  # 扫描链接数
    scanDatas['links'] = testUrl #具体扫描链接
    scanDatas['hole_num'] = len(holeUrl) #漏洞总数
    scanDatas['hole_links'] = holeUrl #漏洞对应的链接,","分隔
    scanDatas['hole_payload'] = holePayload #漏洞对应的payload
    scanDatas['hole_payload_type'] = holePayloadType  #漏洞对应的payload类型
    scanDatas['hole_request_method'] = holeMethod #漏洞测试请求方式
    scanDatas = json.dumps(scanDatas)  # json编码
    print scanDatas  # 传值给scan/execSQLScan
    print '扫描结束'

