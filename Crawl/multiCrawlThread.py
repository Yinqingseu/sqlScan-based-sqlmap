#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import urllib2
import threading
from time import clock #代码计时(语句或函数)
import datetime
import urlparse
import re
import Queue
import gzip,StringIO
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


'''
多线程爬取URL
广度优先遍历：根据用户配置爬虫目标网站下全部可用url
入口参数：url,depth,thread
返回：爬取的全部url，列表存储
'''
#扫描结果参数展示
def showResults(finish_sec,start_sec,total_unique_links,failed_url,start_time,end_time):
    crawled_time = finish_sec-start_sec
    total_unique_num = len(total_unique_links)
    failed_num = len(failed_url)
    print "扫描完毕！"
    print "扫描链接数：%s"% total_unique_num
    print "扫描失败链接数：%s"%failed_num
    print "开始：%s"%start_time
    print "结束：%s"%end_time

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
    def getHtml(self,url):
        try:
            headers = {'User-agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                       'Referer': urlparse.urlparse(url).netloc,
                       'Accept-encoding':'gzip'} #加入用户代理头部，应对一些网站的反爬虫机制
            request = urllib2.Request(url,headers=headers)#去除url中‘#’后的内容
            html = urllib2.urlopen(request).read()
            fEncode = urllib2.urlopen(request).info().get('Content-Encoding')
            if fEncode == 'gzip':
                html = gzip.GzipFile(fileobj = StringIO.StringIO(html),mode = "r").read()
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
                # for i in tmpLinks:
                #     print i
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
        # print '爬虫深度：', nowDepth
        th = CrawlThread(url)#获得深度为1时的全部url
        th.setDaemon(True)
        th.start()
        th.join()
        datas = th.getDatas()
        if datas:
            testLinks = Queue.deque(datas)
        else:#该网址不存在可爬虫链接
            # print '该网址不存在可爬虫链接'
            return None
        while nowDepth < depth and testLinks:
            nowDepth = nowDepth + 1
            # print '爬虫深度：', nowDepth
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

if __name__ == '__main__':
    # 代码运行开始时间：年月日 时分秒
    start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print '开始时间：',start_time
    # 代码运行开始计时标记
    start_sec = clock()
    depth = 0 # 设置扫描深度
    url = "http://testphp.vulnweb.com/artists.php?artist=2"
    threads = 10
    crawlDepth(url,depth,threads)
    if crawledUrl:
        print '爬取链接：',crawledUrl
        print '爬取链接数：',len(crawledUrl)
        for i in crawledUrl:
            print i
    # 代码运行结束时间标记
    finish_sec = clock()
    # 代码运行结束时间：年月日 时分秒
    end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print '结束时间：', end_time
    print  '历时：',sectohms(finish_sec - start_sec)






