# sqlScan-based-sqlmap

基于sqlmap编写的sql注入检测

使用方法：
cmd打开至SCAN/sqlscan.py文件：
python sqlscan.py [url] [depth] [thread]

[url] ：待检测URL
[depth] ：检测深度
[thread]：线程数

扫描结果以json格式返回。
