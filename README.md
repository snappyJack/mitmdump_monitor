# mitmdump_monitor

#### how to use
mitmdump -s mitmdump_monitor.py

#### document

https://snappyjack.github.io/articles/2019-10/%E5%9F%BA%E4%BA%8EMitmproxy%E5%AE%9E%E7%8E%B0%E7%9A%84%E5%A4%9A%E7%BB%88%E7%AB%AF%E5%85%A8%E7%BD%91%E6%B5%81%E9%87%8F%E7%9B%91%E6%8E%A7

#### 一些查询语法
```
查询
{'method':'POST'}
显示某个字段
{pretty_host:1,path:1,text:1}
{pretty_url:1,pretty_host:1,startedDateTime:1,text:1,path:1,clientIPAddress:1}
按时间排序
{startedDateTime:-1}
模糊查询
{"pretty_host": {"$regex": ".*youdao.*"}}
```
