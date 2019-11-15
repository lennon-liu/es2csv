#coding:utf8
'''
author:liulinghong
brief:elasticsearch
description:Packages elasticsearch methods for creating indexes, queries, inserts, and updates
time:2019:9:27
'''
import os
import json
import time
from os import walk
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

class ElasticObj:
    def __init__(self, index_name,index_type="",ip ="172.16.39.15"):
        '''
        :param index_name: 索引名称
        :param index_type: 索引类型
        '''
        self.index_name =index_name
        self.index_type = index_type
        # 无用户名密码状态
        self.es = Elasticsearch([ip])
        #用户名密码状态
        #self.es = Elasticsearch([ip],http_auth=('elastic', 'password'),port=9200)

    def create_index(self,index_name="ott",index_type="ott_type"):
        '''
        创建索引,创建索引名称为ott，类型为ott_type的索引
        :param ex: Elasticsearch对象
        :return:
        '''
        #创建映射
        _index_mappings = {
            "mappings": {
                self.index_type: {
                    "properties": {
                        "datetime": {
                            "type": "date"
                        },
                        "payload": {
                            "type": "text"
                        },
                        "payload_printable":{
                            "type": "text"
                        },
                        "packet":{
                            "type":"text"
                        }
                    }
                }

            }
        }
        if self.es.indices.exists(index=self.index_name) is not True:
            res = self.es.indices.create(index=self.index_name, body=_index_mappings)
            print res

    def Index_Data(self,item):
        '''
        数据存储到es
        :return:
        '''
        res = self.es.index(index=self.index_name, doc_type=self.index_type, body=item)
        #print(res['created'])

    def bulk_Index_Data(self,ACTIONS):
        success,_  = bulk(self.es, ACTIONS, index=self.index_name)
        # print('Performed %d actions' % success)

    def Delete_Index_Data(self,id):
        '''
        删除索引中的一条
        :param id:
        :return:
        '''
        res = self.es.delete(index=self.index_name, doc_type=self.index_type, id=id)
        print res

    def Get_Data_Id(self,id):
        res = self.es.get(index=self.index_name, doc_type=self.index_type,id=id)
        print(res['_source'])
        # # 输出查询到的结果
        for hit in res['hits']['hits']:
            print hit['_source']['last_seen'],hit['_source']['proto'],hit['_source']['link'],hit['_source']['keyword'],hit['_source']['title']

    def Get_Data_By_Body(self):
        # doc = {'query': {'match_all': {}}}
        doc = {
            "query": {
                "match_all":{}
            },
            "sort": [
                {
                    "datetime": {
                        "order": "desc"
                    }
                }
            ]
        }
        _searched = self.es.search(index=self.index_name, doc_type=self.index_type, body=doc)
        search= self.es.search(index=self.index_name, doc_type=self.index_type)

        for hit in search['hits']['hits']:
            print hit['_source']

            print hit['_source']['datetime']
        print len(search['hits']['hits'])

    def search_all(self,page,size):
        body = {
            'query':
                {'match_all': {}
                 },
            'from': page * size,
            'size': size,
        }
        try:
            return self.es.search(index=self.index_name, size = size,body=body)
        except Exception,e:
            return {}
        # return self.es.search(index=self.index_name, size = 10,body=body)

    def search_byid(self,id):
        return  self.es.get(self.index_name,id=id,doc_type = self.index_type)

    def search_filter(self,filter,page):
        if not len(filter):
            body = {
                'query':
                    {'match_all': {}
                     },
                'from':page*10,
                'size':10,
                "sort": [
                    {
                      "datetime": {
                        "order": "desc"
                      }
                    }
                  ]
            }
        elif len(filter) == 1:
            if filter[0].get("timestamp"):
                sort = [
                    {
                        "timestamp": {
                            "order": "desc"
                        }
                    }
                ]
                body = {}
                query={}
                query["range"]= filter[0]
                body["query"]=query
                body["size"] = 10
                body["from"] = page * 10
                body["sort"] = sort
            else:
                sort = [
                    {
                        "timestamp": {
                            "order": "desc"
                        }
                    }
                ]
                body={}
                match = {}
                if filter[0].get("_all"):
                    match["match"] = filter[0]
                else:
                    match["match_phrase"] = filter[0]
                body["query"] = match
                body["size"]=10
                body["sort"]=sort
                body["from"]=page*10
        else :
            query = {}
            must = []
            sort = [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ]
            for body in filter:
                if body.get("datetime")or body.get("timestamp"):
                    must.append({"range": body})
                else:
                    if body.get("_all"):
                        must.append({"match":body})
                    else:
                        must.append({"match_phrase": body})
            query["bool"] = {
                "must":must
            }
            body = {
                "query":query,
                "sort":sort
            }
            body["size"] = 10
            body["from"] = page * 10
        # print body
        return self.es.search(index=self.index_name, size=10, body=body)
    def del_data(self):
        doc = {"query":{
                            "match_all":{}
                        }
                    }
        try:
            self.es.delete_by_query(index=self.index_name,body=doc)
        except Exception,e:
            return False
        return True


    def descSort(self,array, key):
        for i in range(len(array) - 1):
            for j in range(len(array) - 1 - i):
                if float(array[j][key]) < float(array[j + 1][key]):
                    array[j], array[j + 1] = array[j + 1], array[j]
        return array

    def screen_condition1(self,opt):
        if opt == 'category':
            body = {
                "size": 0,
                "query": {

                },
                "aggs": {
                    "category": {
                        "terms": {
                            "field": "alert.category.keyword",
                            "size": 20
                        }
                    }
                }
            }
        elif opt == 'src_ip':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "src_ip": {
                        "terms": {
                            "field": "src_ip.keyword",
                            "size": 20
                        }
                    }
                }
            }
        elif opt == 'severity':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "severity": {
                        "terms": {
                            "field": "alert.severity",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'device_type':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "device_type": {
                        "terms": {
                            "field": "device_type.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'detected_protocol_name':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "detected_protocol_name": {
                        "terms": {
                            "field": "detected_protocol_name.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'host_a_name':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "host_a_name": {
                        "terms": {
                            "field": "host_a_name.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'host_b_name':
            body = {
                "size": 0,
                "query": {},
                "aggs": {
                    "host_b.name": {
                        "terms": {
                            "field": "host_b_name.keyword",
                            "size": 20
                        }
                    }

                }
            }

        typelist = self.es.search(index=self.index_name, body=body)
        try:
            countlist = typelist.get("aggregations").get(opt).get("buckets")
        except:
            countlist=[]
        return  self.descSort(countlist, "doc_count")

    def screen_condition(self,filter,opt):
        if not len(filter):
            query={}
        elif len(filter) == 1:
            if filter[0].get("timestamp"):
                body = {}
                query={}
                query["range"]= filter[0]
            else:
                body={}
                match = {}
                if filter[0].get("_all"):
                    match["match"] = filter[0]
                else:
                    match["match_phrase"] = filter[0]
                query = match
        else :
            query = {}
            must = []
            for body in filter:
                if body.get("datetime")or body.get("timestamp"):
                    must.append({"range": body})
                else:
                    if body.get("_all"):
                        must.append({"match":body})
                    else:
                        must.append({"match_phrase": body})
            query["bool"] = {
                "must":must
            }
        try:
            query = query.pop(opt)
        except:
            pass
        if opt == 'category':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "category": {
                        "terms": {
                            "field": "alert.category.keyword",
                            "size": 20
                        }
                    }
                }
            }
        elif opt == 'src_ip':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "src_ip": {
                        "terms": {
                            "field": "src_ip.keyword",
                            "size": 20
                        }
                    }
                }
            }
        elif opt == 'severity':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "severity": {
                        "terms": {
                            "field": "alert.severity",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'device_type':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "device_type": {
                        "terms": {
                            "field": "device_type.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'detected_protocol_name':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "detected_protocol_name": {
                        "terms": {
                            "field": "detected_protocol_name.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'host_a_name':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "host_a_name": {
                        "terms": {
                            "field": "host_a_name.keyword",
                            "size": 20
                        }
                    }

                }
            }
        elif opt == 'host_b_name':
            body = {
                "size": 0,
                "query": query,
                "aggs": {
                    "host_b.name": {
                        "terms": {
                            "field": "host_b_name.keyword",
                            "size": 20
                        }
                    }

                }
            }

        typelist = self.es.search(index=self.index_name, body=body)
        try:
            countlist = typelist.get("aggregations").get(opt).get("buckets")
        except:
            countlist=[]
        return  self.descSort(countlist, "doc_count")

    def index_exist(self,index_name):
        return  self.es.indices.exists(index=index_name)



# obj = ElasticObj("suricata_flow", "suricata_flow_type","172.16.39.15")
# #
# # print obj.es.indices.exists(index="suricata_instrusion")
#
# #
# obj.create_index()
#obj.Index_Data()

# obj.IndexData()
#obj.Delete_Index_Data("AW1rW62rivY3Jk6-XlF2")
# csvfile = 'D:/work/ElasticSearch/exportExcels/2017-08-31_info.csv'
# obj.Index_Data_FromCSV(csvfile)
#obj.Get_Data_By_Body()
