#-*- coding: UTF-8 -*-
import codecs
import csv
import json
import esload
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def es_write_list(filename,data_list,title):
    file = codecs.open(filename, "ab+", 'utf-8-sig')
    writer = csv.writer(file)
    with open(filename, "r") as f:
        reader = csv.reader(f)
        csv.field_size_limit(500 * 1024 * 1024)
        if not [row for row in reader]:
            print title
            writer.writerow(title)
            writer.writerows(data_list)
        else:
            writer.writerows(data_list)

def get_data(mode):
    cfg_read = open("cfg.json","r")
    if cfg_read:
        cfg = json.loads(cfg_read.read())
    else:
        return False
    if mode == "info":
        obj_cfg = cfg.get("d01")
        title  = ["目标", "IP地址","操作系统", "开放端口","服务", "组件和版本", "组织机构", "主机名", "标题", "参考信息", "设备类型", "设备厂商", "设备品牌","设备型号", "国家", "省份", "城市", "服务提供商", "扫描时间"]
    elif mode == "vul":
        title = ["目标".decode("utf-8"), "漏洞名称".decode("utf-8"), "漏洞时间".decode("utf-8"), "漏洞等级".decode("utf-8"), "漏洞验证信息".decode("utf-8"), "参考链接".decode("utf-8"), "CVE_ID", "漏洞披露时间".decode("utf-8")]
        obj_cfg = cfg.get("d01_vuln")
    else:
        return False
    ip_addr = cfg.get("ip_addr")
    save_path = obj_cfg.get("save_path")
    if not ip_addr:
        return False
    if not obj_cfg:
        return False
    index = obj_cfg.get("index","")
    index_type = obj_cfg.get("index_type","")
    es_obj = esload.ElasticObj(index_name=index,index_type = index_type,ip = ip_addr)
    page_size=50

    rs = es_obj.search_all(0,page_size)
    total = rs.get("hits").get("total")
    pages = total/page_size
    for page in range(0,pages+1):
        try:
            rs =  es_obj.search_all(page,page_size)
            hits = rs.get("hits").get("hits")
            temp_save_list=[]
            for data in hits:
                row = data.get("_source")
                temp_save = []
                if mode == "info":
                    temp_save.append(row.get("ip",""))
                    temp_save.append(row.get("ip",""))
                    components = row.get("components",{})
                    os=""
                    try:
                        for obj in components:
                            for key in obj.keys():
                                if key == "os":
                                    os = obj[key]
                                    break
                    except Exception,e:
                        os=""
                        print e
                    temp_save.append(os)
                    temp_save.append(row.get("port",""))
                    temp_save.append(row.get("protocol",""))
                    temp_save.append(",".join(row.get("tags","")))
                    temp_save.append(row.get("unit_name",""))
                    temp_save.append("")
                    data11=row.get("data", {})
                    temp_save.append(data11.get("title",""))
                    temp_save.append("")
                    temp_save.append("")
                    temp_save.append("")
                    temp_save.append("")
                    temp_save.append("")
                    location = row.get("location",{})
                    temp_save.append(location.get(".country",""))
                    temp_save.append(location.get("province",""))
                    temp_save.append(location.get("city", ""))
                    temp_save.append("")
                    temp_save.append(row.get("timestamp",""))
                else:
                    temp_save.append(row.get("ip", ""))
                    temp_save.append(row.get("name",""))
                    temp_save.append(row.get("timestamp",""))
                    risk = row.get("risk","")
                    if risk == "低危":
                        temp_save.append("low")
                    elif risk == "中危":
                        temp_save.append("medium")
                    elif risk in ["高危","超危"] :
                        temp_save.append("high")
                    else:
                        temp_save.append("low")
                    URL=row.get("URL","")
                    port=row.get("port","")
                    VerifyInfo={
                        'URL':URL,
                        'Port':port
                    }
                    content= json.dumps({'VerifyInfo':VerifyInfo}).replace('"',"\'")
                    temp_save.append('"'+content+'"')

                    references = row.get('references',[])
                    if len(references)>0:
                        temp_save.append(",".join(references))
                    else:
                        temp_save.append("")
                    cve = row.get("cve", {})
                    if len(cve)>0:
                        temp_save.append(",".join(cve))
                    else:
                        temp_save.append("")

                    temp_save.append(row.get("updateDate",""))
                temp_save_list.append(temp_save)
            es_write_list(filename=save_path,data_list=temp_save_list,title=title)
        except Exception,e:
            s = sys.exc_info()
            print "Error '%s' happened on line %d" % (s[1], s[2].tb_lineno)
#
get_data("info")

get_data("vul")