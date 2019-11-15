


import json



with open("cfg.json","w+") as cfg_file:
    cfg = {
        "ip_addr":"172.16.39.63",
        "d01":{
            "index":"d01",
            "index_type":"",
            "save_path":"./d01.csv"
        },
        "d01_vuln":{
            "index": "d01_vuln",
            "index_type": "",
            "save_path": "./d01_vuln.csv"
        }
    }
    cfg_file.write(json.dumps(cfg))