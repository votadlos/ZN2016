#virus total checker

import requests
import time
import pika
import json
import sys
import traceback
from multiprocessing import Pool
from datetime import datetime
from itertools import imap, izip, islice
from elasticsearch import Elasticsearch, helpers

elk_servers = ['127.0.0.1:9200']
elk_timeout = 220
elk_fetchsize = 5000
es = Elasticsearch(elk_servers, timeout=elk_timeout)
bulk_size = 25

processing_thread_count = 8
results = []

apikey = '' #Virus Total API key
process_all = 1
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "VT-checker"
}
proxies = {
  'https': 'https://'
}

counter = { "elk_read_error": 0,
            "total_md5": 0,
	    "in_vt": 0,
	    "with_nonzero_positives": 0,
	    "success_check": 0,
            "script_execution_time": 0,
            "check_date": ''
	}


rbmq_cred = pika.PlainCredentials('user', 'password')
rbmq_param = pika.ConnectionParameters('localhost', 5672, '/', rbmq_cred)
rbmq_conn = pika.BlockingConnection(rbmq_param)
rbmq_channel = rbmq_conn.channel()

def parse_vt_response(json_response):
    vt_report = {}
    if json_response['response_code'] == 1:
	vt_report['vt_check_date'] = datetime.utcnow().isoformat()
	if json_response.has_key('tags'): 
	    vt_report['vt_tags'] = json_response['tags']
	vt_report['vt_positives'] = json_response['positives']
	vt_report['vt_total'] = json_response['total']
	vt_report['vt_scan_date'] = datetime.strptime(json_response['scan_date'], '%Y-%m-%d %H:%M:%S').isoformat()
    else: vt_report['vt_check_date'] = datetime.utcnow().isoformat()
    return vt_report

def checkVT(files):
    file_list = map(lambda x:x['@metadata']['_id'][2:],files)
    params = {'apikey': apikey, 'resource': ','.join(file_list), 'allinfo': process_all}
    try:
	json_response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers, proxies=proxies).json()
	if len(files) == 1:
	    json_response = [json_response] #if one element in response, it is not interpreted as list, but in code bellow we opperate with json_response as list
	map(lambda x:files[x].update(parse_vt_response(json_response[x])),xrange(len(files))) #add to files VT report
	return files
    except:
	return None

def processCheckResult(result):
#    results.extend(result)
    if result:
	counter['success_check'] += len(result)
	counter['in_vt'] += len(filter(lambda x: x.has_key('vt_scan_date'), result))
	counter['with_nonzero_positives'] += len(filter(lambda x: (x.has_key('vt_scan_date') and x['vt_positives'] > 0), result))
	rbmq_channel.basic_publish(exchange='exchange',
                    routing_key='key',
                    body=json.dumps(result),
                    properties=pika.BasicProperties(
            	    delivery_mode = 2, # make message persistent
        ))
    else:
	pass
	#counter['error_check'] += len(result)



if __name__ == '__main__':
    processing_pool = Pool(processing_thread_count)
    startTime = time.time()
    checkDate = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    index_mask = "logstash-files"

    scroll = helpers.scan(es, index=index_mask, size=elk_fetchsize, scroll=u'5m', preserve_order=False, request_timeout=elk_timeout, query=
    {
        "query": {
            "bool": {
                "should": [
                    { "filtered": {
                        "query": {
                            "query_string": {
                                "query": "-vt_scan_date*"
                            }
                        },
                        "filter": {
                            "bool": {
                                "must": [
                                    {"range": {"last_seen": {"gte": "now-30d/m"}}},
                                    {"range": {"vt_check_date": {"lte": "now-1d/m"}}}
                                ]
                            }
                        }
                     }
                    },
                    {
                        "filtered": {
                            "query": {
                                "query_string": {
                                    "query": "-vt_check_date:*"
                                }
                            },
                            "filter": {
                                "range": {"last_seen": {"gte": "now-30d/m"}}
                            }
                        }
                    }
            ]
        }
       }
    })

    while True:
        try:
            md5list = map(lambda x:{'@metadata':{'_op':'ti_bulk','_id':x['_id'],'_index':x['_index'],'_type':x['_type']}}, list(islice(scroll, bulk_size)))
	    counter['total_md5'] += len(md5list)
	except KeyboardInterrupt:
            print " Terminating..."
            processing_pool.terminate()
            break
        except:
            counter['elk_read_error'] += 1
	    #counter['error_md5'] += bulk_size
            print "Exception!"
            print sys.exc_info()[1]
            print sys.exc_info()[0]
            print sys.exc_info()[2]
            tb_string = traceback.format_tb(sys.exc_info()[2])
            print tb_string
	    continue
        if not md5list: break
	processing_pool.apply_async(checkVT, args = (md5list,), callback = processCheckResult)
    processing_pool.close()
    processing_pool.join()
    rbmq_conn.close()
    counter['script_execution_time'] = time.time() - startTime
    counter['check_date'] = checkDate
    print counter