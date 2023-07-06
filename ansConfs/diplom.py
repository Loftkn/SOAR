from thehive4py.exceptions import CaseException, CaseObservableException
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable
import requests
from datetime import datetime, timedelta
import time
import json
import pydnsbl
import random
from ipaddress import ip_address


def get_kibana_addr():
    try:
        requests.get('https://192.168.122.11:5601', verify=False)
        return '192.168.122.11'
    except requests.exceptions.ConnectionError:
        return '192.168.122.22'


def get_thehive_addr():
    try:
        requests.get('http://192.168.122.11:9000')
        return 'http://192.168.122.11:9000' 
    except requests.exceptions.ConnectionError:
        return 'http://192.168.122.22:9000'


def get_alerts(last_hours, size) -> dict:
    # Две переменные чтобы указать интервал времени необходимых инцидентов
    # last_hours=2, size=3  -> Берет 3 инцидента за последние 2 часа
    gte = (datetime.now() - timedelta(hours=last_hours)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'
    lte = (datetime.now()).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'

    json_data = {
        "aggs": {
            "alertsByGrouping": {
                "terms": {
                    "field": "signal.rule.name",
                    "order": {
                        "_count": "desc"
                    },
                    "size": 10
                }
            }
        },
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "must": [],
                            "filter": [
                                {
                                    "term": {
                                        "signal.status": "open"
                                    }
                                }
                            ],
                            "should": [],
                            "must_not": [
                                {
                                    "exists": {
                                        "field": "signal.rule.building_block_type"
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte
                            }
                        }
                    }
                ]
            }
        },
        'size': size
    }
    data = {}
    r = requests.post(f'https://{kibana_addr}:5601/api/detection_engine/signals/search', headers=headers, json=json_data,
                      verify=False).json()
    for i in r['hits']['hits']:
        data[i['_id']] = {
            'name': i['_source']['kibana.alert.rule.name'],
            'alert_query': i['_source']['kibana.alert.rule.description'],
            'timestamp': ' '.join(i['_source']['@timestamp'][:-5].split('T')),
            'sourceaddr': '8.8.8.8',
            #'sourceaddr': '.'.join(str(random.randint(0, 255)) for _ in range(4)),
            'log': i['_source']['event.original'],
            'request_method': i['_source']['http']['request']['method'],
            'url_path': i['_source']['url']['path'],
            'response_code': i['_source']['http']['response']['status_code'],
            'user_agent': i['_source']['user_agent']['original'],
            'tags': i['_source']['kibana.alert.rule.tags']
        }
        #close_alert(i['_id'])
    return data


def close_alert(alert_id) -> None:  # Помечает инцидент закрытым в Kibana во вкладке security#alerts
    json_data = {
        'status': 'closed',
        'query': {
            'bool': {
                'filter': {
                    'terms': {
                        '_id': [alert_id],
                    },
                },
            },
        },
    }

    requests.post(f'https://{kibana_addr}:5601/api/detection_engine/signals/status',
                  headers=headers, json=json_data, verify=False)


def check_ip_with_virustotal(api_key, ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'    
    headers = {
        'x-apikey': api_key
    }
    vt_response = requests.get(url, headers=headers)

    if vt_response.status_code == 200:
        result = vt_response.json()
        data = {
                'country': result['data']['attributes']['country'],
                'owner': result['data']['attributes']['as_owner'],
                'stats': result['data']['attributes']['last_analysis_stats']
                }
        return data
    elif vt_response.status_code == 404:
        return 'IP not found on VirusTotal'    
    elif vt_response.status_code == 401:
        return 'Invalid API key'    
    else:
        return 'An error occurred'


kibana_addr = get_kibana_addr()
thehive_addr = get_thehive_addr()

headers = {
    'Content-Type': 'application/json',
    'Host': kibana_addr,
    'kbn-version': 'kbn_version',
    'Authorization': 'Apikey apiKey',
    'Connection': 'close'
}

alerts = get_alerts(last_hours=12, size=20)
api = TheHiveApi(thehive_addr, 'apiKey')
vt_api = 'virustotal_apiKey'

for alert in alerts.values():
    if not alert['alert_query'] in alert['url_path']:
        continue
    ip_checker = pydnsbl.DNSBLIpChecker().check(alert['sourceaddr'])
    blacklisted_by = ''
    if ip_checker.blacklisted:
        for listedby in ip_checker.detected_by:
                blacklisted_by += '- ' + listedby + '\n'
    case_ = Case(title=alert['name'],
                 tags=alert['tags'],
                 description='\n' + alert['log'] + '\n\n' + check_ip_with_virustotal(vt_api, alert['sourceaddr'])['country'] + '\n' + 'Blacklisted by: ' + blacklisted_by)  
    try:
        response = api.create_case(case_).json()
        case_id = response['id']
        try:
            observable = CaseObservable(dataType='ip',
                                        data=alert['sourceaddr'],
                                        ioc=True,
                                        tags=['attack'],
                                        message=alert['log']
                                        )
            api.create_case_observable(case_id, observable)
        except CaseObservableException:
            time.sleep(5)
    except CaseException:
        time.sleep(5)
