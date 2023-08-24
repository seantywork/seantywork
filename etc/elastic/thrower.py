from elasticsearch import Elasticsearch
from elasticsearch import helpers


es = Elasticsearch("http://elasticsearch.elastic:9200",basic_auth=('elastic', 'test'))

op_list = []
with open("./gbif_data.json") as json_file:
    for record in json_file:
        op_list.append({
                       '_op_type': 'index',
                       '_index': 'gbifdata',
                       '_source': record
                     })

helpers.bulk(client=es, actions=op_list, request_timeout=100)