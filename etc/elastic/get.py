from elasticsearch import Elasticsearch

es = Elasticsearch("http://elasticsearch.elastic:9200",basic_auth=('elastic', 'test'))
res = es.count(index='gbifdata', query= {'match_all':{} })["count"]

print(res)