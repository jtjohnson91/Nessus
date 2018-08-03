#!/usr/bin/python
import requests, json, os
from httplib2 import Http
from json import dumps

##USE AN API AND YOUR USERNAME FOR AUTH BY EDITING THE BELOW VARIALBES
_AccessKey = '<INSERT API ACCESS KEY HERE>'
_SecretKey = '<INSERT API SECRET KEY HERE>
_Username = '<INSERT TENABLE.IO USERNAME HERE>'

headers = {
    'X-Impersonate': 'username=%s' % (_Username),
    'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (_AccessKey, _SecretKey)
}
f1 = open('./tmpfile', 'w+')


_DATERANGE = '<INSERT DESIDERED DATE RANGE HERE>'
_IPSUBNET = '<INSERT SUBNET HERE (EXAMPLE 192.168.0 FOR A 192.168.0.0/24 NETWORK)>'
##CHOOSE YOUR SEVERITY LEVEL FOR REPORTING BY USING ONE OF THE BELOW VARIALBE
#_SEVERITY = 'critical'
_SEVERITY = 'critical,high'
#_SEVERITY = 'critical,high,medium'
#_SEVERITY = 'critical,high,medium,low'
#_SEVERITY = 'critical,high,medium,low,info'

response = requests.get('https://cloud.tenable.com/workbenches/vulnerabilities?date_range=%s&filter.0.quality=match&filter.0.filter=host.target&filter.0.value=%s&filter.search_type=and&severity=%s' % (_DATERANGE, _IPSUBNET, _SEVERITY), headers=headers)
obj = json.loads(response.content.decode('utf-8'))
for x in obj["vulnerabilities"]:
  f1.write("\n-------------------------------------------\n")
  plugin = x["plugin_id"]
  f1.write("Vulnerabilty:   " + x["plugin_name"] +  "\n URL:  https://www.tenable.com/plugins/nessus/" + "%s" % (plugin))
  response2 = requests.get('https://cloud.tenable.com/workbenches/vulnerabilities/%s/info' %(plugin), headers=headers)
  obj2 = json.loads(response2.content.decode('utf-8'))
  f1.write("\n" + " Mitigation:  " + obj2["info"]["solution"])
  response3 = requests.get('https://cloud.tenable.com/workbenches/vulnerabilities/%s/outputs?date_range=%s&filter.0.quality=match&filter.0.filter=host.target&filter.0.value=%s&filter.search_type=and&severity=%s' %(plugin, _DATERANGE, _IPSUBNET, _SEVERITY), headers=headers)
  obj3 = json.loads(response3.content.decode('utf-8'))
  f1.write("\n Hosts:")
  for y in obj3["outputs"][0]["states"][0]["results"][0]["assets"]:
   f1.write("\n  " + y["hostname"])
f1.close()
vuln = open('./tmpfile')
vuln = vuln.read()
##THE VARIABLE 'vuln' CONTAINS THE INFORMATION GATHERED.
##IF USING GOOGLE CHAT TO ALERT UNCOMMENT THE BELOW AND EDIT THE "url" VARIABLE TO YOUR WEBHOOK URL
#msg = { 'text': "\n      *Vulnerabilites*" +'%s' % (vuln) }
#headers2 = {'Content-Type': 'application/json'}
#url = "<INSERT GOOGLE WEBHOOK URL HERE>"
#response = Http().request(
# uri=url,
# method='POST',
# headers=headers2,
# body=dumps(msg)
#)
os.remove("./tmpfile")

