#!/usr/bin/env python
from cgitb import enable
from argparse import ArgumentParser
from concurrent.futures import process
import csv
from fileinput import filename
import requests
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument('command')
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument('-p', '--process-groups', help="List of Process Group IDs", nargs='+', default=[])
parser.add_argument('-f', '--file', help="CSV file containing the Process Group in the first column (no header)")

args = parser.parse_args()
env = args.environment
token = args.token
command = args.command
pgIds = args.process_groups
filename = args.file

settingsKey = 'SENSOR_JAVA_CASP_FLAW_FINDER'
if filename:
    pgIds = []
    with open(filename, newline='') as csvfile:
        filereader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in filereader:
            pgIds.append(row[0])
            # print(row)


def post(endpoint, payload):
        """
        Calls the given endpoint on the Dynatrace API. 
        param: string endpoint: API endpoint to be called
        return: response as json
        """
        authHeader = {'Authorization' : 'Api-Token '+ token}
        url = env + endpoint
        response = requests.post(url, headers=authHeader, json=payload)
        logging.info('API Call Status: %s Request: %s', response.status_code, url);
        logging.debug('Response: %s', response.content)
        if response.reason != 'OK':
            logging.error('Request %s failed', url)
            logging.error('Status Code: %s (%s), Response: %s', response.status_code, response.reason, response.content)
            raise RuntimeError(f'API request failed: {response.status_code} ({response.reason})', response.content)
        return response.json()

def get(endpoint):
        """
        Calls the given endpoint on the Dynatrace API. 
        param: string endpoint: API endpoint to be called
        return: response as json
        """
        authHeader = {'Authorization' : 'Api-Token '+ token}
        url = env + endpoint
        response = requests.get(url, headers=authHeader)
        logging.info('API Call Status: %s Request: %s', response.status_code, url);
        logging.debug('Response: %s', response.content)
        if response.reason != 'OK':
            logging.error('Request %s failed', url)
            logging.error('Status Code: %s (%s), Response: %s', response.status_code, response.reason, response.content)
            raise RuntimeError(f'API request failed: {response.status_code} ({response.reason})', response.content)
        return response.json()

def getFlawFinderSettings():
    settingsResponse = get('/api/v2/settings/objects?schemaIds=builtin:oneagent.features&fields=objectId,value, updateToken, scope&pageSize=500')
    return list(filter(lambda ob: ob['value']['key'] == settingsKey, settingsResponse['items']))

def getPGs(pgIds):
    pgs = []
    # split the list into chunks of 100 in order to avoid too large requests (URI too long)
    pgIdParts = splitIntoChunks(pgIds, 100)
    for pgIds in pgIdParts:
        ids = ','.join('"'+i+'"' for i in pgIds)
        response = get('/api/v2/entities?pageSize=100&entitySelector=entityId('+ids+')')
        pgs += response['entities']
    dic = dict((x['entityId'], x) for x in pgs)
    return dic

def splitIntoChunks(list, maxLength):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(list), maxLength):
            yield list[i:i + maxLength]

def toggleOneAgentSetting(enable, pgIds):
    payload = list(map(lambda pgId:  {
            "schemaId": "builtin:oneagent.features",
            "value": {
                        "enabled": enable,
                        "instrumentation": enable,
                        "key": "SENSOR_JAVA_CASP_FLAW_FINDER"
            },
            "schemaVersion": "1.5.4",
            "scope": pgId
        }, pgIds))
    response = post('/api/v2/settings/objects/', payload)
    print(response)

def createMonitoringRule(enable, pgIds):
    payload = list(map(lambda pgId:   {
      "schemaId": "builtin:appsec.code-level-vulnerability-rule-settings",
      "scope": "environment",
      "value": {
        "enabled": enable,
        "criteria": {
          "processGroup": pgId
        },
        "vulnerabilityDetectionControl": {
          "monitoringMode": "MONITORING_ON"
        },
        "metadata": {
          "comment": ""
        }
      }
    }, pgIds))
    response = post('/api/v2/settings/objects/', payload)
    print(response)


# print(settings)

if command == 'enable':
    toggleOneAgentSetting(True, pgIds)
    createMonitoringRule(True, pgIds)
elif command == 'disable':
    toggleOneAgentSetting(False, pgIds)
    #createMonitoringRule(False, pgIds)
else:
    settings = getFlawFinderSettings()
    pgIdsWithSettings = list(filter(lambda e: e.startswith("PROCESS_GROUP"), map(lambda e: e['scope'],settings)))
    if pgIds:
        scopeDic = dict((x['scope'], x) for x in settings)
        # pgs = getPGs(pgIds)
        for pgId in pgIds:
            if pgId in scopeDic.keys():
                scopeSettings = scopeDic[pgId]
                print(pgId + ' enabled '+ str(scopeSettings['value']['enabled']))
            else:
                print(pgId + ' -')

    else:
        pgs = getPGs(pgIdsWithSettings)
        for i in settings:
            if i['scope'] in pgs.keys():
                pg = pgs[i['scope']]
                print(pg['displayName']+'('+i['scope']+')' + ' enabled '+ str(i['value']['enabled']))
            else:
                print(i['scope'] + ' enabled:'+ str(i['value']['enabled']))


