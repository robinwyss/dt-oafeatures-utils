#!/usr/bin/env python
from cgitb import enable
import string
import sys
import csv
from argparse import ArgumentParser
import requests
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--tag", dest="tag", help="Process Group Tag to filter by")
parser.add_argument("--mz", dest="mz", help="Management Zone to filter by")

args = parser.parse_args()
env = args.environment
token = args.token
tag = args.tag
mz = args.mz

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


def getPGs():
    pgs = []
    # split the list into chunks of 100 in order to avoid too large requests (URI too long)
    url = '/api/v2/entities?pageSize=500&entitySelector=type(PROCESS_GROUP)'
    if mz:
        url += ',mzName("'+mz+'")'
    elif tag:
        url += ',tag('+tag+')'
    response = get(url)
    pgs += response['entities']
    return pgs

pgs = getPGs()
for pg in pgs:
    print(pg['entityId'] + ','+ pg['displayName'])