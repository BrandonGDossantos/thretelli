import requests
import json
import sys
import validators
import configparser

'''
Virus Total 
'''
def virustotal_ip_report(ip):
    url = '%s%s' % (VIRUSTOTAL_BASE_URL, '/ip-address/report')
    params = {'ip': ip, 'apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, params=params)
    return response.json()

def virustotal_domain_report(domain):
    url = '{}{}'.format(VIRUSTOTAL_BASE_URL, '/domain/report')
    params = {'domain': domain, 'apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, params=params)
    return response.json()

'''
Cymon
'''
def cymon_ip_report(ip):
    url = '%sip/%s' % (CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

def cymon_ip_events_report(ip):
    url = '{}ip/{}/events'.format(CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

def cymon_ip_domains_report(ip):
    url = '{}ip/{}/domains'.format(CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

def cymon_ip_urls_report(ip):
    url = '{}ip/{}/urls'.format(CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

def cymon_ip_timeline_report(ip):
    url = '{}ip/{}/timeline'.format(CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

def cymon_ip_malware_report(ip):
    url = '{}ip/{}/malware'.format(CYMON_BASE_URL, ip)
    response = requests.get(url, headers=CYMON_HEADERS)
    return response.json()

'''
IBM Exchange
'''
def ibmexchange_resolve(artifact):
    url = '{}/resolve/{}'.format(IBMEXCHANGE_BASE_URL, artifact)
    response = requests.get(url, auth=IBMEXCHANGE_AUTH)
    return response.json()

'''
GreyNoise
'''
def greynoise_ip_quick(ip):
    url = '{}/v2/noise/quick/{}'.format(GREYNOISE_BASE_URL, ip)
    headers = {'key': GREYNOISE_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

def greynoise_ip_context(ip):
    url = '{}/v2/noise/context/{}'.format(GREYNOISE_BASE_URL, ip)
    headers = {'key': GREYNOISE_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

'''
PassiveTotal
'''
def passivetotal_enrichment(artifact):
    url = PASSIVETOTAL_BASE_URL + '/enrichment'
    data = {'query': artifact}
    response = requests.get(url, auth=PASSIVETOTAL_AUTH, json=data)
    return response.json()

if __name__ == "__main__":
    res = {'VirusTotal':{}, 'PassiveTotal':{}, 'Cymon':{}, 'IBM X-Force': {}, 'GreyNoise': {}}
    config = configparser.ConfigParser()
    config.read("config.cfg")

    # VirusTotal
    VIRUSTOTAL_API_KEY = config.get('virustotal', 'VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_BASE_URL = config.get('virustotal', 'VIRUSTOTAL_BASE_URL')

    # Cymon
    CYMON_API_KEY = config.get('cymon', 'CYMON_API_KEY')
    CYMON_BASE_URL = config.get('cymon', 'CYMON_BASE_URL')
    CYMON_HEADERS = {'Authorization': 'Token {}'.format(CYMON_API_KEY)}

    # IBM Exchange
    IBMEXCHANGE_API_KEY = config.get('ibmexchange', 'IBMEXCHANGE_API_KEY')
    IBMEXCHANGE_API_PASSWORD = config.get('ibmexchange', 'IBMEXCHANGE_API_PASSWORD')
    IBMEXCHANGE_BASE_URL = config.get('ibmexchange', 'IBMEXCHANGE_BASE_URL')
    IBMEXCHANGE_AUTH = (IBMEXCHANGE_API_KEY, IBMEXCHANGE_API_PASSWORD)

    # Passive Total
    PASSIVETOTAL_USERNAME = config.get('passivetotal', 'PASSIVETOTAL_USERNAME')
    PASSIVETOTAL_API_KEY = config.get('passivetotal', 'PASSIVETOTAL_API_KEY')
    PASSIVETOTAL_BASE_URL = config.get('passivetotal', 'PASSIVETOTAL_BASE_URL')
    PASSIVETOTAL_AUTH = (PASSIVETOTAL_USERNAME, PASSIVETOTAL_API_KEY)

    # GreyNoise 
    GREYNOISE_API_KEY = config.get('greynoise', 'GREYNOISE_API_KEY')
    GREYNOISE_BASE_URL = config.get('greynoise', 'GREYNOISE_BASE_URL')

    try: 
        artifact = sys.argv[1]
        if validators.ipv4(artifact):
            res['VirusTotal']['IP Report'] = virustotal_ip_report(artifact)
            res['IBM X-Force'] = ibmexchange_resolve(artifact)
            res['PassiveTotal'] = passivetotal_enrichment(artifact)
            res['Cymon'] = cymon_ip_report(artifact)
            res['Cymon']['Cymon IP Events'] = cymon_ip_events_report(artifact)
            res['Cymon']['Cymon IP Domains'] = cymon_ip_domains_report(artifact)
            res['Cymon']['Cymon IP URLs'] = cymon_ip_urls_report(artifact)
            res['Cymon']['Cymon IP Timeline'] = cymon_ip_timeline_report(artifact)
            res['Cymon']['Cymon IP Malware'] = cymon_ip_malware_report(artifact)
            res['GreyNoise']['Quick'] = greynoise_ip_quick(artifact)
            res['GreyNoise']['Context'] = greynoise_ip_context(artifact)
        if validators.domain(artifact):
            res['VirusTotal']['Domain Report'] = virustotal_domain_report(artifact)
            res['IBM X-Force'] = ibmexchange_resolve(artifact)
            res['PassiveTotal'] = passivetotal_enrichment(artifact)
    except:
        raise ValueError("Please add an artifact")
    f = open("{}.json".format(artifact), 'w')
    f.write(json.dumps(res, indent=4))
    f.close()