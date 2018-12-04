# Thretelli
Gather threat intel on addresses and domains using multiple OSINT sources. 

## Usage 
`python3 intel.py {IP or Domain}`

## Support Sources
### :white_check_mark: Virus Total 
#### GET /ip-address/report
#### GET /domain/report
___
### :white_check_mark: IBM Exchange
#### GET /resolve/{IP or Domain}
___
### :white_check_mark: Cymon 
Note: Domain lookups are depricated 
#### GET /ip/{ip}
#### GET /ip/{ip}/events
#### GET /ip/{ip}/domains
#### GET /ip/{ip}/urls
#### GET /ip/{ip}/timeline
#### GET /ip/{ip}/malware
___
### :white_check_mark: GreyNoise
#### GET /v2/noise/quick/{ip}
#### GET /v2/noise/context/{ip}
___
### :heavy_exclamation_mark: Passive Total 
Note: Out of commission - Quota Exceeded
#### GET /v2/enrichment

