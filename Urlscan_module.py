from datetime import datetime

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ProcessingModule

class Urlscan_module(ProcessingModule):

    name = "urlscan"
    description = "Get report from URLScan platform."
    config = [
        {
            'name': 'api_search',
            'type': 'string',
            'description': 'API path needed to use the URLScan Public API 2.0',
        }
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, 'Missing dependency: requests')

        return True

    def each_with_type(self, target, file_type):
        if file_type == "url":
            if "http://" in target or "https://" in target:
                target = target.replace("http://", "")
                target = target.replace("https://", "")
                target = target.split("/")[0]
            response = requests.get(url=self.api_search, params={'q': target})
            if response.status_code == 200:
                self.results = {}
                if len(response.json()['results']) > 0:
                    urlscan_result = None
                    for result in response.json()['results']:
                        if target in result['page']['domain'] or target in result['task']['url']:
                            urlscan_result = result['result']
                            break
                    if urlscan_result is not None:
                        response = requests.get(url=urlscan_result)
                        response_results = response.json()
                        self.results['status'] = "Succesfully"
                        self.results['domain'] = response_results['page']['domain'] if 'domain' in response_results['page'] else "-"
                        self.results['country'] = response_results['page']['country'] if 'country' in response_results['page'] else "-"
                        self.results['server'] = response_results['page']['server'] if 'server' in response_results['page'] else "-"
                        self.results['ip'] = response_results['page']['ip'] if 'ip' in response_results['page'] else "-"
                        self.results['verdict'] = {}
                        self.results['verdict']['score'] = response_results['verdicts']['overall']['score']
                        self.results['verdict']['malicious'] = response_results['verdicts']['overall']['malicious']
                        self.results['permalink'] = "https://urlscan.io/result/" + response_results['task']['uuid']
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return False
