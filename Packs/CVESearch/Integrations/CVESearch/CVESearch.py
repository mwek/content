import urllib3
from typing import Dict, Any, Tuple, List, Union

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str):
        header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, headers=header)

    def http_request(self, suffix: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Connects to api and Returns response.
           Args:
               suffix :The API endpoint.
           Returns:
               response from the api.
           """
        return self._http_request(method="GET", url_suffix=suffix)


def cve_to_context(cve):
    return {
        "ID": cve.get("id", ""),
        "CVSS": cve.get("cvss", "0"),
        "Published": cve.get("Published", "").rstrip("Z"),
        "Modified": cve.get("Modified", "").rstrip("Z"),
        "Description": cve.get("summary", '')
    }


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    res = client.http_request(suffix="/last")
    if res:
        return "ok", None, None
    raise Exception('Error occurred while trying to query the api.')


def cve_latest_commnad(client: Client, *_) -> Tuple[
        Any, Dict[str, List[Any]], Union[Dict[str, Any], List[Dict[str, Any]]]]:
    ec = []
    human_readable = []
    res = client.http_request(suffix="/last")
    for cve_details in res:
        data = cve_to_context(cve_details)
        ec.append(data)
        human_readable.append(data)
    ec = {'CVE(val.ID === obj.ID)': ec}
    human_readable = tableToMarkdown("cicle.lu Latest CVEs", human_readable)
    return human_readable, ec, res


def cve_command(client: Client, args: dict) -> Tuple[
        str, Dict[str, Dict[str, Any]], Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """Search for cve with the given ID and returns the cve data if found.
    Args:
           args :The demisto args containing the cve_id
    @return:
        CVE details containing ID, CVSS, modified date, published date and description.
    """
    cve_id = args.get("cve_id")
    res = client.http_request(f'cve/{cve_id}')
    if not res:
        return_error(f'Could not find cve results for ID {cve_id}')
    data = cve_to_context(res)
    human_readable = tableToMarkdown("CVE Search results", data)
    context = {'CVE(val.ID === obj.ID)': data}
    return human_readable, context, res


def main():
    params = demisto.params()
    # Service base URL
    base_url = params.get('url')
    client = Client(base_url=base_url)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            return_outputs(*test_module(client, demisto.args()))

        elif demisto.command() == 'cve-latest':
            return_outputs(*cve_latest_commnad(client, demisto.args()))

        elif demisto.command() == 'cve':
            return_outputs(*cve_command(client, demisto.args()))

        else:
            raise NotImplementedError(f'{command} is not an existing CVE Search command')

    except Exception as err:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
