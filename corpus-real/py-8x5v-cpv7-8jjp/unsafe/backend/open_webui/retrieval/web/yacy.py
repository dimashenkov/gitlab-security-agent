import logging
from typing import Optional

import requests
from open_webui.retrieval.web.main import SearchResult, get_filtered_results
from requests.auth import HTTPDigestAuth

log = logging.getLogger(__name__)


def search_yacy(
    query_url: str,
    username: Optional[str],
    password: Optional[str],
    query: str,
    count: int,
    filter_list: Optional[list[str]] = None,
) -> list[SearchResult]:
    ''



















    yacy_auth = None
    if username or password:
        yacy_auth = HTTPDigestAuth(username, password)

    params = {
        'query': query,
        'contentdom': 'text',
        'resource': 'global',
        'maximumRecords': count,
        'nav': 'none',
    }


    if not query_url.endswith('yacysearch.json'):

        query_url = query_url.rstrip('/') + '/yacysearch.json'

    log.debug(f'searching {query_url}')

    response = requests.get(
        query_url,
        auth=yacy_auth,
        headers={
            'User-Agent': 'Open WebUI (https://github.com/open-webui/open-webui) RAG Bot',
            'Accept': 'text/html',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        },
        params=params,
    )

    response.raise_for_status()

    json_response = response.json()
    results = json_response.get('channels', [{}])[0].get('items', [])
    sorted_results = sorted(results, key=lambda x: x.get('ranking', 0), reverse=True)
    if filter_list:
        sorted_results = get_filtered_results(sorted_results, filter_list)
    return [
        SearchResult(
            link=result['link'],
            title=result.get('title'),
            snippet=result.get('description'),
        )
        for result in sorted_results[:count]
    ]
