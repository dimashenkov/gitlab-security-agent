import logging
from typing import Optional

from open_webui.retrieval.web.main import SearchResult, get_filtered_results

log = logging.getLogger(__name__)

''








def search_azure(
    api_key: str,
    endpoint: str,
    index_name: str,
    query: str,
    count: int,
    filter_list: Optional[list[str]] = None,
) -> list[SearchResult]:
    ''













    try:
        from azure.core.credentials import AzureKeyCredential
        from azure.search.documents import SearchClient
    except ImportError:
        log.error(
            'azure-search-documents package is not installed. Install it with: pip install azure-search-documents'
        )
        raise ImportError(
            'azure-search-documents is required for Azure AI Search. '
            'Install it with: pip install azure-search-documents'
        )

    try:

        credential = AzureKeyCredential(api_key)
        search_client = SearchClient(endpoint=endpoint, index_name=index_name, credential=credential)


        results = search_client.search(search_text=query, top=count)


        search_results = []
        for result in results:



            result_dict = dict(result)


            link = (
                result_dict.get('url')
                or result_dict.get('link')
                or result_dict.get('uri')
                or result_dict.get('metadata_storage_path')
                or ''
            )


            title = (
                result_dict.get('title')
                or result_dict.get('name')
                or result_dict.get('metadata_title')
                or result_dict.get('metadata_storage_name')
                or None
            )


            snippet = (
                result_dict.get('content')
                or result_dict.get('snippet')
                or result_dict.get('description')
                or result_dict.get('summary')
                or result_dict.get('text')
                or None
            )


            if snippet and len(snippet) > 500:
                snippet = snippet[:497] + '...'

            if link:
                search_results.append(
                    {
                        'link': link,
                        'title': title,
                        'snippet': snippet,
                    }
                )


        if filter_list:
            search_results = get_filtered_results(search_results, filter_list)


        return [
            SearchResult(
                link=result['link'],
                title=result.get('title'),
                snippet=result.get('snippet'),
            )
            for result in search_results
        ]

    except Exception as ex:
        log.error(f'Azure AI Search error: {ex}')
        raise ex
