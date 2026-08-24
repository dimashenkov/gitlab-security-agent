


















package org.xwiki.livedata.internal.livetable;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.livedata.LiveDataQuery;
import org.xwiki.livedata.LiveDataQuery.Constraint;
import org.xwiki.livedata.LiveDataQuery.Filter;
import org.xwiki.livedata.LiveDataQuery.Source;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;







@Component(roles = LiveTableRequestHandler.class)
@Singleton
public class LiveTableRequestHandler
{
    static final String TEMPLATE = "template";

    static final String RESULT_PAGE = "resultPage";

    static final String CONTEXT_DOC = "$doc";

    @SuppressWarnings("serial")
    private static final Map<String, String> MATCH_TYPE = new HashMap<String, String>()
    {
        {
            put("equals", "exact");
            put("contains", "partial");
            put("startsWith", "prefix");
        }
    };

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> currentDocumentReferenceResolver;









    public String getLiveTableResults(LiveDataQuery liveDataQuery, Supplier<String> liveTableResultsSupplier)
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        String originalAction = xcontext.getAction();
        xcontext.setAction("get");

        XWikiDocument originalDoc = maybeSetContextDocument(xcontext, liveDataQuery);

        XWikiRequest originalRequest = xcontext.getRequest();
        xcontext.setRequest(new LiveTableRequest(originalRequest, getRequestParameters(liveDataQuery)));

        XWikiResponse originalResponse = xcontext.getResponse();
        LiveTableResponse liveTableResponse = new LiveTableResponse(originalResponse);
        xcontext.setResponse(liveTableResponse);

        boolean finished = xcontext.isFinished();
        try {
            String liveTableResultsJSON = liveTableResultsSupplier.get();


            return liveTableResponse.isCommitted() ? liveTableResponse.getContent() : liveTableResultsJSON;
        } finally {
            xcontext.setAction(originalAction);
            xcontext.setDoc(originalDoc);
            xcontext.setRequest(originalRequest);
            xcontext.setResponse(originalResponse);
            xcontext.setFinished(finished);
        }
    }

    private XWikiDocument maybeSetContextDocument(XWikiContext xcontext, LiveDataQuery liveDataQuery)
    {
        XWikiDocument originalDoc = xcontext.getDoc();

        Source source = liveDataQuery.getSource();
        String contextDocRefString = (String) (source != null ? source : new Source()).getParameters().get(CONTEXT_DOC);
        if (contextDocRefString != null) {
            DocumentReference contextDocRef = this.currentDocumentReferenceResolver.resolve(contextDocRefString);
            try {
                XWikiDocument contextDoc = xcontext.getWiki().getDocument(contextDocRef, xcontext);
                xcontext.setDoc(contextDoc);
            } catch (XWikiException e) {
                this.logger.debug("Failed to set context document [{}] for live table results.", contextDocRefString,
                    e);
            }
        }

        return originalDoc;
    }

    private Map<String, String[]> getRequestParameters(LiveDataQuery query)
    {
        Map<String, String[]> requestParams = new HashMap<>();


        requestParams.put("outputSyntax", new String[] {"plain"});


        addSourceRequestParameters(query, requestParams);


        Stream.of(TEMPLATE, RESULT_PAGE, CONTEXT_DOC).forEach(requestParams::remove);


        String[] className = requestParams.remove("className");
        if (className != null) {
            requestParams.put("classname", className);
        }


        String[] translationPrefix = requestParams.remove("translationPrefix");
        if (translationPrefix != null) {
            requestParams.put("transprefix", translationPrefix);
        }


        if (query.getProperties() != null) {
            requestParams.put("collist", new String[] {StringUtils.join(query.getProperties(), ",")});
        }


        addSortRequestParameters(query, requestParams);


        if (query.getFilters() != null) {
            query.getFilters().stream().forEach(filter -> addFilterRequestParameters(filter, requestParams));
        }


        if (query.getOffset() != null) {
            requestParams.put("offset", new String[] {String.valueOf(query.getOffset() + 1)});
        }
        if (query.getLimit() != null) {
            requestParams.put("limit", new String[] {String.valueOf(query.getLimit())});
        }



        requestParams.put("reqNo", new String[] {"1"});

        return requestParams;
    }

    @SuppressWarnings("unchecked")
    private void addSourceRequestParameters(LiveDataQuery query, Map<String, String[]> requestParams)
    {
        if (query.getSource() != null) {
            for (Map.Entry<String, Object> entry : query.getSource().getParameters().entrySet()) {
                Stream<Object> stream;
                if (entry.getValue() instanceof Collection) {
                    stream = ((Collection<Object>) entry.getValue()).stream();
                } else {

                    stream = Stream.of(entry.getValue());
                }
                List<String> values =
                    stream.filter(Objects::nonNull).map(Object::toString).collect(Collectors.toList());
                if (!values.isEmpty()) {
                    requestParams.put(entry.getKey(), values.toArray(new String[values.size()]));
                }
            }
        }
    }

    private void addSortRequestParameters(LiveDataQuery query, Map<String, String[]> requestParams)
    {
        if (query.getSort() != null && !query.getSort().isEmpty()) {
            List<String> sortList =
                query.getSort().stream().map(sortEntry -> sortEntry.getProperty()).collect(Collectors.toList());
            requestParams.put("sort", sortList.toArray(new String[sortList.size()]));
            List<String> dirList = query.getSort().stream().map(sortEntry -> sortEntry.isDescending() ? "desc" : "asc")
                .collect(Collectors.toList());
            requestParams.put("dir", dirList.toArray(new String[dirList.size()]));
        }
    }

    private void addFilterRequestParameters(Filter filter, Map<String, String[]> requestParams)
    {
        List<String> values = filter.getConstraints().stream().filter(Objects::nonNull).map(Constraint::getValue)
            .filter(Objects::nonNull).map(Object::toString).collect(Collectors.toList());
        if (!values.isEmpty()) {
            requestParams.put(filter.getProperty(), values.toArray(new String[values.size()]));
            requestParams.put(filter.getProperty() + "/join_mode", new String[] {filter.isMatchAll() ? "AND" : "OR"});

            List<String> matchType = filter.getConstraints().stream()
                .map(constraint -> constraint == null ? null : constraint.getOperator())
                .map(operator -> MATCH_TYPE.getOrDefault(operator, StringUtils.defaultString(operator)))
                .collect(Collectors.toList());
            requestParams.put(filter.getProperty() + "_match", matchType.toArray(new String[matchType.size()]));




            for (int i = 0; i < matchType.size(); i++) {
                if (Objects.equals(matchType.get(i), "empty")) {
                    requestParams.get(filter.getProperty())[i] = "-";
                }
            }
        }
    }
}
