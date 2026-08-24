


















package org.xwiki.livedata.internal.livetable;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

import com.xpn.xwiki.web.WrappingXWikiRequest;
import com.xpn.xwiki.web.XWikiRequest;







class LiveTableRequest extends WrappingXWikiRequest
{
    private final Map<String, String[]> parameters;

    LiveTableRequest(XWikiRequest request, Map<String, String[]> parameters)
    {
        super(request);
        this.parameters = parameters;
    }

    @Override
    public Map<String, String[]> getParameterMap()
    {
        return this.parameters;
    }

    @Override
    public String getParameter(String name)
    {
        return this.parameters.getOrDefault(name, new String[] {null})[0];
    }

    @Override
    public String get(String name)
    {
        return this.getParameter(name);
    }

    @Override
    public String[] getParameterValues(String name)
    {
        return this.parameters.get(name);
    }

    @Override
    public Enumeration<String> getParameterNames()
    {
        return Collections.enumeration(this.parameters.keySet());
    }
}
