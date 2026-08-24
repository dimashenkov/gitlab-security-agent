


















package org.xwiki.livedata.internal.livetable;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import com.xpn.xwiki.web.XWikiResponse;
import com.xpn.xwiki.web.XWikiServletResponse;







public class LiveTableResponse extends XWikiServletResponse
{
    private StringWriter content = new StringWriter();

    private PrintWriter writer = new PrintWriter(this.content);

    private boolean committed;






    public LiveTableResponse(XWikiResponse response)
    {
        super(response);
    }




    public String getContent()
    {
        return this.content.toString();
    }

    @Override
    public PrintWriter getWriter() throws IOException
    {

        return this.writer;
    }

    @Override
    public void setContentType(String type)
    {

    }

    @Override
    public void setCharacterEncoding(String s)
    {

    }

    @Override
    public void setContentLength(int length)
    {

    }

    @Override
    public void setContentLengthLong(long length)
    {

    }

    @Override
    public void flushBuffer() throws IOException
    {

        this.committed = true;
    }

    @Override
    public boolean isCommitted()
    {
        return this.committed;
    }
}
