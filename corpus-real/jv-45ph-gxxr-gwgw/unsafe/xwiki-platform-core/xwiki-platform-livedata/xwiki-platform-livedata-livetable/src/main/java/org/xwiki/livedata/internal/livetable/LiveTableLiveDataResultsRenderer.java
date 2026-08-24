


















package org.xwiki.livedata.internal.livetable;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.livedata.LiveDataQuery;
import org.xwiki.livedata.livetable.LiveDataLivetableException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.rendering.syntax.Syntax;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.template.TemplateManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

import static org.apache.commons.lang3.exception.ExceptionUtils.getRootCauseMessage;








@Component(roles = LiveTableLiveDataResultsRenderer.class)
@Singleton
public class LiveTableLiveDataResultsRenderer
{
    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> currentDocumentReferenceResolver;

    @Inject
    private ContextualAuthorizationManager authorization;

    @Inject
    private LiveTableRequestHandler liveTableRequestHandler;

    @Inject
    private TemplateManager templateManager;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private Logger logger;










    public String getLiveTableResultsFromPage(String page, LiveDataQuery query) throws AccessDeniedException
    {
        DocumentReference documentReference = this.currentDocumentReferenceResolver.resolve(page);
        this.authorization.checkAccess(Right.VIEW, documentReference);

        return this.liveTableRequestHandler.getLiveTableResults(query, () -> {
            XWikiContext xcontext = this.xcontextProvider.get();
            WikiReference currentWiki = xcontext.getWikiReference();
            xcontext.setWikiReference(documentReference.getWikiReference());
            try {

                this.templateManager.render("xwikivars.vm");
            } catch (Exception e) {
                this.logger.warn(
                    "Failed to evaluate [xwikivars.vm] when getting the Livetable results from page [{}]. Cause: [{}].",
                    page, getRootCauseMessage(e));
            }

            try {
                XWikiDocument document = xcontext.getWiki().getDocument(documentReference, xcontext);
                if (document.isNew()) {
                    throw new LiveDataLivetableException(String.format("Page [%s] does not exist.", documentReference));
                }
                return document.getRenderedContent(Syntax.PLAIN_1_0, xcontext);
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                xcontext.setWikiReference(currentWiki);
            }
        });
    }










    public String getLiveTableResultsFromTemplate(String template, LiveDataQuery query)
    {
        return this.liveTableRequestHandler.getLiveTableResults(query, () -> {
            try {
                if (this.templateManager.getTemplate(template) == null) {
                    throw new LiveDataLivetableException(String.format("Template [%s] does not exist.", template));
                }
                return this.templateManager.render(template);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
}
