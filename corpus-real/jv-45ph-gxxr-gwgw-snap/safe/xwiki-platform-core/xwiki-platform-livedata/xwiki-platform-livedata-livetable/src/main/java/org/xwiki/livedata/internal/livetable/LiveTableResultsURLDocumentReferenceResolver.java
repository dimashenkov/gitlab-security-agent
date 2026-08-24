


















package org.xwiki.livedata.internal.livetable;

import java.net.URL;
import java.util.Collections;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.resource.ResourceReference;
import org.xwiki.resource.ResourceReferenceResolver;
import org.xwiki.resource.ResourceType;
import org.xwiki.resource.ResourceTypeResolver;
import org.xwiki.resource.entity.EntityResourceReference;
import org.xwiki.url.ExtendedURL;

import com.xpn.xwiki.XWikiContext;






@Component(roles = LiveTableResultsURLDocumentReferenceResolver.class)
@Singleton
public class LiveTableResultsURLDocumentReferenceResolver
{
    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private ResourceTypeResolver<ExtendedURL> typeResolver;

    @Inject
    private ResourceReferenceResolver<ExtendedURL> resourceResolver;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<EntityReference> currentEntityDocumentReferenceResolver;

    @Inject
    private EntityReferenceSerializer<String> defaultEntityReferenceSerializer;







    public String resolve(String liveTableResultsURL)
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        try {
            URL url = new URL(xcontext.getURL(), liveTableResultsURL);
            ExtendedURL extendedURL = new ExtendedURL(url, xcontext.getRequest().getContextPath());
            ResourceType type = this.typeResolver.resolve(extendedURL, Collections.emptyMap());
            ResourceReference reference = this.resourceResolver.resolve(extendedURL, type, Collections.emptyMap());
            if (reference instanceof EntityResourceReference) {
                EntityReference entityReference = ((EntityResourceReference) reference).getEntityReference();
                DocumentReference documentReference =
                    this.currentEntityDocumentReferenceResolver.resolve(entityReference);
                return this.defaultEntityReferenceSerializer.serialize(documentReference);
            }
        } catch (Exception e) {
            this.logger.debug("Failed to extract a document reference from [{}].", liveTableResultsURL, e);
        }

        return null;
    }
}
