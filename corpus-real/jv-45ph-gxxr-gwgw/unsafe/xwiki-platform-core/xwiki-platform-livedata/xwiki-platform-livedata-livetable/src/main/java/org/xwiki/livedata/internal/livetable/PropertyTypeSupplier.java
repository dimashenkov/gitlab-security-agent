


















package org.xwiki.livedata.internal.livetable;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.PropertyInterface;
import com.xpn.xwiki.objects.classes.PropertyClass;







@Component(roles = PropertyTypeSupplier.class)
@Singleton
public class PropertyTypeSupplier
{
    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private DocumentReferenceResolver<String> currentDocumentReferenceResolver;









    public String getPropertyType(String propertyName, String className)
    {
        DocumentReference classReference = this.currentDocumentReferenceResolver.resolve(className);
        XWikiContext xcontext = this.xcontextProvider.get();
        try {
            XWikiDocument classDocument = xcontext.getWiki().getDocument(classReference, xcontext);
            PropertyInterface property = classDocument.getXClass().get(propertyName);
            if (property instanceof PropertyClass) {
                return ((PropertyClass) property).getClassType();
            }
        } catch (XWikiException e) {
            this.logger.warn("Failed to read the type of property [{}] from [{}]. Root cause is [{}].", propertyName,
                className, ExceptionUtils.getRootCauseMessage(e));
        }
        return null;
    }
}
