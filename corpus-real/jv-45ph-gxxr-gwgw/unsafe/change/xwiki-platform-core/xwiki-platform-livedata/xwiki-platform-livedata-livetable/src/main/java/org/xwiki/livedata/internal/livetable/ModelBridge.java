


















package org.xwiki.livedata.internal.livetable;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.livedata.LiveDataException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.wysiwyg.converter.HTMLConverter;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.PropertyInterface;
import com.xpn.xwiki.objects.classes.BaseClass;








@Component(roles = { ModelBridge.class })
@Singleton
public class ModelBridge
{
    private static final String NEW_DOCUMENT_UPDATE_ERROR = "We do not support updating new documents.";

    private static final String REQUIRES_HTML_CONVERSION = "RequiresHTMLConversion";

    @Inject
    private ContextualAuthorizationManager authorization;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private HTMLConverter htmlConverter;

    @Inject
    @Named("local")
    private EntityReferenceSerializer<String> localSerializer;

    @Inject
    private Logger logger;
















    public Optional<Object> update(String property, Object value, DocumentReference documentReference,
        DocumentReference classReference) throws AccessDeniedException, XWikiException, LiveDataException
    {
        return update(property, value, documentReference, classReference, 0);
    }















    public Optional<Object> update(String property, Object value, DocumentReference documentReference,
        DocumentReference classReference, int objectNumber)
        throws AccessDeniedException, XWikiException, LiveDataException
    {
        this.authorization.checkAccess(Right.EDIT, documentReference);
        XWikiContext xcontext = this.xcontextProvider.get();
        XWikiDocument document = xcontext.getWiki().getDocument(documentReference, xcontext);

        if (document.isNew()) {
            throw new LiveDataException(NEW_DOCUMENT_UPDATE_ERROR);
        }


        document = document.clone();

        Object changedValue = updateProperty(property, value, classReference, objectNumber, document);

        saveDocument(document);
        return Optional.ofNullable(changedValue);
    }















    public void updateAll(Map<String, Object> properties, DocumentReference documentReference,
        DocumentReference classReference, Map<String, DocumentReference> propertyClassReferences)
        throws AccessDeniedException, XWikiException, LiveDataException
    {
        updateAll(properties, documentReference, classReference, propertyClassReferences, 0);
    }
















    public void updateAll(Map<String, Object> properties, DocumentReference documentReference,
        DocumentReference classReference, Map<String, DocumentReference> propertyClassReferences, int objectNumber)
        throws AccessDeniedException, XWikiException, LiveDataException
    {
        this.authorization.checkAccess(Right.EDIT, documentReference);
        XWikiContext xcontext = this.xcontextProvider.get();
        XWikiDocument document = xcontext.getWiki().getDocument(documentReference, xcontext);

        if (document.isNew()) {
            throw new LiveDataException(NEW_DOCUMENT_UPDATE_ERROR);
        }


        document = document.clone();

        convertPropertiesFromHtml(properties, classReference, propertyClassReferences, objectNumber);

        for (Map.Entry<String, Object> property : properties.entrySet()) {
            DocumentReference propertyClassReference = propertyClassReferences.get(property.getKey());
            DocumentReference targetClassReference = propertyClassReference != null ? propertyClassReference
                : classReference;
            this.updateProperty(property.getKey(), property.getValue(), targetClassReference, objectNumber, document);
        }

        saveDocument(document);
    }

    private void convertPropertiesFromHtml(Map<String, Object> properties, DocumentReference defaultClassReference,
        Map<String, DocumentReference> propertyClassReferences, int objectNumber)
    {
        if (properties.containsKey(REQUIRES_HTML_CONVERSION)) {
            String requiresHTMLConversion = (String) properties.remove(REQUIRES_HTML_CONVERSION);
            Set<String> propertiesRequiringHTMLConversion = getPropertiesRequiringHTMLConversion(
                requiresHTMLConversion, defaultClassReference, propertyClassReferences, objectNumber);
            for (String propertyName : propertiesRequiringHTMLConversion) {
                String syntaxKey = propertyName + "_syntax";
                String cacheKey = propertyName + "_cache";
                properties.computeIfPresent(propertyName, (k, v) ->
                    this.htmlConverter.fromHTML((String) v, (String) properties.get(syntaxKey)));
                properties.remove(syntaxKey);
                properties.remove(cacheKey);
            }
        }
    }










    public Set<String> getPropertiesRequiringHTMLConversion(String requiresHTMLConversion,
        DocumentReference defaultClassReference, Map<String, DocumentReference> propertyClassReferences,
        int objectNumber)
    {

        Set<String> result = new LinkedHashSet<>();
        String defaultClassName = this.localSerializer.serialize(defaultClassReference);
        Set<String> requiresHTMLConversionSet = new LinkedHashSet<>(Arrays.asList(requiresHTMLConversion.split(",")));


        for (Map.Entry<String, DocumentReference> entry : propertyClassReferences.entrySet()) {
            String className = this.localSerializer.serialize(entry.getValue());
            String htmlConversionProperty = getPrefix(className, objectNumber) + entry.getKey();
            if (requiresHTMLConversionSet.remove(htmlConversionProperty)) {
                result.add(entry.getKey());
            }
        }


        for (String requiresHTMLConversionProperty : requiresHTMLConversionSet) {
            String defaultPrefix = getPrefix(defaultClassName, objectNumber);
            result.add(Strings.CS.removeStart(requiresHTMLConversionProperty, defaultPrefix));
        }
        return result;
    }

    private static String getPrefix(String className, int objectNumber)
    {
        return String.format("%s_%d_", className, objectNumber);
    }

    private void saveDocument(XWikiDocument document) throws XWikiException, LiveDataException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        if (document.isContentDirty() || document.isMetaDataDirty()) {
            boolean validate = document.validate(xcontext);
            if (!validate) {
                throw new LiveDataException("Document not validated.");
            }
            document.setAuthorReference(xcontext.getUserReference());
            xcontext.getWiki().saveDocument(document, "LiveData update.", true, xcontext);
        }
    }

    private Object updateProperty(String property, Object value, DocumentReference classReference, int objectNumber,
        XWikiDocument document) throws XWikiException, LiveDataException
    {
        Object changedValue;
        if (StringUtils.defaultIfEmpty(property, "").startsWith("doc.")) {
            changedValue = updateDocument(property.substring(4), value, document);
        } else {
            changedValue = updateXObject(property, value, document, classReference, objectNumber);
        }
        return changedValue;
    }

    private Object updateXObject(String property, Object value, XWikiDocument document,
        DocumentReference classReference, int objectNumber) throws XWikiException, LiveDataException
    {
        XWikiContext xcontext = this.xcontextProvider.get();
        BaseObject baseObject = document.getXObject(classReference, objectNumber);

        if (baseObject == null && objectNumber == document.getXObjectSize(classReference)) {

            baseObject = document.newXObject(classReference, xcontext);
        }

        if (baseObject == null) {
            throw new LiveDataException(
                String.format("XObject [%s] not found at index [%d] in [%s]", classReference, objectNumber, document));
        }

        BaseClass xClass = baseObject.getXClass(xcontext);

        PropertyInterface propertyInterface = baseObject.get(property);
        Object changedValue = propertyInterface != null ? propertyInterface.toFormString() : null;

        Object newValue;
        if (value instanceof List<?> list) {
            newValue = list.stream().map(String::valueOf).toArray(String[]::new);
        } else {
            newValue = value;
        }
        xClass.fromMap(Map.of(property, newValue), baseObject);

        return changedValue;
    }

    private Object updateDocument(String property, Object value, XWikiDocument document)
    {
        Object changedValue = null;
        switch (property) {
            case "hidden" -> {
                changedValue = document.isHidden();
                document.setHidden(Boolean.valueOf(String.valueOf(value)));
            }
            case "enforceRequiredRights" -> {
                changedValue = document.isEnforceRequiredRights();
                document.setEnforceRequiredRights(Boolean.parseBoolean(String.valueOf(value)));
            }
            case "title" -> {
                changedValue = document.getTitle();
                document.setTitle(String.valueOf(value));
            }
            case "content" -> {
                changedValue = document.getContent();
                document.setContent((String) value);
            }
            case null, default -> {

                if (!Objects.equals(property, "fullName")) {
                    this.logger
                        .warn("Unknown property [{}]. Document [{}] will not be updated with value [{}].", property,
                            document,
                            value);
                }
            }
        }
        return changedValue;
    }
}
