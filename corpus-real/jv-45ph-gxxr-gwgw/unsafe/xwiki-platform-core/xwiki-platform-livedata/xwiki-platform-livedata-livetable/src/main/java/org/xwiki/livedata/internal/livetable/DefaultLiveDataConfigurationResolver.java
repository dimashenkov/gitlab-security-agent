


















package org.xwiki.livedata.internal.livetable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.livedata.AbstractLiveDataConfigurationResolver;
import org.xwiki.livedata.LiveDataActionDescriptor;
import org.xwiki.livedata.LiveDataConfiguration;
import org.xwiki.livedata.LiveDataException;
import org.xwiki.livedata.LiveDataMeta;
import org.xwiki.livedata.LiveDataPropertyDescriptor;
import org.xwiki.livedata.LiveDataPropertyDescriptorStore;
import org.xwiki.livedata.LiveDataQuery;
import org.xwiki.livedata.LiveDataQuery.SortEntry;
import org.xwiki.livedata.LiveDataQuery.Source;
import org.xwiki.livedata.WithParameters;
import org.xwiki.localization.ContextualLocalizationManager;








@Component
@Named("liveTable")
@Singleton
public class DefaultLiveDataConfigurationResolver extends AbstractLiveDataConfigurationResolver
{



    @Inject
    private ContextualLocalizationManager l10n;





    @Inject
    @Named("liveTable")
    private Provider<LiveDataPropertyDescriptorStore> propertyStoreProvider;

    @Inject
    @Named("liveTable")
    private Provider<LiveDataConfiguration> defaultConfigProvider;

    @Override
    public LiveDataConfiguration resolve(LiveDataConfiguration config) throws LiveDataException
    {
        LiveDataConfiguration mergedConfig = super.resolve(config);





        setDefaultSort(mergedConfig);


        return translate(mergedConfig, config);
    }

    @Override
    protected LiveDataConfiguration getDefaultConfiguration(LiveDataConfiguration config) throws LiveDataException
    {
        LiveDataConfiguration defaultConfig = this.defaultConfigProvider.get();




        defaultConfig.getMeta().setPropertyDescriptors(getPropertyStore(config.getQuery().getSource()).get());

        List<String> properties = config.getQuery().getProperties();
        if (properties != null) {

            addMissingPropertyDescriptors(defaultConfig, properties);
        }

        return defaultConfig;
    }

    private LiveDataPropertyDescriptorStore getPropertyStore(Source sourceConfig)
    {
        LiveDataPropertyDescriptorStore propertyStore = this.propertyStoreProvider.get();
        if (propertyStore instanceof WithParameters && sourceConfig != null) {
            ((WithParameters) propertyStore).getParameters().putAll(sourceConfig.getParameters());
        }
        return propertyStore;
    }

    private void setDefaultSort(LiveDataConfiguration config)
    {
        LiveDataQuery query = config.getQuery();
        if (query.getProperties() != null) {


            Optional<String> firstNonSpecialProperty = query.getProperties().stream().filter(Objects::nonNull)
                .filter(property -> !property.startsWith("_")).findFirst();
            if (firstNonSpecialProperty.isPresent()
                && isPropertySortable(firstNonSpecialProperty.get(), config.getMeta()))
            {
                if (query.getSort() == null) {
                    query.setSort(new ArrayList<>());
                }
                if (query.getSort().isEmpty()) {

                    query.getSort().add(new SortEntry(firstNonSpecialProperty.get()));
                } else if (query.getSort().size() == 1 && query.getSort().get(0).getProperty() == null) {

                    query.getSort().get(0).setProperty(firstNonSpecialProperty.get());
                }
            }
        }

        if (query.getSort() != null) {

            query.setSort(query.getSort().stream().filter(Objects::nonNull)
                .filter(sortEntry -> !StringUtils.isEmpty(sortEntry.getProperty())).collect(Collectors.toList()));
        }
    }

    private boolean isPropertySortable(String property, LiveDataMeta meta)
    {
        Optional<LiveDataPropertyDescriptor> propertyDescriptor = meta.getPropertyDescriptors().stream()
            .filter(descriptor -> Objects.equals(property, descriptor.getId())).findFirst();
        if (!propertyDescriptor.isPresent()) {
            return false;
        } else if (propertyDescriptor.get().isSortable() != null) {
            return propertyDescriptor.get().isSortable();
        } else {
            String propertyType = propertyDescriptor.get().getType();
            Optional<LiveDataPropertyDescriptor> propertyTypeDescriptor = meta.getPropertyTypes().stream()
                .filter(descriptor -> Objects.equals(descriptor.getId(), propertyType)).findFirst();
            return propertyTypeDescriptor.isPresent() && Boolean.TRUE.equals(propertyTypeDescriptor.get().isSortable());
        }
    }

    private void addMissingPropertyDescriptors(LiveDataConfiguration config, List<String> properties)
    {
        Collection<LiveDataPropertyDescriptor> propertyDescriptors = config.getMeta().getPropertyDescriptors();
        Set<String> propertiesWithDescriptor = propertyDescriptors.stream().filter(Objects::nonNull)
            .map(LiveDataPropertyDescriptor::getId).collect(Collectors.toSet());
        List<LiveDataPropertyDescriptor> missingDescriptors =
            properties.stream().filter(property -> !propertiesWithDescriptor.contains(property))
                .map(this::getDefaultPropertyDescriptor).collect(Collectors.toList());
        if (!missingDescriptors.isEmpty()) {
            propertyDescriptors = new ArrayList<>(propertyDescriptors);
            propertyDescriptors.addAll(missingDescriptors);
            config.getMeta().setPropertyDescriptors(propertyDescriptors);
        }
    }

    private LiveDataPropertyDescriptor getDefaultPropertyDescriptor(String property)
    {
        LiveDataPropertyDescriptor propertyDescriptor = new LiveDataPropertyDescriptor();
        propertyDescriptor.setId(property);
        propertyDescriptor.setType("String");
        propertyDescriptor.setVisible(true);
        return propertyDescriptor;
    }








    private LiveDataConfiguration translate(LiveDataConfiguration mergedConfig, LiveDataConfiguration config)
    {
        String translationPrefix =
            (String) mergedConfig.getQuery().getSource().getParameters().get("translationPrefix");
        for (LiveDataPropertyDescriptor property : mergedConfig.getMeta().getPropertyDescriptors()) {
            translateProperty(config, translationPrefix, property);
        }

        for (LiveDataActionDescriptor action : mergedConfig.getMeta().getActions()) {
            translateAction(config, translationPrefix, action);
        }
        return mergedConfig;
    }

    private void translateProperty(LiveDataConfiguration config, String translationPrefix,
        LiveDataPropertyDescriptor property)
    {



        if (property.getName() == null || !propertyHasDefaultName(config, property.getId())) {
            String translationPlain = this.l10n.getTranslationPlain(translationPrefix + property.getId());
            if (translationPlain != null) {
                property.setName(translationPlain);
            }
            if (property.getName() == null) {
                property.setName(property.getId());
            }
        }
        if (property.getDescription() == null) {
            property.setDescription(this.l10n.getTranslationPlain(translationPrefix + property.getId() + ".hint"));
        }
    }

    private void translateAction(LiveDataConfiguration config, String translationPrefix,
        LiveDataActionDescriptor action)
    {



        if (action.getName() == null && !actionHasDefaultName(config, action.getId())) {
            String translationPlain =
                this.l10n.getTranslationPlain(translationPrefix + "_actions." + action.getId());
            if (translationPlain != null) {
                action.setName(translationPlain);
            }
        }
    }








    private boolean propertyHasDefaultName(LiveDataConfiguration config, String propertyId)
    {
        if (config == null || config.getMeta() == null || config.getMeta().getPropertyDescriptors() == null) {
            return false;
        }
        return config.getMeta().getPropertyDescriptors().stream()
            .anyMatch(it -> Objects.equals(it.getId(), propertyId) && it.getName() != null);
    }








    private boolean actionHasDefaultName(LiveDataConfiguration config, String actionId)
    {
        if (config == null || config.getMeta() == null || config.getMeta().getActions() == null) {
            return false;
        }

        return config.getMeta().getActions().stream()
            .anyMatch(it -> Objects.equals(it.getId(), actionId) && it.getName() != null);
    }
}
