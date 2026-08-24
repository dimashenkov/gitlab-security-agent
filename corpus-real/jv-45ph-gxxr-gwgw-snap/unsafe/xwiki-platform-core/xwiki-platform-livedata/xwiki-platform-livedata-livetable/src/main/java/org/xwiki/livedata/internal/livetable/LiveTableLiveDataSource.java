


















package org.xwiki.livedata.internal.livetable;

import javax.inject.Inject;
import javax.inject.Named;

import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.livedata.LiveDataEntryStore;
import org.xwiki.livedata.LiveDataPropertyDescriptorStore;
import org.xwiki.livedata.LiveDataSource;
import org.xwiki.livedata.WithParameters;







@Component
@Named("liveTable")
@InstantiationStrategy(ComponentInstantiationStrategy.PER_LOOKUP)
public class LiveTableLiveDataSource extends WithParameters implements LiveDataSource
{
    @Inject
    @Named("liveTable")
    private LiveDataEntryStore entryStore;

    @Inject
    @Named("liveTable")
    private LiveDataPropertyDescriptorStore propertyStore;

    @Override
    public LiveDataEntryStore getEntries()
    {
        if (this.entryStore instanceof WithParameters) {
            ((WithParameters) this.entryStore).getParameters().putAll(this.getParameters());
        }
        return this.entryStore;
    }

    @Override
    public LiveDataPropertyDescriptorStore getProperties()
    {
        if (this.propertyStore instanceof WithParameters) {
            ((WithParameters) this.propertyStore).getParameters().putAll(this.getParameters());
        }
        return this.propertyStore;
    }
}
