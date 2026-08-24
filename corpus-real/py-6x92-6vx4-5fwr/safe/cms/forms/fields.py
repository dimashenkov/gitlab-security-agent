from django import forms
from django.contrib.admin.widgets import RelatedFieldWidgetWrapper
from django.core.validators import EMPTY_VALUES
from django.forms import ChoiceField
from django.utils.translation import gettext_lazy as _

from cms.forms.utils import get_page_choices, get_site_choices
from cms.forms.validators import validate_url
from cms.forms.widgets import PageSelectWidget, PageSmartLinkWidget
from cms.models.pagemodel import Page


class PageSelectFormField(forms.MultiValueField):
    ''







    widget = PageSelectWidget
    default_error_messages = {
        'invalid_site': _('Select a valid site'),
        'invalid_page': _('Select a valid page'),
    }

    def __init__(self, queryset=None, empty_label="---------", cache_choices=False,
                 required=True, widget=None, to_field_name=None, limit_choices_to=None, *args, **kwargs):
        errors = self.default_error_messages.copy()
        if 'error_messages' in kwargs:
            errors.update(kwargs['error_messages'])
        self.limit_choices_to = limit_choices_to
        kwargs['required'] = required
        fields = (
            ChoiceField(choices=get_site_choices, required=False, error_messages={'invalid': errors['invalid_site']}),
            ChoiceField(choices=get_page_choices, required=False, error_messages={'invalid': errors['invalid_page']}),
        )




        if 'blank' in kwargs:
            del kwargs['blank']

        super().__init__(fields, *args, **kwargs)

    def compress(self, data_list):
        if data_list:
            page_id = data_list[1]

            if page_id in EMPTY_VALUES:
                if not self.required:
                    return None
                raise forms.ValidationError(self.error_messages['invalid_page'])
            return Page.objects.get(pk=page_id)
        return None

    def has_changed(self, initial, data):
        is_empty = data and (len(data) >= 2 and data[1] in [None, ''])

        if isinstance(self.widget, RelatedFieldWidgetWrapper):
            self.widget.decompress = self.widget.widget.decompress

        if is_empty and initial is None:



            data = ['' for x in range(0, len(data))]
        return super().has_changed(initial, data)

    def _has_changed(self, initial, data):
        return self.has_changed(initial, data)


class PageSmartLinkField(forms.CharField):
    ''










    widget = PageSmartLinkWidget
    default_validators = [validate_url]

    def __init__(self, max_length=None, min_length=None, placeholder_text=None,
                 ajax_view=None, *args, **kwargs):
        self.placeholder_text = placeholder_text
        widget = self.widget(ajax_view=ajax_view)
        super().__init__(
            max_length=max_length, min_length=min_length, widget=widget, *args, **kwargs
        )

    def widget_attrs(self, widget):
        attrs = super().widget_attrs(widget)
        attrs.update({'placeholder_text': self.placeholder_text})
        return attrs

    def clean(self, value):
        value = self.to_python(value).strip()
        return super().clean(value)
