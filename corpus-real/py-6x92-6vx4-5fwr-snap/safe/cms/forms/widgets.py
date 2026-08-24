from django.contrib.auth import get_permission_codename
from django.contrib.sites.models import Site
from django.forms.widgets import MultiWidget, Select, TextInput
from django.urls import NoReverseMatch, reverse_lazy
from django.utils.encoding import force_str
from django.utils.html import escape, escapejs
from django.utils.safestring import mark_safe

from cms.forms.utils import get_page_choices, get_site_choices
from cms.models import Page, PageUser
from cms.utils.urlutils import admin_reverse, static_with_version


class PageSelectWidget(MultiWidget):
    ''


    template_name = 'cms/widgets/pageselectwidget.html'

    class Media:
        js = (
            static_with_version('cms/js/dist/bundle.forms.pageselectwidget.min.js'),
        )

    def __init__(self, site_choices=None, page_choices=None, attrs=None):
        if attrs is not None:
            self.attrs = attrs.copy()
        else:
            self.attrs = {}
        self.choices = []
        super().__init__((Select, Select, Select), attrs)

    def decompress(self, value):
        ''



        if value:
            page = Page.objects.get(pk=value)
            return [page.site_id, page.pk, page.pk]
        site = Site.objects.get_current()
        return [site.pk, None, None]

    def _has_changed(self, initial, data):



        ''





        if data is None or (len(data) >= 2 and data[1] in [None, '']):
            data_value = ''
        else:
            data_value = data
        if initial is None:
            initial_value = ''
        else:
            initial_value = initial
        if force_str(initial_value) != force_str(data_value):
            return True
        return False

    def _build_widgets(self):
        site_choices = get_site_choices()
        page_choices = get_page_choices()
        self.site_choices = site_choices
        self.choices = page_choices
        self.widgets = (
            Select(choices=site_choices),
            Select(choices=[('', '----')]),
            Select(choices=self.choices, attrs={'style': "display:none;"}),
        )

    def get_context(self, name, value, attrs):
        self._build_widgets()
        context = super().get_context(name, value, attrs)
        context['widget']['script_data'] = {"name": name}
        return context

    def format_output(self, rendered_widgets):
        return ' '.join(rendered_widgets)


class PageSmartLinkWidget(TextInput):
    ''
    template_name = 'cms/widgets/pagesmartlinkwidget.html'

    class Media:
        css = {
            'all': (
                'cms/js/select2/select2.css',
                'cms/js/select2/select2-bootstrap.css',
            )
        }
        js = (
            static_with_version('cms/js/dist/bundle.forms.pagesmartlinkwidget.min.js'),
        )

    def __init__(self, attrs=None, ajax_view=None):
        super().__init__(attrs)
        self.ajax_url = self.get_ajax_url(ajax_view=ajax_view)

    def get_ajax_url(self, ajax_view):
        try:
            return reverse_lazy(ajax_view)
        except NoReverseMatch:
            raise Exception(
                'You should provide an ajax_view argument that can be reversed to the PageSmartLinkWidget'
            )

    def _build_script_data(self, name, value, attrs):
        return {
            "id": attrs.get('id', ''),
            "text": str(attrs.get('placeholder_text', '')),
            "lang": self.language,
            "url": force_str(self.ajax_url),
        }

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        context['widget']['script_data'] = self._build_script_data(name, value, context['widget']['attrs'])
        return context


class UserSelectAdminWidget(Select):
    ''






    def render(self, name, value, attrs=None, choices=(), renderer=None):
        output = [super().render(name, value, attrs, renderer=renderer)]
        if hasattr(self, 'user') and (
            self.user.is_superuser or self.user.has_perm(
                PageUser._meta.app_label + '.' + get_permission_codename('add', PageUser._meta))
        ):

            add_url = admin_reverse('cms_pageuser_add')
            output.append(
                '<a href="%s" class="add-another" id="add_id_%s" onclick="return showAddAnotherPopup(this);"> ' %
                (add_url, name)
            )
        return mark_safe(''.join(output))


class AppHookSelect(Select):

    ''




    class Media:
        js = (
            static_with_version('cms/js/dist/bundle.forms.apphookselect.min.js'),
        )

    def __init__(self, attrs=None, choices=(), app_namespaces={}):
        self.app_namespaces = app_namespaces
        super().__init__(attrs, choices)

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None):
        option = super().create_option(name, value, label, selected, index, subindex, attrs)
        if value in self.app_namespaces:
            option['attrs']['data-namespace'] = escape(self.app_namespaces[value])
        return option

    def _build_option(self, selected_choices, option_value, option_label):
        if option_value is None:
            option_value = ''
        option_value = force_str(option_value)
        if option_value in selected_choices:
            selected_html = mark_safe(' selected="selected"')
            if not self.allow_multiple_selected:

                selected_choices.remove(option_value)
        else:
            selected_html = ''

        if option_value in self.app_namespaces:
            data_html = mark_safe(' data-namespace="%s"' % escape(self.app_namespaces[option_value]))
        else:
            data_html = ''
        return option_value, selected_html, data_html, force_str(option_label)

    def render_option(self, selected_choices, option_value, option_label):
        option_data = self._build_option(selected_choices, option_value, option_label)
        return '<option value="%s"%s%s>%s</option>' % option_data


class ApplicationConfigSelect(Select):
    ''









    template_name = 'cms/widgets/applicationconfigselect.html'

    class Media:
        js = (
            static_with_version('cms/js/dist/bundle.forms.apphookselect.min.js'),
        )

    def __init__(self, attrs=None, choices=(), app_configs={}):
        self.app_configs = app_configs
        super().__init__(attrs, choices)

    def _build_script_data(self, name, value, attrs):
        configs = {
            str(application): [[str(config.pk), str(config)] for config in cms_app.get_configs()]
            for application, cms_app in self.app_configs.items()
        }
        urls = {
            str(application): cms_app.get_config_add_url()
            for application, cms_app in self.app_configs.items()
        }

        return {
            "apphooks_configuration": configs,
            "apphooks_configuration_url": urls,
            "apphooks_configuration_value": str(value) if value is not None else "",

        }

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        context['widget']['script_data'] = self._build_script_data(name, value, context['widget']['attrs'])
        return context
