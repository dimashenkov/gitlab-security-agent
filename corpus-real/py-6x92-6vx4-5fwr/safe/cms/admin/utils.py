from __future__ import annotations

import re
import typing
from copy import copy
from urllib.parse import parse_qsl

from django import forms
from django.contrib.admin import ModelAdmin
from django.contrib.admin.checks import ModelAdminChecks
from django.contrib.admin.utils import label_for_field
from django.contrib.admin.views.main import ChangeList
from django.contrib.auth import get_permission_codename
from django.contrib.sites.models import Site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models
from django.db.models import DateField, OuterRef, Subquery, functions
from django.db.models.functions import Cast
from django.forms import modelform_factory
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.urls import NoReverseMatch
from django.utils.html import format_html_join
from django.utils.http import urlencode
from django.utils.safestring import mark_safe
from django.utils.translation import get_language, gettext_lazy as _

from cms.models.managers import ContentAdminManager
from cms.toolbar.utils import get_object_preview_url
from cms.utils import get_language_from_request
from cms.utils.i18n import get_language_dict, get_language_list, get_language_tuple
from cms.utils.urlutils import admin_reverse, static_with_version


class ChangeListActionsMixin(metaclass=forms.MediaDefiningClass):
    ''











    class Media:
        js = (
            "admin/js/jquery.init.js",
            "cms/js/admin/actions.js",
        )
        css = {"all": (static_with_version("cms/css/cms.admin.css"),)}

    EMPTY_ACTION = mark_safe('<span class="cms-empty-action"></span>')

    def get_actions_list(
        self,
    ) -> list[typing.Callable[[models.Model, HttpRequest], str]]:
        ''











        return []

    def get_admin_list_actions(self, request: HttpRequest) -> typing.Callable[[models.Model], str]:
        ''









        def list_actions(obj: models.Model) -> str:
            ''
            return format_html_join(
                "",
                "{}",
                ((action(obj, request),) for action in self.get_actions_list()),
            )

        list_actions.short_description = _("Actions")
        return list_actions

    def admin_list_actions(self, obj: models.Model) -> None:
        raise ValueError(
            'ModelAdmin.display_list contains "admin_list_actions" as a placeholder for list action icons. '
            'ChangeListActionsMixin is not loaded, however. If you implement "get_list_display" make '
            "sure it calls super().get_list_display."
        )  # pragma: no cover

    def get_list_display(self, request: HttpRequest) -> tuple[str | typing.Callable[[models.Model], str], ...]:
        list_display = super().get_list_display(request)
        return tuple(
            self.get_admin_list_actions(request) if item == "admin_list_actions" else item for item in list_display
        )

    @staticmethod
    def admin_action_button(
        url: str,
        icon: str,
        title: str,
        burger_menu: bool = False,
        action: str = "get",
        disabled: bool = False,
        keepsideframe: bool = True,
        name: str = "",
    ) -> str:
        ''
























        return render_to_string(
            "admin/cms/icons/base.html",
            {
                "url": url or "",
                "icon": icon,
                "method": action,
                "disabled": disabled,
                "keepsideframe": keepsideframe,
                "title": title,
                "burger_menu": burger_menu,
                "name": name,
            },
        )



CONTENT_PREFIX = "content__"


class GrouperChangeListBase(ChangeList):
    ''

    current_language: str = None
    available_languages: tuple[tuple[str, str], ...] = ()
    _extra_grouping_fields = []

    def get_filters_params(self, params: dict | None = None):
        lookup_params = super().get_filters_params(params)
        for field in self._extra_grouping_fields:
            if field in lookup_params:
                del lookup_params[field]
        return lookup_params


class GrouperModelAdminChecks(ModelAdminChecks):
    def _check_prepopulated_fields_value_item(self, obj, field_name, label):
        ''


        if field_name.startswith(CONTENT_PREFIX) and obj.content_model:
            field_name = field_name[len(CONTENT_PREFIX) :]
            obj = copy(obj)
            obj.model = obj.content_model
        return super()._check_prepopulated_fields_value_item(obj, field_name, label)

    def _check_prepopulated_fields_key(self, obj, field_name, label):
        ''



        if field_name.startswith(CONTENT_PREFIX) and obj.content_model:
            field_name = field_name[len(CONTENT_PREFIX) :]
            obj = copy(obj)
            obj.model = obj.content_model
        return super()._check_prepopulated_fields_key(obj, field_name, label)


class GrouperModelAdmin(ChangeListActionsMixin, ModelAdmin):
    ''































    grouper_field_name: str | None = None








    extra_grouping_fields: tuple[str, ...] = ()



    content_model: models.Model | None = None




    content_related_field: str | None = None

    change_list_template = "admin/cms/grouper/change_list.html"
    change_form_template = "admin/cms/grouper/change_form.html"
    checks_class = GrouperModelAdminChecks

    class Media:
        js = (
            "admin/js/jquery.init.js",
            "cms/js/admin/language-selector.js",
        )

    EMPTY_CONTENT_VALUE = _("Empty content")
    LC_SORTED_FIELDS = (models.CharField,)
    CONTENT_OBJ_PK_ANNOTATION = "_content_obj_pk"

    _content_content_type = None

    def __init__(self, model, admin_site):
        self._content_subquery_fields = []

        super().__init__(model, admin_site)


        if self.content_model is None:

            from django.apps import apps

            self.content_model = apps.get_model(f"{self.opts.app_label}.{self.model.__name__}Content")


        if not hasattr(self.content_model, "admin_manager"):
            self.content_model.add_to_class("admin_manager", ContentAdminManager())


        if not self.content_related_field:
            for related_object in model._meta.related_objects:
                if related_object.related_model is self.content_model:
                    self.content_related_field = related_object.get_accessor_name()
                    break
            else:
                raise ImproperlyConfigured(f"Related field for grouper model {model.__name__} not found")


        if not self.grouper_field_name:
            self.grouper_field_name = re.sub("(?!^)([A-Z]+)", r"_\1", self.model.__name__).lower()

        if not issubclass(self.form, _GrouperAdminFormMixin):
            self.form = type(
                "AutoGeneratedGrouperAdminForm",
                (GrouperAdminFormMixin(self.content_model), self.form),
                dict(),
            )


        for content_field in self.form._content_fields:
            if (
                not hasattr(self, CONTENT_PREFIX + content_field)
                and content_field != self.grouper_field_name
                and content_field not in self.extra_grouping_fields
            ):
                if CONTENT_PREFIX + content_field in self.list_display:

                    self._content_subquery_fields.append(content_field)
                setattr(
                    self,
                    CONTENT_PREFIX + content_field,
                    self._getter_factory(content_field),
                )

    def _getter_factory(self, field: str) -> typing.Callable[[models.Model], typing.Any]:
        ''


        def getter(obj):
            return self.get_content_field(obj, field)

        getter.short_description = label_for_field(field, self.content_model)
        if field in self._content_subquery_fields:
            getter.admin_order_field = CONTENT_PREFIX + field
            if isinstance(self.content_model._meta.get_field(field), self.LC_SORTED_FIELDS):
                getter.admin_order_field += "__lc"
        getter.boolean = isinstance(self.form.base_fields[CONTENT_PREFIX + field], forms.BooleanField)
        if not getter.boolean:

            for display in getattr(self, "list_display", ()):
                if display == CONTENT_PREFIX + field:
                    getter.empty_value_display = self.EMPTY_CONTENT_VALUE
                if display.startswith(CONTENT_PREFIX):
                    break
        return getter

    def get_content_field(
        self,
        obj: models.Model,
        field_name: str,
        request: HttpRequest | None = None,
    ) -> typing.Any:
        ''

        if hasattr(obj, CONTENT_PREFIX + field_name):

            return getattr(obj, CONTENT_PREFIX + field_name)
        if request:
            self.get_grouping_from_request(request)
        content_obj = self.get_content_obj(obj)
        return getattr(content_obj, field_name) if content_obj else None

    def _get_annotation(self):
        contents = self.content_model.admin_manager.latest_content(
            **{self.grouper_field_name: OuterRef("pk"), **self.current_content_filters}
        )
        annotation = {
            self.CONTENT_OBJ_PK_ANNOTATION: Subquery(contents.values("pk")[:1]),
        }
        for field_name in self._content_subquery_fields:
            annotation[CONTENT_PREFIX + field_name] = Subquery(contents.values(field_name)[:1])
            field = self.content_model._meta.get_field(field_name)
            if isinstance(field, DateField):

                annotation[CONTENT_PREFIX + field_name] = Cast(
                    annotation[CONTENT_PREFIX + field_name], field.__class__()
                )
            if isinstance(field, self.LC_SORTED_FIELDS):

                annotation[CONTENT_PREFIX + field_name + "__lc"] = functions.Lower(
                    Subquery(contents.values(field_name)[:1])
                )
        return annotation

    def can_change_content(self, request, content_obj):
        opts = self.content_model._meta
        perm = f"{opts.app_label}.{get_permission_codename('change' if content_obj else 'add', opts)}"
        if not request.user.has_perm(perm, content_obj):
            return False
        return getattr(content_obj, "is_editable", lambda *_: True)(request)

    def get_queryset(self, request: HttpRequest) -> models.QuerySet:
        ''

        qs = super().get_queryset(request).annotate(**self._get_annotation())
        prefetch = models.Prefetch(
            self.content_related_field,
            queryset=self.content_model.admin_manager.latest_content(),
            to_attr="_admin_prefetch_cache",
        )
        return qs.prefetch_related(prefetch)

    def get_language_from_request(self, request: HttpRequest) -> str:
        ''
        return get_language_from_request(request)

    def get_grouping_from_request(self, request: HttpRequest) -> None:
        ''
        for field in self.extra_grouping_fields:
            if hasattr(self, f"get_{field}_from_request"):
                value = getattr(self, f"get_{field}_from_request")(request)
            else:
                raise ImproperlyConfigured(
                    f"{self.__class__.__name__} lacks method 'get_{field}_from_request(request)' to work with "
                    f"extra_grouping_fields={self.extra_grouping_fields}"
                )
            if value != getattr(self, field, None):
                setattr(self, field, value)

    @property
    def current_content_filters(self) -> dict[str, typing.Any]:
        ''
        return {
            field: getattr(self, field, self.get_extra_grouping_field(field)) for field in self.extra_grouping_fields
        }

    def get_language(self) -> str:
        ''

        return getattr(self, "language", get_language())

    def get_language_tuple(self) -> tuple[tuple[str, str], ...]:
        ''
        return get_language_tuple()

    def get_extra_grouping_field(self, field):
        ''

        if callable(getattr(self, f"get_{field}", None)):
            return getattr(self, f"get_{field}")()
        raise ValueError("Cannot get extra grouping field")

    def get_changelist(self, request: HttpRequest, **kwargs) -> type:
        ''
        return type(
            GrouperChangeListBase.__name__,
            (GrouperChangeListBase,),
            dict(_extra_grouping_fields=self.extra_grouping_fields),
        )

    def get_changelist_instance(self, request: HttpRequest) -> GrouperChangeListBase:
        ''
        self.get_grouping_from_request(request)
        cl = super().get_changelist_instance(request)
        cl.current_language = self.get_language()
        if "language" in self.extra_grouping_fields:
            cl.available_languages = self.get_language_tuple()
        return cl

    def changeform_view(
        self,
        request: HttpRequest,
        object_id: str | None = None,
        form_url: str = "",
        extra_context: dict = None,
    ) -> HttpResponse:
        ''
        self.get_grouping_from_request(request)
        return super().changeform_view(
            request,
            object_id,
            form_url,
            {
                **(extra_context or {}),
                **self.get_extra_context(request, object_id=object_id),
            },
        )

    def delete_view(
        self,
        request: HttpRequest,
        object_id: str,
        extra_context: dict | None = None,
    ) -> HttpResponse:
        ''
        self.get_grouping_from_request(request)
        return super().delete_view(request, object_id, extra_context)

    def history_view(
        self,
        request: HttpRequest,
        object_id: str,
        extra_context: dict | None = None,
    ) -> HttpResponse:
        ''
        self.get_grouping_from_request(request)
        return super().history_view(request, object_id, extra_context)

    def get_preserved_filters(self, request: HttpRequest) -> str:
        ''



        preserved_filters = dict(parse_qsl(super().get_preserved_filters(request)))

        grouping_filters = {}
        for field in self.extra_grouping_fields:
            value = getattr(self, field, None)
            if "field" not in preserved_filters:
                grouping_filters[field] = value
        preserved_filters.update(grouping_filters)
        if "_changelist_filters" not in preserved_filters:
            preserved_filters["_changelist_filters"] = urlencode(grouping_filters)
        return urlencode(preserved_filters)

    def get_extra_context(self, request: HttpRequest, object_id: str | None = None) -> dict[str, typing.Any]:
        ''
        if object_id:

            obj = get_object_or_404(self.model, pk=object_id)
            content_instance = self.get_content_obj(obj)
            title = _("%(object_name)s Properties") % dict(object_name=obj._meta.verbose_name.capitalize())
        else:
            obj = None
            content_instance = None
            title = _("Add new %(object_name)s") % dict(object_name=self.model._meta.verbose_name)

        if content_instance:
            subtitle = str(content_instance)
        else:
            subtitle = _("Add content")

        extra_context = {
            "changed_message": _(
                'Content for the current language has been changed. Click "Cancel" to '
                'return to the form and save changes. Click "OK" to discard changes.'
            ),
            "title": title,
            "content_instance": content_instance,
            "subtitle": subtitle,
        }

        ''
        if "language" in self.extra_grouping_fields:
            language = self.language
            if obj:
                filled_languages = self.get_content_objects(obj).values_list("language", flat=True).distinct()
            else:
                filled_languages = []

            extra_context["language_tabs"] = self.get_language_tuple()
            extra_context["language"] = language
            extra_context["filled_languages"] = filled_languages
            extra_context["can_change_content_obj"] = self.can_change_content(request, content_instance)
            if content_instance is None:
                subtitle = _("Add %(language)s content") % dict(language=get_language_dict().get(self.language))
                extra_context["subtitle"] = subtitle


        return extra_context

    def get_form(self, request: HttpRequest, obj: models.Model | None = None, **kwargs) -> type:
        ''
        form_class = super().get_form(request, obj, **kwargs)
        form_class._admin = self
        form_class._request = request

        for field in self.extra_grouping_fields:
            form_class.base_fields[CONTENT_PREFIX + field].widget = forms.HiddenInput()

        if (getattr(form_class._meta, "fields", None) or "__all__") != "__all__":
            for field in self.extra_grouping_fields:
                if CONTENT_PREFIX + field not in form_class._meta.fields:
                    raise ImproperlyConfigured(
                        f"{self.__class__.__name__} needs to include all "
                        f"extra_grouping_fields={self.extra_grouping_fields} in its admin. {field} is missing."
                    )
        return form_class





    def _get_view_action(self, obj, request: HttpRequest) -> str:
        if self.get_content_obj(obj):
            view_url = self.view_on_site(self.get_content_obj(obj))
            return self.admin_action_button(
                url=view_url,
                icon="view",
                title=_("Preview"),
                disabled=not view_url,
                keepsideframe=False,
                name="view",
            )
        return self.EMPTY_ACTION

    def _has_content(self, obj: models.Model) -> bool:
        if self._is_content_obj(obj):
            return True  # pragma: no cover
        if hasattr(obj, self.CONTENT_OBJ_PK_ANNOTATION):
            return getattr(obj, self.CONTENT_OBJ_PK_ANNOTATION) is not None
        return self.get_content_obj(obj) is not None  # pragma: no cover

    def _get_settings_action(self, obj: models.Model, request: HttpRequest) -> str:
        edit_url = admin_reverse(f"{obj._meta.app_label}_{obj._meta.model_name}_change", args=(obj.pk,))
        edit_url += f"?{urlencode(self.current_content_filters)}"
        has_content = self._has_content(obj)
        return self.admin_action_button(
            url=edit_url,
            icon="settings" if has_content else "plus",
            title=_("Settings") if has_content else _("Add content"),
            disabled=not edit_url,
            name="settings",
        )

    def get_actions_list(self) -> list:
        return [self._get_view_action, self._get_settings_action]

    def endpoint_url(self, admin: str, obj: models.Model) -> str:
        if self._is_content_obj(obj):
            cls = obj.__class__
            pk = obj.pk
        else:
            content = self.get_content_obj(obj)
            cls = content.__class__
            pk = content.pk

        if self._content_content_type is None:
            from django.contrib.contenttypes.models import ContentType

            self._content_content_type = ContentType.objects.get_for_model(cls).pk
        try:
            return admin_reverse(admin, args=[self._content_content_type, pk])
        except NoReverseMatch:
            return ""

    def _is_content_obj(self, obj: models.Model) -> bool:
        return isinstance(obj, self.content_model)

    def _get_content_queryset(self, obj: models.Model) -> models.QuerySet:
        return getattr(obj, self.content_related_field)(manager="admin_manager").latest_content()

    def get_content_obj(self, obj: models.Model | None) -> models.Model | None:
        if obj is None or self._is_content_obj(obj):
            return obj

        if not hasattr(obj, "_grouper_admin_content_obj_cache"):

            if hasattr(obj, "_admin_prefetch_cache"):
                for content_obj in obj._admin_prefetch_cache:
                    if all(
                        getattr(content_obj, key, None) == value for key, value in self.current_content_filters.items()
                    ):
                        obj._grouper_admin_content_obj_cache = content_obj
                        return content_obj
                obj._grouper_admin_content_obj_cache = None
                return None
            obj._grouper_admin_content_obj_cache = (
                self._get_content_queryset(obj).filter(**self.current_content_filters).first()
            )
        return obj._grouper_admin_content_obj_cache

    def get_content_objects(self, obj: models.Model | None) -> models.QuerySet:
        if obj is None:
            return None
        if self._is_content_obj(obj):

            return self.get_content_objects(self.get_grouper_obj(obj))
        return self._get_content_queryset(obj)

    def clear_content_cache(self) -> None:

        pass

    def get_grouper_obj(self, obj: models.Model) -> models.Model:
        ''


        if self._is_content_obj(obj):
            field_name = obj.__class__.__name__[-7:].lower()
            return getattr(obj, field_name)
        return obj

    def view_on_site(self, obj: models.Model) -> str | None:

        content_obj = self.get_content_obj(obj)
        if content_obj:

            return get_object_preview_url(content_obj, language=getattr(content_obj, "language", None))
        return None

    def get_readonly_fields(self, request: HttpRequest, obj: models.Model | None = None):
        ''


        fields = super().get_readonly_fields(request, obj)
        content_obj = self.get_content_obj(obj)
        if not self.can_change_content(request, content_obj):

            fields = [
                *fields,
                *(
                    CONTENT_PREFIX + field
                    for field in self.form._content_fields
                    if field != self.grouper_field_name and field not in self.extra_grouping_fields
                )
            ]
        return fields

    def get_prepopulated_fields(self, request: HttpRequest, obj: models.Model | None = None) -> dict:
        ''






        prepopulated_fields = super().get_prepopulated_fields(request, obj)
        if not prepopulated_fields:
            return prepopulated_fields
        readonly = set(self.get_readonly_fields(request, obj))
        return {key: value for key, value in prepopulated_fields.items() if key not in readonly}

    def save_model(self, request: HttpRequest, obj: models.Model, form: forms.Form, change: bool) -> None:
        ''
        super().save_model(request, obj or form.instance, form, change)
        content_dict = {
            field: form.cleaned_data[CONTENT_PREFIX + field]
            for field in form._content_fields
            if CONTENT_PREFIX + field in form.cleaned_data
        }
        if form._content_instance is None or form._content_instance.pk is None:
            content_dict[self.grouper_field_name] = form.instance
            if hasattr(form._content_model.objects, "with_user"):

                form._content_model.objects.with_user(request.user).create(**content_dict)
            else:  # pragma: no cover

                form._content_model.objects.create(**content_dict)
        elif self.can_change_content(request, form._content_instance):

            for key, value in content_dict.items():
                setattr(form._content_instance, key, value)

            setattr(form._content_instance, self.grouper_field_name, obj)
            form._content_instance.save()

    def get_search_fields(self, request):
        ''
        content_search_fields = []
        grouper_search_fields = []
        for field_name in self.search_fields:
            if field_name.startswith(CONTENT_PREFIX):
                content_search_fields.append(field_name[len(CONTENT_PREFIX) :])
            else:
                grouper_search_fields.append(field_name)

        if getattr(request, "_content_fields", False):
            return content_search_fields

        return grouper_search_fields

    def get_search_results(self, request, queryset, search_term):
        grouper_search_result, may_have_duplicate_grouper = super().get_search_results(request, queryset, search_term)

        search_result_from_content, may_have_duplicate_content = self._get_content_search_result(
            request, queryset, search_term
        )

        return grouper_search_result | search_result_from_content, (
            may_have_duplicate_grouper & may_have_duplicate_content
        )

    def _get_content_search_result(self, request, queryset, search_term):
        ''
        try:


            request._content_fields = True
            content_queryset = self.content_model.admin_manager.all()
            if self.get_search_fields(request):
                content_search_result, __ = super().get_search_results(request, content_queryset, search_term)
            else:
                content_search_result = self.content_model.admin_manager.none()
            search_result_from_content = queryset.filter(
                id__in=content_search_result.values_list(f"{self.grouper_field_name}_id", flat=True)
            )
        finally:
            request._content_fields = False
        return search_result_from_content, False


class _GrouperAdminFormMixin:
    _content_fields: list = []

    def __init__(self, *args, **kwargs):
        if not hasattr(self, "_admin"):
            raise ValueError(
                "GrouperModelFormMixin forms can only be instantiated if the class attribute '_admin' "
                "has been set and points to the instantiating admin instance."
            )

        if "instance" in kwargs and kwargs["instance"]:

            instance = kwargs["instance"]
            self._content_instance = self._admin.get_content_obj(instance)
            if self._content_instance:
                kwargs["initial"] = {
                    **{
                        CONTENT_PREFIX + field: getattr(self._content_instance, field)
                        for field in self._content_fields
                        if CONTENT_PREFIX + field in self.base_fields
                    },
                    **kwargs.get("initial", {}),
                }
        else:
            self._content_instance = None


        kwargs["initial"] = {
            **{CONTENT_PREFIX + key: value for key, value in self._admin.current_content_filters.items()},
            **kwargs.get("initial", {}),
        }


        super().__init__(*args, **kwargs)


        self.fields[CONTENT_PREFIX + self._admin.grouper_field_name].widget = forms.HiddenInput()

        self.fields[CONTENT_PREFIX + self._admin.grouper_field_name].required = False
        self.update_labels(self._content_fields)

    def update_labels(self, fields: list[str]) -> None:
        ''
        if "language" in self._admin.extra_grouping_fields:
            language_dict = get_language_dict()
            language_postfix = f" ({language_dict[self._admin.language]})"
            for field in fields:
                if CONTENT_PREFIX + field in self.fields:

                    self.fields[CONTENT_PREFIX + field].label += language_postfix
                else:

                    if self._meta.labels is None:
                        self._meta.labels = {}
                    self._meta.labels.setdefault(
                        CONTENT_PREFIX + field,
                        label_for_field(field, self._admin.content_model) + language_postfix,
                    )

    def clean(self) -> dict:
        if (
            f"{CONTENT_PREFIX}language" in self.cleaned_data
            and self.cleaned_data[f"{CONTENT_PREFIX}language"] not in get_language_list()
        ):
            raise ValidationError(
                _("Invalid language %(value)s. This form cannot be processed. Try changing languages."),
                params=dict(value=self.cleaned_data.get("language", _("<unspecified>"))),
                code="invalid-language",
            )
        return super().clean()


class GrouperAdminFormMixin:
    ''

















    def __new__(cls, content_model: models.base.ModelBase) -> type:
        model_form = modelform_factory(content_model, fields="__all__")
        base_fields = {CONTENT_PREFIX + key: value for key, value in model_form.base_fields.items()}
        return forms.forms.DeclarativeFieldsMetaclass(
            GrouperAdminFormMixin.__name__,
            (_GrouperAdminFormMixin,),
            {
                **base_fields,
                "_content_model": model_form._meta.model,
                "_content_fields": model_form.base_fields.keys(),
            },
        )
