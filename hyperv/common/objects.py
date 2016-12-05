# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""This module contains data models used across the project."""

# pylint: disable=protected-access

import copy

from oslo_log import log as logging
import six

from hyperv.neutron import exception

LOG = logging.getLogger(__name__)


class _FieldDescriptor(object):

    """Descriptor for all the available fields for a model.

    Fields are exposed as descriptors in order to control access to the
    underlying raw data.
    """

    def __init__(self, field):
        self._field = field
        self._attribute = field.name

    @property
    def field(self):
        """Expose the received field object."""
        return self._field

    def __get__(self, instance, instance_type=None):
        if instance is not None:
            return instance._data.get(self._attribute)
        return self._field

    def __set__(self, instance, value):
        instance._changes[self._attribute] = value


class Field(object):

    """Meta information regarding the data components.

    :param name:       The name of the current piece of information.
    :param default:    Default value for the current field. (default: `None`)
    :param allow_none: Whether the current piece of information is required
                       for the container object or can be missing.
                       (default: `True`)
    """

    def __init__(self, name, default=None, allow_none=True):
        self._name = name
        self._default = default
        self._required = not allow_none

    @property
    def name(self):
        """The name of the current field."""
        return self._name

    @property
    def default(self):
        """Default value for the current field."""
        return self._default

    @property
    def required(self):
        """Whether the current field is required or can be missing."""
        return self._required

    def add_to_class(self, model_class):
        """Replace the `Field` attribute with a named `_FieldDescriptor`.

        .. note::
            This method is called  during construction of the `Model`.
        """
        model_class._meta.add_field(self)
        setattr(model_class, self._name, _FieldDescriptor(self))


class _ModelOptions(object):

    """Container for all the model options.

    .. note::
        The current object will be created by the model metaclass.
    """

    def __init__(self, cls):
        self._model_class = cls
        self._name = cls.__name__

        self._fields = {}
        self._defaults = {}
        self._default_callables = {}

    @property
    def fields(self):
        """All the available fields for the current model."""
        return self._fields

    def add_field(self, name, field):
        """Add the received field to the model."""
        self.remove_field(name)
        self._fields[name] = field

        if field.default is not None:
            if six.callable(field.default):
                self._default_callables[name] = field.default
            else:
                self._defaults[name] = field.default

    def remove_field(self, field_name):
        """Remove the field with the received field name from model."""
        field = self._fields.pop(field_name, None)
        if field is not None and field.default is not None:
            if six.callable(field.default):
                self._default_callables.pop(field_name, None)
            else:
                self._defaults.pop(field_name, None)

    def get_defaults(self):
        """Get a dictionary that contains all the available defaults."""
        defaults = self._defaults.copy()
        for field_name, default in self._default_callables.items():
            defaults[field_name] = default()
        return defaults


class _BaseModel(type):

    """Metaclass used for properly setting up a new model."""

    def __new__(mcs, name, bases, attrs):
        # The inherit is made by deep copying the underlying field into
        # the attributes of the new model.
        for base in bases:
            for key, attribute in base.__dict__.items():
                if key not in attrs and isinstance(attribute,
                                                   _FieldDescriptor):
                    attrs[key] = copy.deepcopy(attribute.field)

        # Initialize the new class and set the magic attributes
        cls = super(_BaseModel, mcs).__new__(mcs, name, bases, attrs)

        # Create the _ModelOptions object and inject it in the new class
        setattr(cls, "_meta", _ModelOptions(cls))

        # Get all the available fields for the current model.
        for name, field in list(cls.__dict__.items()):
            if isinstance(field, Field) and not name.startswith("_"):
                field.add_to_class(name, cls)

        # Create string representation for the current model before finalizing
        setattr(cls, '__str__', lambda self: '%s' % cls.__name__)
        return cls


@six.add_metaclass(_BaseModel)
class Model(object):

    """Container for meta information regarding the data structure."""

    def __init__(self, **fields):
        self._data = self._meta.get_defaults()
        self._changes = {}

        for field_name in self._meta.fields:
            value = fields.pop(field_name, None)
            if field_name not in self._data or value:
                setattr(self, field_name, value)

        if fields:
            LOG.debug("Unrecognized fields: %r", fields)

    def validate(self):
        """Check if the current model was properly created."""
        for field_name, field in self._meta.fields.items():
            if field.required and self._data.get(field.name) is None:
                raise exception.DataProcessingError(
                    "The required field %r is missing." % field_name)

    def update(self, fields):
        """Update the value of one or more fields."""
        self._data.update(fields)

    def commit(self):
        """Apply all the changes on the current model."""
        self._data.update(self._changes)
        self._changes.clear()

    def dump(self):
        """Create a dictionary with the content of the current model."""
        content = self._data.copy()
        for key, value in content.items():
            if isinstance(value, Model):
                content[key] = value.dump()
        return content
