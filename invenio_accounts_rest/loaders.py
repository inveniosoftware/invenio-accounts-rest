# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2017 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""Default data loader."""

from flask import request
from invenio_rest.errors import FieldError, RESTValidationError
from jsonpatch import JsonPatchException, JsonPointerException, apply_patch
from .errors import PatchJSONFailureRESTError


_fields_without_profile = set([
    'email',
    'active',
    'password',
    'old_password',
])


_fields_with_profile = _fields_without_profile.union(set([
    'full_name',
    'username',
]))


def default_json_loader_without_profile(**kwargs):
    """Default data loader when Invenio Userprofiles is not installed."""
    data = request.get_json(force=True)
    for key in data:
        if key not in _fields_without_profile:
            raise RESTValidationError(errors=[
                FieldError(key, 'Unknown field {}'.format(key))
            ])
    return data


def _fix_profile(data):
    """Move profile properties to their right place."""
    data['profile'] = {}
    if 'full_name' in data:
        data['profile']['full_name'] = data['full_name']
        del data['full_name']
    if 'username' in data:
        data['profile']['username'] = data['username']
        del data['username']
    return data


def default_json_loader_with_profile(**kwargs):
    """Default data loader when Invenio Userprofiles is installed."""
    data = request.get_json(force=True)
    for key in data:
        if key not in _fields_with_profile:
            raise RESTValidationError(errors=[
                FieldError(key, 'Unknown field {}'.format(key))
            ])

    _fix_profile(data)

    return data


def _json_patch_loader_factory(fields, **kwargs):
    """Create JSON PATCH data loaders for user properties modifications."""
    def json_patch_loader(user=None):
        data = request.get_json(force=True)
        if data is None:
            abort(400)
        modified_fields = {
            cmd['path'] for cmd in data
            if 'path' in cmd and 'op' in cmd and cmd['op'] != 'test'
        }
        errors = [
            FieldError(field, 'Unknown field {}.'.format(field))
            for field in _fields_with_profile.intersection(modified_fields)
        ]
        if len(errors) > 0:
            raise RESTValidationError(errors=errors)

        original = {
            'email': user.email, 'active': user.active, 'password': None
        }
        # if invenio-userprofiles is loaded add profile's fields
        if 'full_name' in fields:
            original.update({
                'full_name': user.profile.full_name,
                'username': user.profile.username
            })
        try:
            patched = apply_patch(original, data)
        except (JsonPatchException, JsonPointerException):
            raise PatchJSONFailureRESTError()
        if patched['password'] is None:
            del patched['password']

        if 'full_name' in fields:
            _fix_profile(patched)
        return patched
    return json_patch_loader


default_json_patch_loader_with_profile = _json_patch_loader_factory(
    _fields_with_profile
)
"""JSON PATCH data loader for modifiying user properties including profiles."""


default_json_patch_loader_without_profile = _json_patch_loader_factory(
    _fields_without_profile
)
"""JSON PATCH data loader for modifiying user properties without profiles."""
