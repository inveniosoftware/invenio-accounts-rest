# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
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

"""Invenio modules that adds accounts REST API."""

from __future__ import absolute_import, print_function

import json

from flask import Blueprint, request
from invenio_accounts.models import User
from invenio_oauth2server import require_api_auth
from invenio_rest import ContentNegotiatedMethodView
from sqlalchemy import String, cast


def accounts_serializer(*args, **kwargs):
    """Basic serializer for invenio_accounts.models.User data."""
    return json.dumps([{'id': u.id, 'email': u.email} for u in args])


def create_blueprint():
    """Create invenio-accounts REST blueprint."""
    blueprint = Blueprint(
        'invenio_accounts_rest',
        __name__,
    )

    accounts_resource = AccountsResource.as_view(
        'accounts_resource',
        serializers={'application/json': accounts_serializer},
        default_media_type='application/json'
    )

    blueprint.add_url_rule(
        '/users/',
        view_func=accounts_resource,
        methods=['GET'],
    )

    return blueprint


class AccountsResource(ContentNegotiatedMethodView):
    """MethodView implementation."""

    def __init__(self, serializers, default_media_type):
        """Constructor."""
        super(AccountsResource, self).__init__(
            serializers, default_media_type=default_media_type)

    @require_api_auth()
    def get(self):
        """Get accounts/users/?q=."""
        query = request.args.get('q')
        if query:
            return User.query.filter(
                (User.email.like(query)) |
                (cast(User.id, String) == query)
            ).all()
        else:
            return User.query.all()
