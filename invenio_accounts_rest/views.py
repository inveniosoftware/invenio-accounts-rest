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

from flask import Blueprint, jsonify, request
from invenio_accounts.models import User
from invenio_oauth2server import require_api_auth
from invenio_rest import ContentNegotiatedMethodView
from sqlalchemy import String, cast

from invenio_accounts_rest.serializers import accounts_serializer

blueprint = Blueprint(
    'invenio_accounts_rest',
    __name__,
)


def dummy_serializer(data, *args, **kwargs):
    """Mock serializer."""
    if data is not None:
        response = jsonify(data['data'])
        response.status_code = data['code']
    else:
        response = None
        response.status_code = args[0]
    return response


class ListRolesResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'list_roles'

    def __init__(self, **kwargs):
        """Constructor."""
        super(ListRolesResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def get(self):
        """."""
        pass

    def post(self):
        """."""
        pass


class RoleResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'role'

    def __init__(self, **kwargs):
        """Constructor."""
        super(RoleResource, self).__init__(
            serializers={
                'application/json': dummy_serializer,
                'application/json-patch+json': dummy_serializer,
            },
            default_media_type='application/json',
            **kwargs
        )

    def get(self, role_id):
        """."""
        pass

    def patch(self, role_id):
        """."""
        pass

    def post(self):
        """."""
        pass

    def delete(self, role_id):
        """."""
        pass


class AssignRoleResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'assign_role'

    def __init__(self, **kwargs):
        """Constructor."""
        super(AssignRoleResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def put(self, user_id, role_id):
        """."""
        pass


class UnassignRoleResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'unassign_role'

    def __init__(self, **kwargs):
        """Constructor."""
        super(UnassignRoleResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def delete(self, user_id, role_id):
        """."""
        pass


class UserRolesListResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'user_roles_list'

    def __init__(self, **kwargs):
        """Constructor."""
        super(UserRolesListResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def get(self, user_id):
        """."""
        pass


class UserPropertiesListResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'user_properties_list'

    def __init__(self, **kwargs):
        """Constructor."""
        super(UserPropertiesListResource, self).__init__(
            serializers={
                'application/json': dummy_serializer,
                'application/json-patch+json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def patch(self, user_id):
        """."""
        pass

    def get(self, user_id):
        """."""
        pass


class UserProfilePropertiesListResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'user_profile_properties_list'

    def __init__(self, **kwargs):
        """Constructor."""
        super(UserProfilePropertiesListResource, self).__init__(
            serializers={
                'application/json': dummy_serializer,
                'application/json-patch+json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def patch(self, user_id):
        """."""
        pass


class UserListResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'users_list'

    def __init__(self, **kwargs):
        """Constructor."""
        super(UserListResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def get(self):
        """."""
        pass


class DeactivateUserResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'deactivate_user'

    def __init__(self, **kwargs):
        """Constructor."""
        super(DeactivateUserResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def put(self, user_id):
        """."""
        pass


class ReactivateUserResource(ContentNegotiatedMethodView):
    """."""

    view_name = 'reactivate_user'

    def __init__(self, **kwargs):
        """Constructor."""
        super(ReactivateUserResource, self).__init__(
            serializers={
                'application/json': dummy_serializer
            },
            default_media_type='application/json',
            **kwargs
        )

    def put(self, user_id):
        """."""
        pass


class AccountsResource(ContentNegotiatedMethodView):
    """MethodView implementation."""

    view_name = 'accounts_resource'

    def __init__(self, **kwargs):
        """Constructor."""
        super(AccountsResource, self).__init__(
            serializers={'application/json': accounts_serializer},
            default_media_type='application/json',
            **kwargs
        )

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


blueprint.add_url_rule(
    '/roles',
    view_func=ListRolesResource.as_view(
        ListRolesResource.view_name
    )
)

blueprint.add_url_rule(
    '/roles/<string:role_id>',
    view_func=RoleResource.as_view(
        RoleResource.view_name
    )
)


blueprint.add_url_rule(
    '/roles/<string:role_id>/users/<string:user_id>',
    view_func=AssignRoleResource.as_view(
        AssignRoleResource.view_name
    )
)


blueprint.add_url_rule(
    '/roles/<string:role_id>/users/<string:user_id>',
    view_func=UnassignRoleResource.as_view(
        UnassignRoleResource.view_name
    )
)


blueprint.add_url_rule(
    '/users/<string:user_id>/roles',
    view_func=UserRolesListResource.as_view(
        UserRolesListResource.view_name
    )
)


blueprint.add_url_rule(
    '/users/<string:user_id>',
    view_func=UserPropertiesListResource.as_view(
        UserPropertiesListResource.view_name
    )
)


blueprint.add_url_rule(
    '/users/<string:user_id>/profile_properties',
    view_func=UserProfilePropertiesListResource.as_view(
        UserProfilePropertiesListResource.view_name
    )
)


blueprint.add_url_rule(
    '/users',
    view_func=UserListResource.as_view(
        UserListResource.view_name
    )
)


blueprint.add_url_rule(
    '/user/deactivate/<string:user_id>',
    view_func=DeactivateUserResource.as_view(
        DeactivateUserResource.view_name
    )
)


blueprint.add_url_rule(
    '/user/reactivate/<string:user_id>',
    view_func=ReactivateUserResource.as_view(
        ReactivateUserResource.view_name
    )
)


blueprint.add_url_rule(
    '/users/',
    view_func=AccountsResource.as_view(
        AccountsResource.view_name
    ),
    methods=['GET'],
)
