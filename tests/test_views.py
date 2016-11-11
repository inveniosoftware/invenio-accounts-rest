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


"""Test module's REST API."""

from __future__ import absolute_import, print_function

import json

import pytest
from flask import url_for
from invenio_access.models import ActionUsers
from invenio_db import db

from invenio_accounts_rest.views import AssignRoleResource, \
    DeactivateUserResource, ListRolesResource, ReactivateUserResource, \
    RoleResource, UnassignRoleResource, UserListResource, \
    UserProfilePropertiesListResource, UserPropertiesListResource, \
    UserRolesListResource

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


def test_list_roles(app, roles, users):
    """Test listing all existing roles."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            return_value = {
                'hits': {
                    'total': 1,
                    'hits': [
                        {
                            'links': {
                                'self': url_for(
                                    'invenio_accounts_rest.role',
                                    role_id=users[0].roles[0].id,
                                    _external=True
                                )
                            },
                            'description': users[0].roles[0].description,
                            'name': users[0].roles[0].name,
                            'id': users[0].roles[0].id
                        }
                    ]
                }
            }

            with patch.object(
                ListRolesResource,
                'get',
                return_value={'data': return_value, 'code': 200}
            ):

                res = client.get(
                    url_for('invenio_accounts_rest.list_roles'),
                    headers=headers
                )

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))

            assert len(response_data['hits']['hits']) == 1
            assert response_data['hits']['hits'][0] == {
                'links': {
                    'self': url_for(
                        'invenio_accounts_rest.role',
                        role_id=users[0].roles[0].id,
                        _external=True,
                    )
                },
                'description': roles[0].description,
                'name': roles[0].name,
                'id': roles[0].id
            }


@pytest.yield_fixture()
def test_list_roles_permissions_mock(app, roles, users):

    return_value = {
        'hits': {
            'total': 1,
            'hits': [
                {
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.role',
                            role_id=users[0].roles[0].id,
                            _external=True
                        )
                    },
                    'description': users[0].roles[0].description,
                    'name': users[0].roles[0].name,
                    'id': users[0].roles[0].id
                }
            ]
        }
    }

    with patch.object(
        ListRolesResource,
        'get',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_list_roles_permissions(
    app, users, roles, test_list_roles_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.list_roles',
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_get_role(app, roles, users):
    """Test getting a role."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            return_value = {
                'hits': {
                    'total': 1,
                    'hits': [
                        {
                            'links': {
                                'self': url_for(
                                    'invenio_accounts_rest.role',
                                    role_id=roles[0].id,
                                    _external=True
                                )
                            },
                            'role': {
                                'description': roles[0].description,
                                'name': roles[0].name,
                                'role_id': roles[0].id
                            }
                        }
                    ]
                }
            }

            with patch.object(
                    RoleResource,
                    'get',
                    return_value={'data': return_value, 'code': 200}
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.role',
                        role_id=roles[0].id
                    ),
                    headers=headers
                )

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))

            assert response_data['hits']['hits'][0] == {
                'links': {
                    'self': url_for(
                        'invenio_accounts_rest.role',
                        role_id=roles[0].id,
                        _external=True
                    )
                },
                'role': {
                    'description': roles[0].description,
                    'name': roles[0].name,
                    'role_id': roles[0].id
                }
            }


@pytest.yield_fixture()
def test_get_role_permissions_mock(app, roles, users):

    return_value = {
        'hits': {
            'total': 1,
            'hits': [
                {
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.role',
                            role_id=roles[0].id,
                            _external=True
                        )
                    },
                    'role': {
                        'description': roles[0].description,
                        'name': roles[0].name,
                        'role_id': roles[0].id
                    }
                }
            ]
        }
    }

    with patch.object(
        RoleResource,
        'get',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_get_role_permissions(
    app, users, roles, test_get_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.role',
                    role_id=roles[0].id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_create_role(app, users):
    """Test creating a role."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            role_id = 2

            return_value = {
                'hits': {
                    'total': 1,
                    'hits': [
                        {
                            'links': {
                                'self': url_for(
                                    'invenio_accounts_rest.role',
                                    role_id=role_id,
                                    _external=True
                                )
                            },
                            'role': {
                                'description': 'desc',
                                'name': 'role',
                                'role_id': role_id
                            }
                        }
                    ]
                }
            }

            with patch.object(
                    ListRolesResource,
                    'post',
                    return_value={'data': return_value, 'code': 201}
            ):
                res = client.post(
                    url_for('invenio_accounts_rest.list_roles'),
                    data=json.dumps(
                        {'name': 'role', 'description': 'desc'}
                    ),
                    headers=headers
                )

            assert res.status_code == 201
            response_data = json.loads(res.get_data(as_text=True))

            role_id = response_data['hits']['hits'][0]['role']['role_id']
            assert response_data['hits']['hits'][0] == {
                'links': {
                    'self': url_for(
                        'invenio_accounts_rest.role',
                        role_id=role_id,
                        _external=True
                    )
                },
                'role': {
                    'description': 'desc',
                    'name': 'role',
                    'role_id': role_id
                }
            }


@pytest.yield_fixture()
def test_create_role_permissions_mock(app, roles, users):

    role_id = 2

    return_value = {
        'hits': {
            'total': 1,
            'hits': [
                {
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.role',
                            role_id=role_id,
                            _external=True
                        )
                    },
                    'role': {
                        'description': 'desc',
                        'name': 'role',
                        'role_id': role_id
                    }
                }
            ]
        }
    }

    with patch.object(
        ListRolesResource,
        'post',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_create_role_permissions(
    app, users, roles, test_create_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.post(
                url_for(
                    'invenio_accounts_rest.list_roles',
                    access_token=access_token,
                ),
                data=json.dumps(
                    {'name': 'role', 'description': 'desc'}
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_delete_role(app, roles, users):
    """Test deleting a role."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            with patch.object(
                    RoleResource,
                    'delete',
                    return_value={'data': {}, 'code': 204}
            ):
                res = client.delete(
                    url_for(
                        'invenio_accounts_rest.role',
                        role_id=roles[0].id
                    ),
                    headers=headers
                )
                assert res.status_code == 204

            with patch.object(
                RoleResource,
                'get',
                return_value={'data': {}, 'code': 204}
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.role',
                        role_id=roles[0].id
                    ),
                    headers=headers
                )
                assert res.status_code == 204


@pytest.yield_fixture()
def test_delete_role_permissions_mock(app, roles, users):
    with patch.object(
        RoleResource,
        'delete',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_delete_role_permissions(
    app, users, roles, test_delete_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.delete(
                url_for(
                    'invenio_accounts_rest.role',
                    role_id=roles[0].id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_assign_role(app, users):
    """Test assigning role to user."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            with patch.object(
                    AssignRoleResource,
                    'put',
                    return_value={'data': {}, 'code': 201}
            ):
                res = client.put(
                    url_for(
                        'invenio_accounts_rest.assign_role',
                        user_id=users[1].id,
                        role_id=users[0].roles[0].id
                    ),
                    headers=headers
                )
                assert res.status_code == 201

            with patch.object(
                    UserRolesListResource,
                    'get',
                    return_value={
                        'data': {
                            'user': {
                                'roles': [users[0].roles[0].id]
                            },
                        },
                        'code': 200
                    }
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.user_roles_list',
                        user_id=users[1].id
                    ),
                    headers=headers
                )
                response_data = json.loads(res.get_data(as_text=True))
                assert users[0].roles[0].id in response_data['user']['roles']


@pytest.yield_fixture()
def test_assign_role_permissions_mock(app, roles, users):
    with patch.object(
        AssignRoleResource,
        'put',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_assign_role_permissions(
    app, users, roles, test_assign_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.put(
                url_for(
                    'invenio_accounts_rest.assign_role',
                    user_id=other_user.id,
                    role_id=modified_user.roles[0].id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_unassign_role(app, users):
    """Test unassigning role from user."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            role = users[0].roles[0]

            with patch.object(
                    UnassignRoleResource,
                    'delete',
                    return_value={'data': {}, 'code': 204}
            ):
                res = client.delete(
                    url_for(
                        'invenio_accounts_rest.unassign_role',
                        user_id=users[0].id,
                        role_id=role.id,
                    ),
                    headers=headers
                )
                assert res.status_code == 204

            with patch.object(
                    UserRolesListResource,
                    'get',
                    return_value={
                        'data': {
                            'user': {
                                'roles': [users[0].roles[0].id]
                            }
                        },
                        'code': 200
                    }
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.user_roles_list',
                        user_id=users[0].id
                    ),
                    headers=headers
                )
                response_data = json.loads(res.get_data(as_text=True))
                assert role not in response_data['user']['roles']


@pytest.yield_fixture()
def test_unassign_role_permissions_mock(app, roles, users):
    with patch.object(
        UnassignRoleResource,
        'delete',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_unassign_role_permissions(
    app, users, roles, test_unassign_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]
    role = users[0].roles[0]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.delete(
                url_for(
                    'invenio_accounts_rest.unassign_role',
                    user_id=modified_user.id,
                    role_id=modified_user.roles[0].id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_update_role(app, roles, users):
    """Test updating a role."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json-patch+json')]

            return_value = {
                'hits': {
                    'total': 1,
                    'hits': [
                        {
                            'links': {
                                'self': url_for(
                                    'invenio_accounts_rest.role',
                                    role_id=roles[0].id,
                                    _external=True
                                )
                            },
                            'role': {
                                'description': 'desc',
                                'name': 'new_name',
                                'id': roles[0].id
                            }
                        }
                    ]
                }
            }

            with patch.object(
                    RoleResource,
                    'patch',
                    return_value={'data': return_value, 'code': 200}
            ):
                res = client.patch(
                    url_for(
                        'invenio_accounts_rest.role',
                        role_id=roles[0].id
                    ),
                    data=json.dumps([{
                        'op': 'replace',
                        'path': '/new_name',
                        'value': 'new_name'
                    }]),
                    headers=headers
                )

                assert res.status_code == 200
                response_data = json.loads(res.get_data(as_text=True))
                assert response_data == return_value


@pytest.yield_fixture()
def test_update_role_permissions_mock(app, roles, users):
    return_value = {
        'hits': {
            'total': 1,
            'hits': [
                {
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.role',
                            role_id=roles[0].id,
                            _external=True
                        )
                    },
                    'role': {
                        'description': 'desc',
                        'name': 'new_name',
                        'id': roles[0].id
                    }
                }
            ]
        }
    }
    with patch.object(
        RoleResource,
        'patch',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_update_role_permissions(
    app, users, roles, test_update_role_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json-patch+json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.patch(
                url_for(
                    'invenio_accounts_rest.role',
                    role_id=roles[0].id,
                    access_token=access_token,
                ),
                data=json.dumps([{
                    'op': 'replace',
                    'path': '/new_name',
                    'value': 'new_name'
                }]),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_get_user_roles(app, users):
    """Test listing all user's roles."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            with patch.object(
                    UserRolesListResource,
                    'get',
                    return_value={'data': {}, 'code': 200}
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.user_roles_list',
                        user_id=users[0].id
                    ),
                    headers=headers
                )

                assert res.status_code == 200
                response_data = json.loads(res.get_data(as_text=True))
                # TODO: length and elems in list
                # assert len(response_data['user']['roles']) == 1
                # assert response_data['user']['roles'][0].name == role.name


@pytest.yield_fixture()
def test_get_user_roles_permissions_mock(app, users):

    with patch.object(
        UserRolesListResource,
        'get',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_get_user_roles_permissions(
    app, users, test_get_user_roles_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.user_roles_list',
                    user_id=modified_user.id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_get_user_properties(app, users):
    """Test listing all user's properties."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            return_value = {
                'data': {
                    'user': {
                        'email': users[0].email
                    },
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.' +
                            'user_properties_list',
                            user_id=users[0].id,
                            _external=True
                        )
                    }
                }
            }

            with patch.object(
                    UserPropertiesListResource,
                    'get',
                    return_value={'data': return_value, 'code': 200}
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.user_properties_list',
                        user_id=users[0].id
                    ),
                    headers=headers
                )

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data['data']['user']['email'] == users[0].email
            assert response_data['data']['links']['self'] == url_for(
                'invenio_accounts_rest.user_properties_list',
                user_id=users[0].id,
                _external=True
            )
            # TODO: test that only owner and admin can see the email


@pytest.yield_fixture()
def test_get_user_properties_permissions_mock(app, users):

    return_value = {
        'data': {
            'user': {
                'email': users[0].email
            },
            'links': {
                'self': url_for(
                    'invenio_accounts_rest.' +
                    'user_properties_list',
                    user_id=users[0].id,
                    _external=True
                )
            }
        }
    }

    with patch.object(
        UserPropertiesListResource,
        'get',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_get_user_properties_permissions(
    app, users, test_get_user_properties_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.user_properties_list',
                    user_id=modified_user.id,
                    access_token=access_token
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_modify_user_properties(app, users):
    """Test modifying user's properties."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json-patch+json')]

            return_value = {
                'data': {
                    'user': {
                        'id': users[0].id,
                        'email': 'other@email.com'
                    },
                    'links': {
                        'self': url_for(
                            'invenio_accounts_rest.' +
                            'user_properties_list',
                            user_id=users[0].id,
                            _external=True
                        )
                    }
                }
            }

            with patch.object(
                UserPropertiesListResource,
                'patch',
                return_value={'data': return_value, 'code': 200}
            ):
                res = client.patch(
                    url_for(
                        'invenio_accounts_rest.user_properties_list',
                        user_id=users[0].id
                    ),
                    data=json.dumps([{
                        'op': 'replace',
                        'path': '/email',
                        'value': 'other@email.com'
                    }]),
                    headers=headers
                )

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data['data']['links']['self'] == url_for(
                'invenio_accounts_rest.user_properties_list',
                user_id=users[0].id,
                _external=True
            )
            assert response_data['data']['user']['id'] == users[0].id
            assert response_data['data']['user']['email'] == 'other@email.com'


@pytest.yield_fixture()
def test_modify_user_properties_permissions_mock(app, users):

    return_value = {
        'data': {
            'user': {
                'id': users[0].id,
                'email': 'other@email.com'
            },
            'links': {
                'self': url_for(
                    'invenio_accounts_rest.' +
                    'user_properties_list',
                    user_id=users[0].id,
                    _external=True
                )
            }
        }
    }

    with patch.object(
        UserPropertiesListResource,
        'patch',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_modify_user_properties_permissions(
    app, users, test_modify_user_properties_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json-patch+json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.patch(
                url_for(
                    'invenio_accounts_rest.user_properties_list',
                    user_id=modified_user.id,
                    access_token=access_token,
                ),
                data=json.dumps([{
                    'op': 'replace',
                    'path': '/email',
                    'value': 'other@email.com'
                }]),
                headers=headers
            )
        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_modify_user_profile_properties(app, users):
    """Test modifying user profile's properties."""
    with app.app_context():
        with app.test_client() as client:

            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json-patch+json')]

            return_value = {
                'profile': {
                    'full_name': 'new full name'
                }
            }

            with patch.object(
                    UserProfilePropertiesListResource,
                    'patch',
                    return_value={'data': return_value, 'code': 200}
            ):
                res = client.patch(
                    url_for(
                        'invenio_accounts_rest.user_profile_properties_list',
                        user_id=users[0].id
                    ),
                    data=json.dumps([{
                        'op': 'replace',
                        'path': '/profile/full_name',
                        'value': 'new full name'
                    }]),
                    headers=headers
                )

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data['profile']['full_name'] == 'new full name'


@pytest.yield_fixture()
def test_modify_user_profile_properties_permissions_mock(app):

    return_value = {
        'profile': {
            'full_name': 'new full name'
        }
    }

    with patch.object(
        UserProfilePropertiesListResource,
        'patch',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_modify_user_profile_properties_permissions(
    app, users, test_modify_user_profile_properties_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json-patch+json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.patch(
                url_for(
                    'invenio_accounts_rest.user_profile_properties_list',
                    user_id=modified_user.id,
                    access_token=access_token,
                ),
                data=json.dumps([{
                    'op': 'replace',
                    'path': '/profile/full_name',
                    'value': 'new full name'
                }]),
                headers=headers
            )
        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_list_users(app, users):
    """Test listing all existing users."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            return_value = [{
                'id': users[0].id,
                'email': users[0].email,
            }]

            with patch.object(
                UserListResource,
                'get',
                return_value={'data': return_value, 'code': 200}
            ):
                res = client.get(
                    url_for('invenio_accounts_rest.users_list'),
                    headers=headers)

            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))
            # TODO: length test
            assert response_data[0]['id'] == users[0].id
            assert response_data[0]['email'] == users[0].email


@pytest.yield_fixture()
def test_list_users_permission_mock(app, users):

    return_value = [{
        'id': users[0].id,
        'email': users[0].email,
    }]

    with patch.object(
        UserListResource,
        'get',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_list_users_permission(
    app, users, test_list_users_permission_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.users_list',
                    access_token=access_token,
                ),
                headers=headers,
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_search_users(app, users):
    """Test searching users."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            return_value = {
                'links': {
                    'self': url_for(
                        'invenio_accounts_rest.users_list',
                        q='other',
                        _external=True
                    )
                },
                'users': [
                    {
                        'id': users[0].id,
                        'email': users[0].email,
                        'links': {
                            'self': url_for(
                                'invenio_accounts_rest.user_properties_list',
                                user_id=users[0].id,
                                _external=True
                            )
                        },
                    }
                ]
            }

            with patch.object(
                    UserListResource,
                    'get',
                    return_value={'data': return_value, 'code': 200}
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.users_list',
                        q='other'
                    ),
                    headers=headers
                )
            assert res.status_code == 200
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data == return_value


@pytest.yield_fixture()
def test_search_users_permission_mock(app, users):

    return_value = {
        'links': {
            'self': url_for(
                'invenio_accounts_rest.users_list',
                q='other',
                _external=True
            )
        },
        'users': [
            {
                'id': users[0].id,
                'email': users[0].email,
                'links': {
                    'self': url_for(
                        'invenio_accounts_rest.user_properties_list',
                        user_id=users[0].id,
                        _external=True
                    )
                },
            }
        ]
    }

    with patch.object(
        UserListResource,
        'get',
        side_effect=[
            {'data': return_value, 'code': 401},
            {'data': return_value, 'code': 200},
            {'data': return_value, 'code': 403},
            {'data': return_value, 'code': 200}
        ]
    ):
        yield


def test_search_users_permission(
    app, users, test_search_users_permission_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.get(
                url_for(
                    'invenio_accounts_rest.users_list',
                    q='other',
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_reactivate_user(app, users):
    """Test reactivating user."""
    with app.app_context():
        with app.test_client() as client:
            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            with patch.object(
                    ReactivateUserResource,
                    'put',
                    return_value={'data': {}, 'code': 200}
            ):
                res = client.put(
                    url_for(
                        'invenio_accounts_rest.reactivate_user',
                        user_id=users[2].id,
                    ),
                    headers=headers
                )
            assert res.status_code == 200

            with patch.object(
                    UserListResource,
                    'get',
                    return_value={
                        'data': {
                            'user': {
                                'active': True
                            }
                        },
                        'code': 200
                    }
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.users_list',
                        user_id=users[2].id
                    ),
                    headers=headers
                )
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data['user']['active'] is True


@pytest.yield_fixture()
def test_reactivate_user_permission_mock(app):
    with patch.object(
        ReactivateUserResource,
        'put',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_reactivate_user_permission(
    app, users, test_reactivate_user_permission_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.put(
                    url_for(
                        'invenio_accounts_rest.reactivate_user',
                        user_id=admin.id,
                        access_token=access_token,
                    ),
                    headers=headers
                )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403


def test_deactivate_user(app, users):
    """Test deactivating user."""
    with app.app_context():
        with app.test_client() as client:

            headers = [('Content-Type', 'application/json'),
                       ('Accept', 'application/json')]

            with patch.object(
                    DeactivateUserResource,
                    'put',
                    return_value={'data': {}, 'code': 204}
            ):
                res = client.put(
                    url_for(
                        'invenio_accounts_rest.deactivate_user',
                        user_id=users[1].id,
                    ),
                    headers=headers
                )

            assert res.status_code == 204

            with patch.object(
                    UserListResource,
                    'get',
                    return_value={
                        'data': {
                            'user': {
                                'active': False
                            }
                        },
                        'code': 200
                    }
            ):
                res = client.get(
                    url_for(
                        'invenio_accounts_rest.users_list',
                        user_id=users[1].id
                    ),
                    headers=headers
                )
            response_data = json.loads(res.get_data(as_text=True))
            assert response_data['user']['active'] is False


@pytest.yield_fixture()
def test_deactivate_user_permissions_mock(app):
    with patch.object(
        DeactivateUserResource,
        'put',
        side_effect=[
            {'data': {}, 'code': 401},
            {'data': {}, 'code': 200},
            {'data': {}, 'code': 403},
            {'data': {}, 'code': 200}
        ]
    ):
        yield


def test_deactivate_user_permissions(
    app, users, test_deactivate_user_permissions_mock
):
    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    modified_user = users[0]
    other_user = users[1]
    admin = users[2]

    def patch_test(access_token, expected_code):
        with app.test_client() as client:
            res = client.put(
                url_for(
                    'invenio_accounts_rest.deactivate_user',
                    user_id=modified_user.id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    patch_test(None, 401)
    patch_test(modified_user.allowed_token, 200)
    patch_test(other_user.allowed_token, 403)
    patch_test(admin.allowed_token, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403
