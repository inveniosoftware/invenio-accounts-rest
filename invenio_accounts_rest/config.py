# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2017-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""InvenioAccountsREST configuration."""

from .utils import deny_all

ACCOUNTS_REST_READ_ROLE_PERMISSION_FACTORY = deny_all
"""Default get role permission factory: reject any request."""

ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY = deny_all
"""Default update role permission factory: reject any request."""

ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY = deny_all
"""Default delete role permission factory: reject any request."""

ACCOUNTS_REST_READ_ROLES_LIST_PERMISSION_FACTORY = deny_all
"""Default list roles permission factory: reject any request."""

ACCOUNTS_REST_CREATE_ROLE_PERMISSION_FACTORY = deny_all
"""Default create role permission factory: reject any request."""

ACCOUNTS_REST_ASSIGN_ROLE_PERMISSION_FACTORY = deny_all
"""Default assign role to user permission factory: reject any request."""

ACCOUNTS_REST_UNASSIGN_ROLE_PERMISSION_FACTORY = deny_all
"""Default unassign role from user permission factory: reject any request."""

ACCOUNTS_REST_READ_ROLE_USERS_LIST_PERMISSION_FACTORY = deny_all
"""Default list roles' users permission factory: reject any request."""

ACCOUNTS_REST_READ_USER_ROLES_LIST_PERMISSION_FACTORY = deny_all
"""Default list users' roles permission factory: reject any request."""

ACCOUNTS_REST_READ_USER_PROPERTIES_PERMISSION_FACTORY = deny_all
"""Default read user properties permission factory: reject any request."""

ACCOUNTS_REST_UPDATE_USER_PROPERTIES_PERMISSION_FACTORY = deny_all
"""Default modify user properties permission factory: reject any request."""

ACCOUNTS_REST_READ_USERS_LIST_PERMISSION_FACTORY = deny_all
"""Default list users permission factory: reject any request."""
