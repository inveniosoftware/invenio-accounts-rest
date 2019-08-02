# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio modules that adds accounts REST API."""

from __future__ import absolute_import, print_function

from flask import current_app

from . import config
from .utils import load_or_import_from_config
from .views import blueprint


class InvenioAccountsREST(object):
    """Invenio-Accounts-REST extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.app = app
        self.init_config(app)
        app.register_blueprint(blueprint)
        app.extensions['invenio-accounts-rest'] = self

    def read_role_permission_factory(self, **kwargs):
        """Permission factory for reading the role."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_ROLE_PERMISSION_FACTORY', app=self.app)

    def update_role_permission_factory(self, **kwargs):
        """Permission factory for updating the role."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY', app=self.app)

    def delete_role_permission_factory(self, **kwargs):
        """Permission factory for deleting the role."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY', app=self.app)

    def read_roles_list_permission_factory(self, **kwargs):
        """Permission factory for reading the list of roles."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_ROLES_LIST_PERMISSION_FACTORY', app=self.app)

    def create_role_permission_factory(self, **kwargs):
        """Permission factory for creating the role."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_CREATE_ROLE_PERMISSION_FACTORY', app=self.app)

    def assign_role_permission_factory(self, **kwargs):
        """Permission factory for assigning the role to the user."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_ASSIGN_ROLE_PERMISSION_FACTORY', app=self.app)

    def unassign_role_permission_factory(self, **kwargs):
        """Permission factory for unassigning the role from the user."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_UNASSIGN_ROLE_PERMISSION_FACTORY', app=self.app)

    def read_role_users_list_permission_factory(self, **kwargs):
        """Permission factory for reading a role's list of users."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_ROLE_USERS_LIST_PERMISSION_FACTORY',
            app=self.app
        )

    def read_user_roles_list_permission_factory(self, **kwargs):
        """Permission factory for reading the list of roles."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_USER_ROLES_LIST_PERMISSION_FACTORY',
            app=self.app
        )

    def read_user_properties_permission_factory(self, **kwargs):
        """Permission factory for reading the user's properties."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_USER_PROPERTIES_PERMISSION_FACTORY',
            app=self.app
        )

    def update_user_properties_permission_factory(self, **kwargs):
        """Permission factory for modifying the user's properties."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_UPDATE_USER_PROPERTIES_PERMISSION_FACTORY',
            app=self.app
        )

    def read_users_list_permission_factory(self, **kwargs):
        """Permission factory for reading the list of users."""
        return load_or_import_from_config(
            'ACCOUNTS_REST_READ_USERS_LIST_PERMISSION_FACTORY', app=self.app)

    def init_config(self, app):
        """Initialize configuration."""
        # Set up API endpoints for records.
        for k in dir(config):
            if k.startswith('ACCOUNTS_REST_'):
                app.config.setdefault(k, getattr(config, k))
