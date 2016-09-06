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


"""Pytest configuration."""

from __future__ import absolute_import, print_function

import tempfile

import pytest
from flask import Flask
from flask_security.utils import encrypt_password
from invenio_accounts import InvenioAccounts
from invenio_db import db as db_
from invenio_db import InvenioDB
from invenio_oauth2server import InvenioOAuth2Server
from invenio_oauth2server.models import Token
from sqlalchemy_utils.functions import create_database, database_exists
from werkzeug.local import LocalProxy

from invenio_accounts_rest import InvenioAccountsREST


@pytest.yield_fixture()
def app():
    """Flask application fixture."""
    instance_path = tempfile.mkdtemp()

    app = Flask(__name__, instance_path=instance_path)
    app.config.update(
        OAUTH2SERVER_CLIENT_ID_SALT_LEN=40,
        OAUTH2SERVER_CLIENT_SECRET_SALT_LEN=60,
        OAUTH2SERVER_TOKEN_PERSONAL_SALT_LEN=60,
        SECRET_KEY='changeme',
        TESTING=True,
    )

    InvenioOAuth2Server(app)
    InvenioAccounts(app)
    InvenioAccountsREST(app)
    InvenioDB(app)

    with app.app_context():
        yield app


@pytest.yield_fixture()
def db(app):
    """Database fixture."""
    if not database_exists(str(db_.engine.url)):
        create_database(str(db_.engine.url))

    db_.create_all()
    yield db_
    db_.session.remove()
    db_.drop_all()


@pytest.yield_fixture()
def access_token(app, db):
    """Access token fixture."""
    _datastore = LocalProxy(lambda: app.extensions['security'].datastore)
    kwargs = dict(email='admin@inveniosoftware.org', password='123456',
                  active=True)
    kwargs['password'] = encrypt_password(kwargs['password'])
    user = _datastore.create_user(**kwargs)

    db.session.commit()
    token = Token.create_personal(
        'test-personal-{0}'.format(user.id),
        user.id,
        scopes=[],
        is_internal=True,
    ).access_token
    db.session.commit()

    yield token
