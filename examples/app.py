# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.


"""Minimal Flask application example for development.

Run example development server:

.. code-block:: console

   $ cd examples
   $ export FLASK_APP=app.py
   $ export FLASK_DEBUG=1
   $ flask run
"""

from __future__ import absolute_import, print_function

from flask import Flask
from flask_babelex import Babel

from invenio_accounts_rest import InvenioAccountsREST

# Create Flask application
app = Flask(__name__)
Babel(app)
InvenioAccountsREST(app)
