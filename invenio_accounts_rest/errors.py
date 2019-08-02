# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2017-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio accounts REST errors."""

from invenio_rest.errors import RESTException


class MaxResultWindowRESTError(RESTException):
    """Maximum number of results passed."""

    code = 400
    description = 'Maximum number of results have been reached.'


class PatchJSONFailureRESTError(RESTException):
    """Failed to patch JSON."""

    code = 400
    description = 'Could not patch JSON.'


class MissingOldPasswordError(RESTException):
    """Old password not provided while trying to change user password."""

    code = 400
    description = 'Missing field old_password.'
