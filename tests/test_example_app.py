# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.


"""Test example app."""

import os
from os.path import abspath, dirname, join


def setup_module(module):
    """Set up before all tests."""

    # Go to example directory
    project_dir = dirname(dirname(abspath(__file__)))
    exampleapp_dir = join(project_dir, 'examples')
    os.chdir(exampleapp_dir)


def teardown_module(module):
    """Tear down after all tests."""
    pass


def test_example_app():
    """Test example app."""
    pass
