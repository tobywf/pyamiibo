#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.path.insert(0, os.path.abspath('..'))

# -- General configuration ------------------------------------------------
needs_sphinx = '1.6'
extensions = [
    'sphinx.ext.autodoc',
    # 'sphinx.ext.viewcode',  # sphinx doesn't work great with properties :/
    'sphinx.ext.intersphinx',
]

templates_path = []
source_suffix = '.rst'
master_doc = 'index'

project = 'PyAmiibo'
description = '{} Documentation'.format(project)
copyright = '2017, Toby Fleming'
author = 'Toby Fleming'

version = '0.2'
release = '0.2.0'

language = None
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

autoclass_content = 'both'
autodoc_default_flags = ['members']
autosummary_generate = True

pygments_style = 'sphinx'
todo_include_todos = False
intersphinx_mapping = {
    'python': ('https://docs.python.org/dev', None),
}

# -- Options for HTML output ----------------------------------------------
html_theme = 'sphinx_rtd_theme'
# html_theme_options = {}
html_static_path = []

# -- Options for LaTeX output ---------------------------------------------
latex_elements = {'papersize': 'a4paper'}
latex_documents = [
    (master_doc, '{}.tex'.format(project), description, author, 'manual'),
]

# -- Options for manual page output ---------------------------------------
man_pages = [
    (master_doc, project, description, [author], 1)
]
