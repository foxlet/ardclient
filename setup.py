#!/usr/bin/env python

from distutils.core import setup, Extension

xlib = Extension('xlib',
                    sources = ['ardclient/xlibmodule.c'],
                    libraries = ['X11'],
                    include_dirs=['/usr/X11R6/include/'],
                    library_dirs=['/usr/X11R6/lib'])

setup (name = 'Ardclient',
       version = '1.0',
       description = 'Ardclient',
       ext_modules = [xlib],
       scripts = ['scripts/ardclient', 'scripts/ardpasswd'],
       package_dir = {'ardclient' : 'ardclient'},
       packages = ['ardclient', 'ardclient.protocol'],
       data_files = [('etc/ardclient', ['etc/ardclient.conf'])],
       )
