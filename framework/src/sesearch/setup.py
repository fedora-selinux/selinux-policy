#!/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>

from distutils.core import setup, Extension
extension_mod = Extension("setroubleshoot.sesearch._sesearch", [ "sesearch_wrapper.c"], libraries=["apol", "qpol"] )

setup(name = "sesearch", version="1.0", description="Python SESearch Bindings", author="Thomas Liu", author_email="tliu@redhat.com", ext_modules=[extension_mod], packages=["setroubleshoot/sesearch"])
