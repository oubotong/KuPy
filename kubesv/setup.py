# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='kubesv',
    version='0.1.0',
    description='K8s configuration verification',
    long_description=readme,
    author='CS219B Kubernetes Group',
    author_email='oubutong@cs.ucla.edu',
    url='https://github.com/oubotong/Kubernetes-verification',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

