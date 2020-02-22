#!/bin/bash
/usr/bin/python3 ./setup.py install $@
rm -rf build cryptoluggage.egg-info bdist_wheel

