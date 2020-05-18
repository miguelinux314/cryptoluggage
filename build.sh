#!/bin/bash
rm -rf build cryptoluggage.egg-info bdist_wheel
python3 setup.py sdist bdist_wheel
rm -rf build cryptoluggage.egg-info bdist_wheel
