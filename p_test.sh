#!/bin/bash


export PYTHONPATH=/home/bgrieder/projects/cosmian_server/python

cd ~/projects/CiFEr/build
make && sudo make install &&\ 
/usr/bin/python3 ~/projects/cosmian_server/python/prototypes/abe/gpsw/test_gpsw.py &&\

cd ~/projects/CiFEr
