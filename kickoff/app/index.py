#!/usr/bin/python
from wsgiref.handlers import CGIHandler
from kickoff import app

CGIHandler().run(app)
