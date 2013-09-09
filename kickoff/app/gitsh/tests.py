#!/usr/bin/python

import sys
#import git
import os
import re
import tempfile
import gitsh

repository=tempfile.mkdtemp()
cache=tempfile.mkdtemp()

print "Using %s as repository, and %s as cache directory." %(repository, cache)

repo = gitsh.gitsh(repository,cache, True)

# Initialize the repository
repo.init()
repo.remote()

# Add a file
path = "%s/testfile" % cache
fp = open(path, 'w+')
fp.write("Some data")

repo.add(path)
repo.commit(path)
repo.push()

log = repo.log()
print log[0]

