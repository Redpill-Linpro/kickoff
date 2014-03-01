#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Gitsh - A simple wrapper around git.
# Copyright (C) 2014  Espen Braastad / Redpill Linpro
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
import logging
import subprocess
import datetime

class gitsh():

    def __init__(self, repository, cache, log_file = False, \
                 log_level = logging.DEBUG, verbose = False):

        self.verbose = verbose
        self.repository = repository
        self.cache = cache
        self.log_level = log_level

        if log_file:
            self.log_file = log_file
        else:
            self.log_file = "/tmp/gitsh.log"

    def init(self):
        s = False
    
        cmd = ['git', 'init', self.cache]
        pr = subprocess.Popen(cmd,
               cwd=os.path.dirname(self.cache),
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO,"Repository initialized at %s" % self.cache)
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to initialized repository at %s" % \
                self.cache)
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))
    
        return (s,out,error,pr.returncode)

    def remote(self, remote = False):

        if not remote:
            remote = self.repository

        s = False
    
        cmd = ['git', 'remote', 'add', 'origin', remote]
        pr = subprocess.Popen(cmd,
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "Remote origin repository %s added" % remote)
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to add remote origin repository " \
                "%s" % remote)
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))
    
        return (s,out,error,pr.returncode)

    def clone(self):
        s = False
        out = False
        error = False
        ret = False
    
        try:
            cmd = ['git', 'clone', self.repository, self.cache]
            pr = subprocess.Popen(cmd,
                   cwd=os.path.dirname(self.cache),
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git clone from " \
                "repository %s to %s" % (self.repository, self.cache))
    
        else:
            (out, error) = pr.communicate()
            ret = pr.returncode

            if ret == 0:
                self._dolog(logging.INFO, "Repository %s cloned to %s" % \
                    (self.repository, self.cache))
                s = True
            else:
                self._dolog(logging.ERROR, "Failed to clone repository %s to " \
                    "%s" % (self.repository, self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, " \
                    "stderr=%s, retcode=%s" % \
                    (s, " ".join(cmd), out, error, ret))
    
        return (s,out,error,ret)
    
    def pull(self):
        s = False
        out = False
        error = False
        ret = False
    
        try:
            cmd = ['git', 'pull']
            pr = subprocess.Popen(['git', 'pull'],
                   cwd=self.cache,
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git pull")
            return False
    
        else:
            (out, error) = pr.communicate()
            ret = pr.returncode

            if ret == 0:
                self._dolog(logging.INFO, "Repository pulled %s" % (self.cache))
                s = True
            else:
                self._dolog(logging.ERROR, "Failed to pull repository %s" % (self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                    (s, " ".join(cmd), out, error, ret))

        return (s,out,error,ret)
    
    def add(self, path):
        s = False
        out = False
        error = False
        ret = False
    
        try:
            cmd = ['git', 'add', path]
            pr = subprocess.Popen(cmd,
                   cwd=self.cache,
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git add")
            return False
    
        else:
            (out, error) = pr.communicate()

            ret = pr.returncode
            if ret == 0:
                self._dolog(logging.INFO, "File %s added to repository %s" % \
                    (path, self.cache))
                s = True
            else:
                self._dolog(logging.ERROR, "Failed to add %s to repository %s" % \
                    (path, self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                    (s, " ".join(cmd), out, error, ret))
    
        return (s,out,error,ret)
       
    def commit(self, path, message = "Not set"):
        s = False
        out = False
        error = False
        ret = False

        try:
            cmd = ['git', 'commit', '-m', message, path]
            pr = subprocess.Popen(cmd,
                   cwd=self.cache,
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git commit")
            return False
    
        else:
            (out, error) = pr.communicate()
            ret = pr.returncode

            if pr.returncode == 0:
                self._dolog(logging.INFO, "File %s committed to repository %s" % \
                    (path, self.cache))
                s = True
            else:
                self._dolog(logging.ERROR, "Failed to commit %s to repository %s" % \
                        (path, self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, " \
                    "stderr=%s, retcode=%s, cwd=%s" % (s, " ".join(cmd), out, \
                    error, ret, self.cache))
    
        return (s,out,error,ret)
    
    def push(self):
        s = False
        out = False
        error = False
        ret = False

        try:
            cmd = ['git', 'push', '-u', 'origin', 'master']
            pr = subprocess.Popen(cmd,
                   cwd=self.cache,
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git push")
            return False
    
        else:
            (out, error) = pr.communicate()
            ret = pr.returncode

            if ret == 0:
                self._dolog(logging.INFO, "Repository %s pushed" % \
                        (self.cache))
                s = True
            else:
                self._dolog(logging.ERROR, "Failed to push repository %s" % \
                        (self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                    (s, " ".join(cmd), out, error, ret))
    
        return (s,out,error,ret)

    def log(self):
        s = False
        out = False
        error = False
        ret = False
        log = []
    
        try:
            cmd = ['git', 'log', '--format= \
                                    author_name: %an\n \
                                    author_email: %ae\n \
                                    author_date: %at\n \
                                    committer_name: %cn\n \
                                    committer_email: %ce\n \
                                    committer_date: %ct\n \
                                    subject: %s\n \
                                    body: %b\n \
                                    \n']
            pr = subprocess.Popen(cmd,
                   cwd=self.cache,
                   stdout=subprocess.PIPE, 
                   stderr=subprocess.PIPE, 
                   shell=False)
        except:
            self._dolog(logging.ERROR, "Unable to execute git log")
            return False
    
        else:
            (out, error) = pr.communicate()
            ret = pr.returncode

            if ret == 0:
                s = True

                # Parse the output here, and populate the list
                line_filter = re.compile("^([^:]+)\s*:\s*(.*)$")
                for message in out.split("\n\n"):
                    l = {}
                    for line in message.split("\n"):
                        m = line_filter.match(line)
                        if m:
                            l[m.group(1).replace(' ','')] = m.group(2)
                    if len(l) > 6:
                        log.append(l)

            else:
                self._dolog(logging.ERROR, "Failed to read git log" % \
                        (self.cache))
                self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                    (s, " ".join(cmd), out, error, ret))
                            
            # Sort by commit date
            log = sorted(log, key=lambda k: k['committer_date']) 

        return (log,s,out,error,ret)

    def _dolog(self,level,text):
        if not self.log_file:
            return

        if not self.log_level:
            return

        logging.basicConfig(filename=self.log_file, level=self.log_level)
    
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    
        text = "[%s] %s" % (timestamp, text)
        logging.log(level, text)

