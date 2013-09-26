# -*- coding: utf-8 -*-
"""
    gitsh
    ~~~~~

    A simple wrapper around git.

"""

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
            return False
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "Repository %s cloned to %s" % \
                (self.repository, self.cache))
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to clone repository %s to %s" % \
                (self.repository, self.cache))
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))
    
        return (s,out,error,pr.returncode)
    
    def pull(self):
        s = False
    
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
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "Repository pulled %s" % (self.cache))
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to pull repository %s" % (self.cache))
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))

        return (s,out,error,pr.returncode)
    
    def add(self, path):
        s = False
    
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
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "File %s added to repository %s" % \
                (path, self.cache))
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to add %s to repository %s" % \
                (path, self.cache))
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))
    
        return (s,out,error,pr.returncode)
       
    def commit(self, path, message = "Not set"):
        s = False

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
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "File %s committed to repository %s" % \
                (path, self.cache))
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to commit %s to repository %s" % \
                    (path, self.cache))
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, " \
                "stderr=%s, retcode=%s, cwd=%s" % (s, " ".join(cmd), out, \
                error, pr.returncode, self.cache))
    
        return (s,out,error,pr.returncode)
    
    def push(self):
        s = False

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
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            self._dolog(logging.INFO, "Repository %s pushed" % \
                    (self.cache))
            s = True
        else:
            self._dolog(logging.ERROR, "Failed to push repository %s" % \
                    (self.cache))
            self._dolog(logging.DEBUG, "status=%s, cmd=%s, stdout=%s, stderr=%s, retcode=%s" % \
                (s, " ".join(cmd), out, error, pr.returncode))
    
        return (s,out,error,pr.returncode)

    def log(self):
        s = False
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
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
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
                (s, " ".join(cmd), out, error, pr.returncode))
                        
        # Sort by commit date
        log = sorted(log, key=lambda k: k['committer_date']) 
        return (log,s,out,error,pr.returncode)

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

