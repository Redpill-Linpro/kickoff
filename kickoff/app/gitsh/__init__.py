# -*- coding: utf-8 -*-
"""
    gitsh
    ~~~~~

    A simple wrapper around git.

"""

import os
import re
import subprocess

class gitsh():

    def __init__(self, repository, cache, verbose = False):
        self.verbose = verbose
        self.repository = repository
        self.cache = cache

    def init(self):
        s = False
    
        pr = subprocess.Popen(['git', 'init', self.cache],
               cwd=os.path.dirname(self.cache),
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "Repository initialized at %s" % self.cache
            s = True
        else:
            if self.verbose:
                print "Failed to initialized repository at %s" % \
                    self.cache
    
        return (s,out,error,pr.returncode)

    def remote(self, remote = False):

        if not remote:
            remote = self.repository

        s = False
    
        pr = subprocess.Popen(['git', 'remote', 'add', 'origin', remote],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "Remote origin repository %s added" % remote
            s = True
        else:
            if self.verbose:
                print "Failed to add remote origin repository %s" % \
                    remote
    
        return (s,out,error,pr.returncode)

    def clone(self):
        s = False
    
        pr = subprocess.Popen(['git', 'clone', self.repository, self.cache],
               cwd=os.path.dirname(self.cache),
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "Repository %s cloned to %s" % \
                    (self.repository, self.cache)
            s = True
        else:
            if self.verbose:
                print "Failed to clone repository %s to %s" % \
                    (self.repository, self.cache)
    
        return (s,out,error,pr.returncode)
    
    def pull(self):
        s = False
    
        pr = subprocess.Popen(['git', 'pull'],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "Repository pulled %s" % \
                    (self.cache)
            s = True
        else:
            if self.verbose:
                print "Failed to pull repository %s" % \
                    (self.cache)

        return (s,out,error,pr.returncode)
    
    def add(self, path):
        s = False
    
        pr = subprocess.Popen(['git', 'add', path],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "File %s added to repository %s" % \
                    (path, self.cache)
            s = True
        else:
            if self.verbose:
                print "Failed to add %s to repository %s" % \
                    (path, self.cache)
    
        return (s,out,error,pr.returncode)
       
    def commit(self, path, message = "Not set"):
        s = False

        pr = subprocess.Popen(['git', 'commit', '-m', message, path],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "File %s committed to repository %s" % \
                    (path, self.cache)
            s = True
        else:
            if self.verbose:
                print "Failed to commit %s to repository %s" % \
                    (path, self.cache)
    
        return (s,out,error,pr.returncode)
    
    def push(self):
        s = False

        pr = subprocess.Popen(['git', 'push', '-u', 'origin', 'master'],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            if self.verbose:
                print "Repository %s pushed" % \
                    (path, self.cache)
            s = True
        else:
            if self.verbose:
                print "Failed to push repository %s" % \
                    (self.cache)
    
        return (s,out,error,pr.returncode)

    def log(self):
        s = False
        log = []
    
        pr = subprocess.Popen(['git', 'log', '--format=author_name: %an\n \
                                                       author_email: %ae\n \
                                                       author_date: %at\n \
                                                       committer_name: %cn\n \
                                                       committer_email: %ce\n \
                                                       committer_date: %ct\n \
                                                       subject: %s\n \
                                                       body: %b\n \
                                                       \n'],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
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
                        
        # Sort by commit date
        log = sorted(log, key=lambda k: k['committer_date']) 
        return (log,s,out,error,pr.returncode)

