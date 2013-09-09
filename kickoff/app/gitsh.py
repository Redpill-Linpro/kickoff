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

    debug = False
    cache = False
    repository = False

    def __init__(self, repository, cache, debug = False):
        self.debug = debug
        self.repository = repository
        self.cache = cache

    def clone(self):
        s = False
    
        pr = subprocess.Popen(['git', 'clone', self.repository, self.cache],
               cwd=os.path.dirname(self.cache),
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            s = True
    
        return (s,out,error,pr.returncode)
    
    def pull(self):
        s = False
    
        pr = subprocess.Popen(['git', 'pull', self.cache],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            s = True
    
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
            s = True
    
        return (s,out,error,pr.returncode)
       
    def commit(self, path):
        s = False

        pr = subprocess.Popen(['git', 'commit', '-m', message, path],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            s = True
    
        return (s,out,error,pr.returncode)
    
    def push(self):
        s = False

        pr = subprocess.Popen(['git', 'psuh'],
               cwd=self.cache,
               stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, 
               shell=False)
    
        (out, error) = pr.communicate()

        if pr.returncode == 0:
            s = True
    
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

