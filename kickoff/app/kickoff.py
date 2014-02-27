#!/usr/bin/env python

import os
import re
import operator
import cgi
import bson
import shutil
import time
import flask
import socket
import datetime
import apachelog
import pymongo
import hashlib
import json
import logging
import gitsh
import string

#from dulwich.repo import Repo
#from dulwich.client import HttpGitClient

#import socket
#import syslog

app = flask.Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile('../conf/kickoff.cfg')

# Convert from datetime object to timestamp
def dt_to_timestamp(dt):
    t = dt.strftime("%Y%m%d%H%M%S")
    return t

# Convert from timestamp to datetime object
def timestamp_to_dt(timestamp):
    t = datetime.datetime.strptime(str(timestamp.strip("[").split(" ")[0]), '%d/%b/%Y:%H:%M:%S')
    return t

def epoch_to_dt(epoch):
    t = datetime.datetime.fromtimestamp(int(epoch))
    return t

def dolog(text, prefix = '', level = 'debug'):
    logging.basicConfig(filename=app.config['LOG_FILE'],level=logging.DEBUG)

    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    text = "[%s] %s : %s" % (timestamp, prefix, text)

    if level == 'debug':
        logging.debug(text)
    elif level == 'info':
        logging.info(text)
    elif level == 'warning':
        logging.warning(text)
    elif level == 'error':
        logging.error(text)
    elif level == 'critical':
        logging.critical(text)

def dbopen(collection):
    dbhost = app.config['DBHOST']
    dbport = app.config['DBPORT']
    db = app.config['DBNAME']

    # Connect to mongodb
    try:
        connection = pymongo.Connection(dbhost,dbport)

    except:
        print "Unable to connect to database server " \
              "at %s:%s" % (dbhost,dbport)
        return False

    # Select database
    try:
        database = connection[db]

    except:
        print "ERROR: Unable to select to database %s " \
              "at %s:%s" % (db,dbhost,dbport)
        return False

    # Select collection
    try:
        col = database[collection]

    except:
        print "ERROR: Unable to select to collection %s " \
              "in database at %s:%s" % (collection,db,dbhost,dbport)
        return False

    # Return collection handler
    return col

def get_vendor(mac):
    path = app.config["OUI"]
    vendor = False
    if not os.path.isfile(path):
        dolog("The path %s does not exist" % path, "get_vendor")
        return False

    # Need dashes as part of the address
    mac = pretty_mac(mac)

    needle = mac[0:8].upper()
    r = re.compile('^\s+%s\s+\(hex\)\s+(.*)' % needle)
    with open(path, 'r') as f:
        for line in f:
            m = r.search(line)
            if m:
                vendor = m.group(1)

    return vendor

## Save the data for a spesific MAC address.
#def save_host(mac, data = {}):
#    path = app.config['HOST_DIR'] + '/' + mac
#
#    now = datetime.datetime.now()
#    ts = dt_to_timestamp(now)
#
#    if not os.path.exists(path):
#        os.makedirs(path,0700)
#
#    status = False
#
#    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#    data['mac'] = mac
#
#    filepath = '%s/%s.json' % (path, ts)
#    content = json.dumps(data, indent=4, sort_keys=True)
#
#    try:
#        f = open(filepath,'w+')
#        f.write(content)
#        f.close()
#
#    except:
#        print "Unable to write host file (%s)." % (filepath)
#
#    else:
#        status = True
#        print "Host file written (%s)." % (filepath)
#
#    return status
#
## Save the data for a spesific MAC address.
#def save_state(mac, data = {}):
#    path = app.config['STATE_DIR'] + '/' + mac
#
#    now = datetime.datetime.now()
#    ts = dt_to_timestamp(now)
#
#    if not os.path.exists(path):
#        os.makedirs(path,0700)
#
#    status = False
#
#    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#    data['mac'] = mac
#    data['id'] = hashlib.sha1(ts + mac).hexdigest()
#    data['ts'] = int(ts)
#
#    filepath = '%s/%s.json' % (path, ts)
#    content = json.dumps(data, indent=4, sort_keys=True)
#
#    try:
#        f = open(filepath,'w+')
#        f.write(content)
#        f.close()
#
#    except:
#        print "Unable to write state file (%s)." % (filepath)
#
#    else:
#        status = True
#        #print "State file created (%s)." % (filepath)
#
#        history = app.config['HISTORY_DIR']
#        if not os.path.exists(history):
#            os.makedirs(history,0700)
#
#        linkpath = '%s/%s-%s' % (history, ts, mac)
#        try:
#            os.symlink(filepath, linkpath)
#        except:
#            print "Unable to create symlink from %s to %s" % \
#                (filepath, linkpath)
#
#    return status

# Input validation for domains
def clean_domain(domain):
    f = re.compile('[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*')
    m = f.match(domain)
    if not m:
       domain = False

    return domain

def verify_mac(mac):
    macfilter = re.compile('^[a-f0-9]{12}$')

    if mac:
        m = macfilter.match(mac)
        if m:
            return True

    return False

## Give MAC addresses nice formatting.
def clean_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^0-9a-fA-F]', '', mac)
    mac = mac.lower()

    # At this point, the mac address should be 12 characters
    if len(mac) != 12:
        mac = False
    
    return mac

## Give MAC addresses nice formatting.
def pretty_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^0-9a-fA-F]', '', mac)
    mac = mac.lower()

    # At this point, the mac address should be 12 characters
    if len(mac) == 12:
        mac = '%s-%s-%s-%s-%s-%s' % \
              (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12])
    else:
        mac = False
    
    return mac

#def get_ipxe_configuration(mac, permission, host):
#    ipxe = False
#    path = False
#    status = False
#
#    # If not permission, serve some exit-message
#    if not permission:
#        path = app.config['DEFAULT_NO_PERMISSION_IPXE_CONFIGURATION']
#        status = 0
#
#    else:
#        # Check if the directory of this mac address exists to see if we have seen
#        # this host before or not.
#        d = app.config['STATE_DIR'] + '/' + mac
#        if os.path.isdir(d):
#            # Known host
#            # Look for configuration, if none is found:
#            if 'ipxe' in host:
#                ipxe = host['ipxe']
#                status = 3
#            else:
#                path = app.config['DEFAULT_KNOWN_HOST_IPXE_CONFIGURATION']
#                status = 2
#        else:
#            # Unknown host
#            path = app.config['DEFAULT_UNKNOWN_HOST_IPXE_CONFIGURATION']
#            status = 1
#
#    if not ipxe and path:
#        if os.path.exists(path):
#            try:
#                f = open(path, 'r')
#
#            except:
#                print "Unable to open file %s for reading." % (path)
#
#            else:
#                ipxe = f.read()
#                f.close()
#
#    return (status,ipxe)
#
#def get_data(path, ts = False):
#    if not os.path.isdir(path):
#        return False
#
#    if not ts:
#        f = re.compile("^(\d+)\.json$")
#        ts = 0
#        for entry in os.listdir(path):
#            i = path + '/' + entry
#            m = f.match(entry)
#            if os.path.isfile(i) and m:
#                this_ts = int(m.group(1))
#                if this_ts > ts:
#                    ts = this_ts
#
#    filepath = path + '/' + str(ts) + '.json'
#    if not os.path.isfile(filepath):
#        print "File %s does not exist" % filepath
#        return False
#
#    try:
#        f = open(filepath,'r')
#    except:
#        print "Unable to open file %s for reading" % filepath
#    else:
#         try:
#             content = json.loads(f.read())
#
#         except:
#             print "Unable to read and/or decode content in %s" % filepath
#
#         else:
#             return content
#
#    return False
#
## Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
#def get_permission(host, mac, uuid, remote_addr, hostname):
#    if 'mac' in host:
#        if mac != host['mac']:
#            return False
#
#    if 'uuid' in host:
#        if uuid != host['uuid']:
#            return False
#
#    if 'remote_addr' in host:
#        if remote_addr != host['remote_addr']:
#            return False
#
#    if 'hostname' in host:
#        if hostname != host['hostname']:
#            return False
#
#    return True
#
#def get_host_configuration(mac, uuid = False, remote_addr = False, hostname = False):
#    data = {}
#    path = app.config['HOST_DIR'] + '/' + mac
#
#    if os.path.isdir(path):
#        # Known host
#        data = get_data(path)
#
#    else:
#        # Unknown host, create a default here with lockdown
#        data['mac'] = mac
#        data['uuid'] = uuid
#        data['remote_addr'] = remote_addr
#        data['hostname'] = hostname
#
#        vendor = get_vendor(mac)
#        if vendor:
#            data['vendor'] = vendor
#
#        now = datetime.datetime.now()
#        ts = dt_to_timestamp(now)
#
#        data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#        if not os.path.exists(path):
#            os.makedirs(path,0700)
#
#        status = False
#        filepath = '%s/%s.json' % (path, ts)
#        content = json.dumps(data, indent=4, sort_keys=True)
#
#        try:
#            f = open(filepath,'w+')
#            f.write(content)
#            f.close()
#
#        except:
#            print "Unable to write host file (%s)." % (filepath)
#
#        else:
#            status = True
#            print "Host file written (%s)." % (filepath)
#
#    return data
#
#def get_revisions(path, count = False, reverse = True):
#    f = re.compile("^(\d+)\.json$")
#    revisions = []
#    if os.path.isdir(path):
#        for i in os.listdir(path):
#            filepath = path + "/" + i
#            m = f.match(i)
#            if os.path.isfile(filepath) and m:
#                ts = int(m.group(1))
#                revisions.append(ts)
#    revisions.sort()
#    if reverse:
#        revisions.reverse()
#    if count:
#        return revisions[0:count]
#    else:
#        return revisions
#        
#def get_all_mac_addresses():
#    path = app.config['STATE_DIR']
#    macs = []
#    if os.path.isdir(path):
#        for mac in os.listdir(path):
#            p = path + "/" + mac
#            if os.path.isdir(p):
#                macs.append(mac)
#    return macs

# https://gist.github.com/nzjrs/207624
def humanize_date_difference(now, otherdate=None, offset=None):
    if otherdate:
        dt = otherdate - now
        offset = dt.seconds + (dt.days * 60*60*24)
    if offset:
        delta_s = offset % 60
        offset /= 60
        delta_m = offset % 60
        offset /= 60
        delta_h = offset % 24
        offset /= 24
        delta_d = offset
    else:
        return "now"
 
    if delta_d == 0:
        #if delta_d > 6:
        #    date = now + datetime.timedelta(days=-delta_d, hours=-delta_h, minutes=-delta_m)
        #    return date.strftime('%A, %Y %B %m, %H:%I')
        #else:
        #    wday = now + datetime.timedelta(days=-delta_d)
        #    return wday.strftime('%A')
        return "%dh %dm" % (delta_h, delta_m)
    if delta_d > 0:
        return "%dd %dh %dm" % (delta_d, delta_h, delta_m)
    if delta_h > 0:
        return "%dh %dm" % (delta_h, delta_m)
    if delta_m > 0:
        return "%dm %ds" % (delta_m, delta_s)
    else:
        return "%ds" % delta_s

def is_boot_request(request, useragent):
    r = re.compile('^GET\s+\/bootstrap\/(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\/ipxe\s+HTTP\/[0-9]+\.[0-9]+$')
    u = re.compile('^iPXE.*$')

    rm = r.match(request)
    um = u.match(useragent)

    if rm and um:
        mac = rm.group(1)
        return mac
    else:
        #dolog("Request %s is not a boot request" % request)
        return False

def log_data_exists(checksum):
    col = dbopen('log')

    q = {}
    q['_id'] = checksum
    try:
        count = col.find(q).count()

    except:
        print "Unable to execute find query %s" % q

    else:
        if count > 0:
            return True

    return False

def create_default_configuration(i):
    status = True

    # Create directory
    mac = pretty_mac(i['mac'])
    prefix = mac

    dolog("Will create default configuration for the new host", prefix)

    basedir = "%s/%s" % (app.config['CACHE'],mac)
    if not os.path.exists(basedir):
        try:
            os.makedirs(basedir)
        except:
            status = False
            dolog("Unable to create directory %s" % (basedir), prefix)
        else:
            dolog("Directory %s created" % (basedir), prefix)
    else:
        dolog("Configuration directory for the new host does already exist", prefix)

    p = "%s/ipxe" % (basedir)
    if os.path.exists(p):
        dolog("iPXE configuration for mac %s does already exist in %s. Aborting to avoid overwriting." % (mac, p), prefix)
        return False

    # Copy default ipxe configuration
    if status:
        f = app.config['DEFAULT_HOST_IPXE_CONFIGURATION']
        content = read_file(f)
        target="ipxe"
        message = "Added ipxe configuration automatically by host discovery from %s" % i['client']
        (status, output) = inject_template(content, target, mac, message, i)

    # Create default htaccess configuration
    if status:
        f = app.config['DEFAULT_HOST_HTACCESS_CONFIGURATION']
        content = read_file(f)
        target=".htaccess"
        message = "Added htaccess configuration automatically by host discovery from %s" % i['client']
        (status, output) = inject_template(content, target, mac, message, i)

    # Create default environment configuration
    if status:
        f = app.config['DEFAULT_HOST_ENVIRONMENT_CONFIGURATION']
        content = read_file(f)
        target="environment"
        message = "Added environment automatically by host discovery from %s" % i['client']
        (status, output) = inject_template(content, target, mac, message, i)

    return status

def inject_template(content, target, mac, log_message, data = {}):
    path = "%s/%s/%s" % (app.config['CACHE'],pretty_mac(mac),target)
    status = True
    messages = []

    prefix = "inject_template"
    repository = app.config['REPOSITORY']
    cache = app.config['CACHE']
    repo = gitsh.gitsh(repository, cache, log_file = app.config['LOG_FILE'])

    if not os.path.isdir(cache):
        try:
            (s,out,error,ret) = repo.clone()
        except:
            status = False
            dolog("Failed to clone remote repository %s to %s" % (repository, cache), prefix)
        else:
            dolog("Remote repository %s cloned to %s" % (repository, cache), prefix)
    else:
        (s,out,error,ret) = repo.pull()
        if not s:
            if error:
                messages.append((3,error))
            else:
                messages.append((3,out))

    dolog("Injecting template into %s" % (path), mac)

    try:
        for i in data:
            needle = "##%s##" % i
            if string.find(content,needle) > -1:
                dolog("Replacing %s with %s in %s" % (needle,data[i],target), mac)
                content = string.replace(content, needle, str(data[i]))

        t = open(path,'w')
        t.write(content)
        t.close()

    except:
        status = False
        dolog("Unable to inject template into %s" % (path), mac)

    else:
        (s,out,error,ret) = repo.add(path)
        if not s:
            status = False
            if error:
                messages.append((3,error))
            else:
                messages.append((3,out))

        (s,out,error,ret) = repo.commit(path, message = log_message)
        if not s:
            status = False
            if error:
                messages.append((3,error))
            else:
                messages.append((3,out))

        (s,out,error,ret) = repo.push()
        if not s:
            status = False
            if error:
                messages.append((3,error))
            else:
                messages.append((3,out))

        if status:
            dolog("The changes were commited and pushed to the remote repository.", mac)
        else:
            dolog("Something failed when injecting template.", mac)

    return (status, messages)

def process_log_data(data,checksum,host):
    request = data['%r']
    useragent = data['%{User-Agent}i']
    mac = is_boot_request(request, useragent)
    prefix = "process_log_data"
    if mac:
        if not log_data_exists(checksum):

            i = {}
            i['_id'] = checksum
            i['host'] = host
            i['request'] = request
            i['useragent'] = useragent
            i['status'] = int(data['%>s'])
            i['byte'] = data['%b']
            i['client'] = data['%h']

            i['timestamp'] = data['%t']
            i['referer'] = data['%{Referer}i']
            i['mac'] = clean_mac(mac)

            dt = timestamp_to_dt(i['timestamp'])
            if dt:
                i['epoch'] = int(time.mktime(dt.timetuple()))

            vendor = get_vendor(i['mac'])
            if vendor:
                i['vendor'] = vendor

            #dolog("Log entry was %s" % (i), prefix)

            # This is a discovery. The mac address lacks configuration. Should
            # add default configuration at this point.
            if i['status'] == 404:
                create_default_configuration(i)

            # Only add the following status codes. 
            # TODO: The idea here is to avoid 301/302 mostly, but is this really such a good idea? Consider using an
            # exclude filter instead.
            if i['status'] in [200, 206, 400, 401, 403, 404, 500]:
                dolog("New log entry found to store, checksum %s" % (checksum), prefix)
                col = dbopen('log')
                try:
                    col.insert(i)
                except:
                    dolog("Unable to insert log data into db", prefix)
                    return False
                else:
                    dolog("Log line %s inserted" % checksum, prefix)
                    return True

    return False

def get_discovered_hosts(limit = False, uniqe = True):
    res = []
    (history, dates) = get_boot_requests()
    for i in history:
        if i['status'] == 404:
            if uniqe:
                add = True
                for r in res:
                    if r['mac'] == i['mac']:
                        add = False

                if add:
                    res.append(i)
            else:
                res.append(i)

        if limit:
            if len(res) >= limit:
                 break

    return res

def verify_date(date):
    r = re.compile('^\d{4}-\d{2}-\d{2}$')
    if r.match(date):
        return True
    else:
        return False

def get_boot_requests(mac = False, first = 0, limit = False, status = [], status_filter = False, date = False):
    res = []
    dates = {}

    if status_filter == 'only':
        pass
    elif status_filter == 'exclude':
        pass
    else:
        status_filter = 'all'

    print "Status: %s" % status
    print "Filter: %s" % status_filter


    now = datetime.datetime.now()
    col = dbopen('log')
    prefix = "get_boot_requests"
    fqdn_cache = {}
    try:
        q = {}
        if mac:
            q['mac'] = mac

        cursor = col.find(q)
    except:
        dolog("Unable to get boot requests %s" % (q), prefix)
    else:
        for i in cursor.sort('epoch',pymongo.DESCENDING):
            add = False
            dt = epoch_to_dt(i['epoch'])
            i['age'] = humanize_date_difference(dt,now)
            i['pretty_mac'] = pretty_mac(i['mac'])
            i['status'] = int(i['status'])

            if i['client'] in fqdn_cache:
                fqdn = fqdn_cache[i['client']]
            else:
                fqdn = get_reverse_address(i['client'])
                fqdn_cache[i['client']] = fqdn

            if fqdn:
                i['client_ptr'] = fqdn
                i['domain'] = extract_domain_from_fqdn(fqdn)

            if status_filter == 'only':
                if i['status'] in status:
                    add = True
            elif status_filter == 'exclude':
                if i['status'] not in status:
                    add = True
            else:
                add = True

            if add == True:
                d = dt.strftime("%Y-%m-%d")
                if not d in dates:
                    dates[d] = 0

                # One more request this day
                dates[d] += 1

                if not date:
                   res.append(i)

                else:
                    if date == d:
                        res.append(i)

    #res = sorted(res, key=lambda x: x['epoch'], reverse = True)
    if limit:
        res=res[first:first+limit]
    return res, dates

#def get_last_boot_requests(first = 0, limit = False, mac = False, status = []):
#    res = []
#
#    path = app.config['HISTORY_DIR']
#    f = re.compile('^(\d+)-(.*)')
#    if mac:
#        path = app.config['STATE_DIR'] + '/' + mac
#        f = re.compile('^(\d{14}).json$')
#
#    now = datetime.datetime.now()
#
#    if not os.path.isdir(path):
#        print "Directory %s does not exists." % path
#        return []
#    
#    entries = sorted(os.listdir(path), reverse = True)
#
#    matched_counter = 0
#    for entry in entries:
#        matching = False
#        if os.path.islink('%s/%s' % (path, entry)):
#            m = f.match(entry)
#            if m:
#                ts = m.group(1)
#                mac = m.group(2)
#                mac = clean_mac(mac)
#        else:
#            m = f.match(entry)
#            if m:
#                ts = m.group(1)
#
#        if ts and mac:
#            state_path = app.config['STATE_DIR'] + '/' + mac
#            data = get_data(state_path, ts = ts)
#            dt = timestamp_to_dt(ts)
#            data['age'] = humanize_date_difference(dt,now)
#            data['seconds'] = (now-dt).seconds
#
#            # Status filter
#            if len(status) > 0:
#                if data['status'] in status:
#                    matching = True
#            else:
#                matching = True
#
#            if matching:
#                if matched_counter >= first:
#                    res.append(data)
#
#                matched_counter += 1
#
#        if limit:
#            if len(res) >= limit:
#                break
#
#    return res

# Use the DNS PTR to create logical groups of nodes. This method converts fqdn
# to group name.
def extract_domain_from_fqdn(fqdn):
    group = False
    rule = re.compile('^[^\.]+\.(.*)')
    res = rule.search(fqdn)
    if res:
        if res.group(1):
            group = res.group(1)

    return group

def get_reverse_address(ip):
    try:
        reverse = socket.gethostbyaddr(ip)[0]
    except:
        reverse = False
    return reverse

def get_environments():
    environments = []
    now = datetime.datetime.now()
    col = dbopen('environments')
    prefix = "get_environments"
    try:
        q = {}
        cursor = col.find(q)
    except:
        dolog("Unable to get environments from the database: %s" % (q), prefix)
    else:
        for i in cursor:
            i['_id'] = str(i['_id'])

            if 'registered' in i:
                dt = epoch_to_dt(i['registered'])
                i['registered_age'] = humanize_date_difference(dt,now)

            if 'updated' in i:
                dt = epoch_to_dt(i['updated'])
                i['updated_age'] = humanize_date_difference(dt,now)

            environments.append(i)

    environments = sorted(environments, key=lambda x: (-x['enabled'], x['name']))
    return environments

def get_templates():
    templates = []
    now = datetime.datetime.now()
    col = dbopen('templates')
    prefix = "get_templates"
    try:
        q = {}
        cursor = col.find(q)
    except:
        dolog("Unable to get templates from the database: %s" % (q), prefix)
    else:
        for i in cursor:
            i['_id'] = str(i['_id'])

            if 'registered' in i:
                dt = epoch_to_dt(i['registered'])
                i['registered_age'] = humanize_date_difference(dt,now)

            if 'updated' in i:
                dt = epoch_to_dt(i['updated'])
                i['updated_age'] = humanize_date_difference(dt,now)

            templates.append(i)

    templates = sorted(templates, key=lambda x: (-x['enabled'], x['name']))
    #templates = sorted(templates, key=operator.attrgetter('name'))
    return templates

@app.route("/")
def index():
    (k, dates) = get_boot_requests()

    known = []

    # Show only known hosts in the recent boot history column
    if len(k) > 0:
        # Status filter is set
        enough = False
        for i in k:
            if 'status' in i:
                if i['status'] != 404:
                    if len(known) < 5:
                        known.append(i)
                    else:
                        enough = True

            if enough:
                continue

    unknown = get_discovered_hosts(limit = 5)


    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
    ]
    return flask.render_template("index.html", title = "Overview", \
        active = "overview", unknown = unknown, entries = known, \
        headings = headings)

@app.route("/environments/")
@app.route("/environments")
def environments():
    return flask.redirect('/environments/existing')

@app.route("/environments/existing/")
@app.route("/environments/existing")
def environments_existing():
    environments = get_environments()

    return flask.render_template("environments_existing.html", \
        title = "Available environments", \
        environments = environments, \
        active = "environments", subactive = "existing" )

@app.route("/environments/modify/", methods = ['GET', 'POST'])
@app.route("/environments/modify", methods = ['GET', 'POST'])
@app.route("/environments/new/", methods = ['GET', 'POST'])
@app.route("/environments/new", methods = ['GET', 'POST'])
def environments_new():

    prefix = "environments_modify"
    subactive = "new"
    messages = []
    status = True
    name = False
    content = False
    enabled = False

    title = "Create new environment"

    _id = flask.request.args.get('id', False)
    i = {}
    if _id:
        subactive = "modify"
        environments = get_environments()
        for e in environments:
            if str(e['_id']) == str(_id):
                title = "Modify environment"

                if 'name' in e:
                    name = e['name']

                if 'enabled' in e:
                    enabled = e['enabled']

                if 'content' in e:
                    content = e['content']

                try:
                    i['_id'] = bson.objectid.ObjectId(_id)
                    i['registered'] = e['registered']
                except:
                    messages.append((3,"Environment id is not valid!"))
                    status = False

    if flask.request.method == 'POST':
        try:
            enabled = flask.request.form['enabled']
        except:
            enabled = False

        try:
            name = flask.request.form['name']
            content = flask.request.form['content']

        except:
            messages.append((2, "All required input fields are not set, please try again."))

        else:
            if len(name) < 3:
                messages.append((2, "The name of the environment is too short."))
                status = False
              
            if len(content) < 3:
                messages.append((2, "The content of the environment is too short."))
                status = False

            i['name'] = name
            i['content'] = content

            if enabled:
                i['enabled'] = True
            else:
                i['enabled'] = False

            if status:
                col = dbopen('environments')
                dt = datetime.datetime.now()
                epoch = int(time.mktime(dt.timetuple()))
                try:
                    if _id:
                        i['updated'] = epoch
                        col.update({'_id':bson.objectid.ObjectId(_id)}, i,True)
                    else:
                        i['registered'] = epoch
                        col.insert(i)
                except:
                    dolog("Unable to insert environment into db", prefix)
                    messages.append((3, "Failed to write the changes to the database."))
                else:
                    dolog("Environment '%s' written to the database successfully" % name)
                    messages.append((0, "The changes have been written to the database."))
    
    return flask.render_template("environments_modify.html", \
        title = title, \
        active = "environments", subactive = subactive, \
        messages = messages, \
        name = name, enabled = enabled, content = content, _id = _id)

@app.route("/templates/")
@app.route("/templates")
def templates():
    return flask.redirect('/templates/existing')

@app.route("/templates/existing/")
@app.route("/templates/existing")
def templates_existing():
    templates = get_templates()

    return flask.render_template("templates_existing.html", \
        title = "Available templates", \
        templates = templates, \
        active = "templates", subactive = "existing" )

@app.route("/templates/modify/", methods = ['GET', 'POST'])
@app.route("/templates/modify", methods = ['GET', 'POST'])
@app.route("/templates/new/", methods = ['GET', 'POST'])
@app.route("/templates/new", methods = ['GET', 'POST'])
def templates_new():

    prefix = "templates_modify"
    subactive = "new"
    messages = []
    status = True
    name = False
    content = False
    enabled = False

    title = "Create new template"

    _id = flask.request.args.get('id', False)
    i = {}
    if _id:
        subactive = "modify"
        templates = get_templates()
        for t in templates:
            if str(t['_id']) == str(_id):
                title = "Modify template"

                if 'name' in t:
                    name = t['name']

                if 'enabled' in t:
                    enabled = t['enabled']

                if 'content' in t:
                    content = t['content']

                try:
                    i['_id'] = bson.objectid.ObjectId(_id)
                    i['registered'] = t['registered']
                except:
                    messages.append((3,"Template id is not valid!"))
                    status = False

    if flask.request.method == 'POST':
        try:
            enabled = flask.request.form['enabled']
        except:
            enabled = False

        try:
            name = flask.request.form['name']
            content = flask.request.form['content']

        except:
            messages.append((2, "All required input fields are not set, please try again."))

        else:
            if len(name) < 3:
                messages.append((2, "The name of the template is too short."))
                status = False
              
            if len(content) < 3:
                messages.append((2, "The content of the template is too short."))
                status = False

            i['name'] = name
            i['content'] = content

            if enabled:
                i['enabled'] = True
            else:
                i['enabled'] = False

            if status:
                col = dbopen('templates')
                dt = datetime.datetime.now()
                epoch = int(time.mktime(dt.timetuple()))
                try:
                    if _id:
                        i['updated'] = epoch
                        col.update({'_id':bson.objectid.ObjectId(_id)}, i,True)
                    else:
                        i['registered'] = epoch
                        col.insert(i)
                except:
                    dolog("Unable to insert template into db", prefix)
                    messages.append((3, "Failed to write the changes to the database."))
                else:
                    dolog("Template '%s' written to the database successfully" % name)
                    messages.append((0, "The changes have been written to the database."))
    
    return flask.render_template("templates_modify.html", \
        title = title, \
        active = "templates", subactive = subactive, \
        messages = messages, \
        name = name, enabled = enabled, content = content, _id = _id)

@app.route("/hosts/")
@app.route("/hosts")
def hosts():
    (cfg, output) = get_bootstrap_cfg()
    (history, dates) = get_boot_requests()
    data = {}
    for i in history:
        mac = i['mac']

        if not mac in data:
            data[mac] = i

    for mac in cfg:
        if mac in data:
            data[mac] = dict(data[mac], **cfg[mac])
        else:
            data[mac] = cfg[mac]
            data[mac]['mac'] = mac

    hosts = []
    for mac in data:
        # To enable sorting
        if not 'epoch' in data[mac]:
            data[mac]['epoch'] = -1

        hosts.append(data[mac])

    hosts = sorted(hosts, key=lambda x: x['epoch'], reverse = True)
    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'timestamp',     'pretty': 'Timestamp'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'Status'},
    ]

    return flask.render_template("hosts.html", \
        entries = hosts, \
        messages = output, \
        headings = headings, \
        title = "Hosts", \
        active = "hosts")

@app.route("/maintenance/")
@app.route("/maintenance")
def maintenance():
    out = {}
    out['errors'] = []
    out['meta'] = []

    logdir = app.config['REPLICA_LOG_DIR']
    log_format = app.config['REPLICA_LOG_FORMAT']
    prefix = "maintenance"

    # Will do a pull for each maintenance run to allow external changes to 
    # the configuration repository.
    repository = app.config['REPOSITORY']
    cache = app.config['CACHE']
    repo = gitsh.gitsh(repository, cache, log_file = app.config['LOG_FILE'])
    if os.path.isdir(cache):
        if repo.pull():
            out['meta'].append("Remote repository pulled successfully")
    else:
        if repo.clone():
            out['meta'].append("Remote repository cloned successfully")

    if not os.path.isdir(logdir):
        return flask.make_response("The path %s is not a directory" % logdir, 500)

    p = apachelog.parser(log_format)
    for host in os.listdir(logdir):
        path = "%s/%s" % (logdir,host)
        #dolog("Processing logs from directory %s" % path, prefix)
        if os.path.isdir(path):
            if not host in out:
                out[host] = {}

            for f in os.listdir(path):
                path = "%s/%s/%s" % (logdir,host,f)

                if os.path.isfile(path):
                    meta = {}
                    try:
                        fp = open(path,'r')
                    except:
                        dolog("Processing log: %s (failed to open!)" % (f), prefix)
                        out['errors'].append("Unable to open %s for reading" % path)
                    else:
                        meta['new_entries'] = 0
                        #try:
                        #    stat = os.stat(path)
                        #except:
                        #    out['errors'].append("Unable to stat %s" % path)
                        #else:
                        #    meta['mtime'] = stat.st_mtime
                        #    meta['size'] = stat.st_size

                        # Cheap way to count number of lines
                        for lines, l in enumerate(fp):
                            pass
                        lines += 1
                        fp.seek(0, 0)

                        #dolog("Log: %s (%d lines)" % (f,lines), prefix)

                        for i,line in enumerate(fp):
                            try:
                                data = p.parse(line)
                            except:
                                #out['errors'].append("Unable to parse line [%s] in file %s" % (line,path))
                                pass
                            else:
                                checksum = hashlib.sha1()
                                checksum.update(line)

                                s=process_log_data(data,checksum.hexdigest(),host)
                                if s:
                                    meta['new_entries'] += 1

                    out[host][f] = meta

    # Remove the error list if it's empty
    if len(out['errors']) == 0:
        del(out['errors'])
    
    response = flask.make_response(json.dumps(out, indent=2))
    response.headers['cache-control'] = 'max-age=0, must-revalidate'
    return response

@app.route("/domains/")
@app.route("/domains")
def domains():
    (history, dates) = get_boot_requests()
    data = []
    domains = []

    # Read only the last boot request from each domain into the dict
    for i in history:
        if 'domain' in i:
            if not i['domain'] in domains:
                domains.append(i['domain'])
                data.append(i)

    headings = [
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'Status'},
    ]

    data = sorted(data, key=lambda x: x['epoch'], reverse = True)
    return flask.render_template("domains.html", title = "Domains", \
        active = "domains", entries = data, headings = headings)

@app.route("/domain/<domain>")
def domain(domain):
    domain = clean_domain(domain)
    if not domain:
        return flask.make_response("The given domain is not valid", 400)

    (history, dates) = get_boot_requests()
    data = {}
    for i in history:
        if not i['mac'] in data:
            data[i['mac']] = i

    hosts = []
    for mac in data:
        if 'domain' in data[mac]:
            if data[mac]['domain'] == domain:
                hosts.append(data[mac])

    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'Status'},
    ]

    hosts = sorted(hosts, key=lambda x: x['epoch'], reverse = True)
    return flask.render_template("domain.html", title = "Domain %s" % domain, \
        active = "domains", entries = hosts, headings = headings, \
        domain = domain)

def parse_status(s):
    status = []
    if s:
        for i in s.split(","):
            try:
                status.append(int(i))
            except:
                pass
    return status

@app.route("/history/")
@app.route("/history")
def history():

    s = flask.request.args.get('status', False)
    status = parse_status(s)
    status_filter = flask.request.args.get('status_filter', False)

    # Show today as default
    now = datetime.datetime.now()
    date = now.strftime("%Y-%m-%d")

    # Use the date of the last boot request
    if len(status) > 0:
        (boot, dates) = get_boot_requests(limit = 1, status = status, status_filter='only')
    else:
        (boot, dates) = get_boot_requests(limit = 1)

    if len(boot) == 1:
        if 'epoch' in boot[0]:
            dt = epoch_to_dt(boot[0]['epoch'])
            date = dt.strftime("%Y-%m-%d")

    if len(status)>0:
        return flask.redirect('/history/%s?status=%s&status_filter=%s' % (date,s,status_filter))
    else:
        return flask.redirect('/history/%s' % date)

@app.route("/history/<date>/", methods = ['POST', 'GET'])
@app.route("/history/<date>", methods = ['POST', 'GET'])
def history_date(date):

    if not verify_date(date):
        return flask.redirect('/history')

    if flask.request.method == 'POST':
        try:
            date = flask.request.form['date']
            status = flask.request.form['status']
            status_filter = flask.request.form['status_filter']
            verify_date(date)
        except:
            pass
        else:
            try:
                int(status)
                status_filter
            except:
                return flask.redirect('/history/%s' % (date))
            else:
                return flask.redirect('/history/%s?status=%s&status_filter=%s' % (date,status,status_filter))

    # Status filter
    s = flask.request.args.get('status', False)
    status = parse_status(s)
    status_filter = flask.request.args.get('status_filter', False)

    if len(status) > 0:
        (entries, dates) = get_boot_requests(date = date, status = status, status_filter = status_filter)
    else:
        (entries, dates) = get_boot_requests(date = date)

    data = []

    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'timestamp',     'pretty': 'Timestamp'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'Status'},
    ]

    entries = sorted(entries, key=lambda x: x['epoch'], reverse = True)
    return flask.render_template("history.html", title = "Boot history", \
        active = "history", entries = entries, headings = headings, \
        status = status, dates = dates, date = date, s = s, status_filter = status_filter)

#@app.route("/boot-history/")
#@app.route("/boot-history")
#def boot_history():
#    per_page = int(app.config['ELEMENTS_PER_PAGE'])
#    page = int(flask.request.args.get('page', 1))
#
#    # Status filter
#    s = flask.request.args.get('status', False)
#    status = []
#    if s:
#        for i in list(s):
#            status.append(int(i))
#
#    boot = False
#    mac = flask.request.args.get('mac', False)
#    if mac:
#        mac = clean_mac(mac)
#        boot = get_last_boot_requests(limit = 1, mac = mac)
#
#        title = "%s boot history" % mac
#    else:
#        if int(s) == 1:
#            title = "Discovered hosts"
#        else:
#            title = "Boot history"
#
#    entries = get_last_boot_requests(first = per_page*(page-1), limit = per_page, mac = mac, status = status)
#
#    previous_page = False
#    next_page = False
#
#    if page > 1:
#        previous_page = page - 1
#
#    if len(entries) == per_page:
#        next_page = page + 1
#
#    return flask.render_template("boot-history.html", title = title, \
#        active = "history", entries = entries, mac = mac, status = int(s), \
#        boot = boot, \
#        page = page, previous_page = previous_page, next_page = next_page)

@app.route("/mac/<mac>")
@app.route("/mac/<mac>/")
def mac(mac):
    return flask.redirect('/mac/%s/configuration' % mac)

@app.route("/mac/<mac>/security", methods = ['GET', 'POST'])
def mac_security(mac):
    mac = clean_mac(mac)
    messages = []
    client = "TODO"

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            mac = flask.request.form['mac']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            mac = clean_mac(mac)

            if mac:
                target=".htaccess"
                f = app.config['DEFAULT_HOST_HTACCESS_CONFIGURATION']
                content = read_file(f)
                (data, dates) = get_boot_requests(limit = 1, mac = mac)
                if len(data) == 1:
                    data = data[0]

                log_message = "The default template was injected to the netboot security filter for %s" % (pretty_mac(mac))
                (status, output) = inject_template(content, target, mac, log_message, data)
                if status:
                    messages.append((0, "The template was successfully injected to the netboot security filter for %s" % (pretty_mac(mac))))
                else:
                    for o in output:
                        messages.append(o)

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)

    return flask.render_template("mac_security.html", \
        title = "%s security" % pretty_mac(mac), mac = mac, \
        messages = output, \
        active = "hosts", subactive = "security", cfg = cfg, boot = boot, \
        pretty_mac = pretty_mac(mac))

@app.route("/mac/<mac>/security/edit", methods = ['POST', 'GET'])
def mac_security_edit(mac):
    mac = clean_mac(mac)
    messages = []
    client = "TODO"

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            content = flask.request.form['content']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            if len(content) < 3:
                messages.append((2, "The content of the template is too short."))
                status = False

            target=".htaccess"
            (data, dates) = get_boot_requests(limit = 1, mac = mac)
            if len(data) == 1:
                data = data[0]

            if status:
                log_message = "The netboot security filter for '%s' was " \
                              "manually edited" % (pretty_mac(mac))
                (status, output) = inject_template(content, target, mac, log_message, data)
                if status:
                    messages.append((0, "The netboot security filter for %s was updated" % (pretty_mac(mac))))
                else:
                    for o in output:
                        messages.append(o)

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)
    for o in output:
        messages.append(o)

    return flask.render_template("mac_security_edit.html", \
        title = "%s netboot security filter modification" % pretty_mac(mac), mac = mac, \
        pretty_mac = pretty_mac(mac), \
        messages = messages, \
        active = "hosts", subactive = "security", cfg = cfg, boot = boot)

@app.route("/mac/<mac>/environment", methods = ['POST', 'GET'])
def mac_environment(mac):
    mac = clean_mac(mac)
    environments = get_environments()
    messages = []
    client = "TODO"
    repository = app.config['REPOSITORY']

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            _id = flask.request.form['id']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            found = False
            for e in environments:
                if e['_id'] == _id:
                    found = True

                    target="environment"
                    content = e['content']
                    (data, dates) = get_boot_requests(limit = 1, mac = mac)
                    if len(data) == 1:
                        data = data[0]

                    log_message = "The environment '%s' was injected to host %s" % (t['name'], pretty_mac(mac))
                    (status, output) = inject_template(content, target, mac, log_message, data)
                    if status:
                        messages.append((0, "The environment '%s' was successfully injected to host %s" % (t['name'], pretty_mac(mac))))
                    else:
                        for o in output:
                            messages.append(o)

            if not found:
                messages.append((2, "The environment was not found. Please re-try."))

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)
    for o in output:
        messages.append(o)

    return flask.render_template("mac_environment.html", \
        title = "%s environment" % pretty_mac(mac), mac = mac, \
        pretty_mac = pretty_mac(mac), \
        environments = environments, \
        repository = repository, \
        messages = messages, \
        active = "hosts", subactive = "environment", cfg = cfg, boot = boot)

@app.route("/mac/<mac>/environment/edit", methods = ['POST', 'GET'])
def mac_environment_edit(mac):
    mac = clean_mac(mac)
    messages = []
    client = "TODO"

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            content = flask.request.form['content']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            if len(content) < 3:
                messages.append((2, "The content of the environment is too short."))
                status = False

            target="environment"
            (data, dates) = get_boot_requests(limit = 1, mac = mac)
            if len(data) == 1:
                data = data[0]

            if status:
                log_message = "The environment for host '%s' was " \
                              "manually edited" % (pretty_mac(mac))
                (status, output) = inject_template(content, target, mac, log_message, data)
                if status:
                    messages.append((0, "The environment for host %s was updated" % (pretty_mac(mac))))
                else:
                    for o in output:
                        messages.append(o)

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)
    for o in output:
        messages.append(o)

    return flask.render_template("mac_environment_edit.html", \
        title = "%s environment modification" % pretty_mac(mac), mac = mac, \
        pretty_mac = pretty_mac(mac), \
        messages = messages, \
        active = "hosts", subactive = "environment", cfg = cfg, boot = boot)
    
@app.route("/mac/<mac>/configuration", methods = ['POST', 'GET'])
def mac_configuration(mac):
    mac = clean_mac(mac)
    templates = get_templates()
    messages = []
    client = "TODO"
    repository = app.config['REPOSITORY']

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            _id = flask.request.form['id']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            found = False
            for t in templates:
                if t['_id'] == _id:
                    found = True

                    target="ipxe"
                    content = t['content']
                    (data, dates) = get_boot_requests(limit = 1, mac = mac)
                    if len(data) == 1:
                        data = data[0]

                    log_message = "Template '%s' was injected to the netboot configuration for %s" % (t['name'], pretty_mac(mac))
                    (status, output) = inject_template(content, target, mac, log_message, data)
                    if status:
                        messages.append((0, "The template '%s' was successfully injected to the netboot configuration for %s" % (t['name'], pretty_mac(mac))))
                    else:
                        for o in output:
                            messages.append(o)

            if not found:
                messages.append((2, "The template was not found. Please re-try."))

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)
    for o in output:
        messages.append(o)

    return flask.render_template("mac_configuration.html", \
        title = "%s netboot configuration" % pretty_mac(mac), mac = mac, \
        pretty_mac = pretty_mac(mac), \
        templates = templates, \
        repository = repository, \
        messages = messages, \
        active = "hosts", subactive = "configuration", cfg = cfg, boot = boot)

@app.route("/mac/<mac>/configuration/edit", methods = ['POST', 'GET'])
def mac_configuration_edit(mac):
    mac = clean_mac(mac)
    messages = []
    client = "TODO"

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    if flask.request.method == 'POST':

        # Will inject 
        status = True
        try:
            content = flask.request.form['content']
        except:
            messages.append((3, "All required input fields are not set, please try again."))
        else:
            if len(content) < 3:
                messages.append((2, "The content of the template is too short."))
                status = False

            target="ipxe"
            (data, dates) = get_boot_requests(limit = 1, mac = mac)
            if len(data) == 1:
                data = data[0]

            if status:
                log_message = "The netboot configuration for '%s' was " \
                              "manually edited" % (pretty_mac(mac))
                (status, output) = inject_template(content, target, mac, log_message, data)
                if status:
                    messages.append((0, "The netboot configuration for %s was updated" % (pretty_mac(mac))))
                else:
                    for o in output:
                        messages.append(o)

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (cfg,output) = get_bootstrap_cfg(mac)
    for o in output:
        messages.append(o)

    return flask.render_template("mac_configuration_edit.html", \
        title = "%s netboot configuration modification" % pretty_mac(mac), mac = mac, \
        pretty_mac = pretty_mac(mac), \
        messages = messages, \
        active = "hosts", subactive = "configuration", cfg = cfg, boot = boot)

@app.route("/mac/<mac>/history")
def mac_history(mac):
    mac = clean_mac(mac)
    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    (boot, dates) = get_boot_requests(limit = 1, mac = mac)
    (history, dates) = get_boot_requests(mac)
    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'timestamp',     'pretty': 'Timestamp'},
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'Status'},
    ]

    return flask.render_template("mac_history.html", \
        title = "%s boot history" % pretty_mac(mac), mac = mac, \
        active = "hosts", subactive = "history", entries = history, \
        headings = headings, \
        pretty_mac = pretty_mac(mac), \
        boot = boot)

@app.route("/about/")
@app.route("/about")
def about():
    return flask.render_template("about.html", title = "About", \
       active = "about")

#@app.route("/bootstrap/mac-<mac>.ipxe")
#def bootstrap(mac):
#    mac = clean_mac(mac)
#    h = {'content-type' : 'text/plain'}
#
#    if not mac:
#        return flask.make_response("The given mac address is not valid", 400, h)
#
#    # Store the UUID if sent by the client
#    uuid = flask.request.args.get('uuid', None)
#    hostname = flask.request.args.get('hostname', None)
#
#    # Read the source IP address of the request
#    remote_addr = flask.request.environ.get('REMOTE_ADDR', None)
#
#    # Get host configuration
#    host = get_host_configuration(mac, uuid, remote_addr, hostname)
#
#    # Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
#    permission = get_permission(host, mac, uuid, remote_addr, hostname)
#
#    # If permission is granted, get configuration:
#    (status, ipxe) = get_ipxe_configuration(mac, permission, host)
#
#    data = {}
#    data['ipxe']        = ipxe
#    data['uuid']        = uuid
#    data['remote_addr'] = remote_addr
#    data['status']      = status
#    data['hostname']    = hostname
#
#    if 'vendor' in host:
#        data['vendor']  = host['vendor']
#
#    reverse = get_reverse_address(remote_addr)
#    if reverse:
#        data['reverse'] = reverse
#        data['domain'] = extract_domain_from_fqdn(reverse)
#
#    if not save_state(mac, data):
#        print "Unable to write state for MAC " + mac
#        return flask.make_response("Unable to write state for MAC %s" % (mac), 500, h)
#
#    return flask.make_response(ipxe, 200, h)

#def save_host_boot_configuration(mac, ipxe, htaccess):
#    status = False
#    return status

def read_file(path):
    contents = False
    try:
        fp = open(path, 'r')
    except:
        pass
    else:
        contents = fp.read()

    return contents

def get_bootstrap_cfg(mac = False):
    repository = app.config['REPOSITORY']
    cache = app.config['CACHE']
    messages = []

    if mac:
        if not verify_mac(mac):
            mac = False

    repo = gitsh.gitsh(repository, cache, log_file = app.config['LOG_FILE'])
    if os.path.isdir(cache):
        (s,out,error,ret) = repo.pull()
        if not s:
            if error:
                messages.append((3,error))
            elif out:
                messages.append((3,out))
            else:
                messages.append((3,"Unable to pull the remote repository"))
    else:
        (s,out,error,ret) = repo.clone()
        if not s:
            if error:
                messages.append((3,error))
            elif out:
                messages.append((3,out))
            else:
                messages.append((3,"Unable to clone the repository"))

    data = {}
    if os.path.isdir(cache):
        for d in os.listdir(cache):
            path = cache + "/" + d
            if os.path.isdir(path):
                m = clean_mac(d)
                if verify_mac(m):
                    if mac:
                        if mac != m:
                            continue
    
                    if not m in data:
                        data[m] = {}
                        data[m]['pretty_mac'] = pretty_mac(m)
        
                    for f in os.listdir(cache + "/" + d):
                        path = cache + "/" + d + "/" + f
                        if os.path.isfile(path):
                            if f == 'ipxe':
                                data[m]['ipxe'] = read_file(path)
                
                            elif f == '.htaccess':
                                data[m]['htaccess'] = read_file(path)
            
    return (data,messages)

#@app.route("/api/configuration/", methods = ['GET', 'POST'])
#@app.route("/api/configuration", methods = ['GET', 'POST'])
#def api_configuration():
#    out = {}
#    if flask.request.method == 'GET':
#        out = get_bootstrap_cfg()
#
#    if flask.request.method == 'POST':
#        try:
#            mac = clean_mac(flask.request.form['mac'])
#            ipxe = flask.request.form['ipxe']
#            htaccess = flask.request.form['htaccess']
#
#        except:
#            out['error'] = 'The input data was invalid'
#
#    response = flask.make_response(json.dumps(out, indent=2))
#    response.headers['cache-control'] = 'max-age=0, must-revalidate'
#    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0')

