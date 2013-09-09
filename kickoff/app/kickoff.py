#!/usr/bin/env python

import os
import re
import cgi
import flask
import socket
import datetime
import hashlib
import json
import git

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
    t = datetime.datetime.strptime(str(timestamp), '%Y%m%d%H%M%S')
    return t

#def get_vendor(mac):
#    path = '/vagrant/kickoff/conf/oui.txt'
#    vendor = False
#    if not os.path.isfile(path):
#        return False
#
#    needle = mac[0:8].upper()
#    r = re.compile('^\s+%s\s+\(hex\)\s+(.*)' % needle)
#    with open(path, 'r') as f:
#        for line in f:
#            m = r.search(line)
#            if m:
#                vendor = m.group(1)
#
#    return vendor
#
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
#
## Input validation for domains
#def clean_domain(domain):
#    f = re.compile('[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*')
#    m = f.match(domain)
#    if not m:
#       domain = False
#
#    return domain

def verify_mac(mac):
    macfilter = re.compile('^[a-f0-9]{12}$')
    m = macfilter.match(mac)

    if m:
        return True
    else:
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
 
    if delta_d > 1:
        if delta_d > 6:
            date = now + datetime.timedelta(days=-delta_d, hours=-delta_h, minutes=-delta_m)
            return date.strftime('%A, %Y %B %m, %H:%I')
        else:
            wday = now + datetime.timedelta(days=-delta_d)
            return wday.strftime('%A')
    if delta_d == 1:
        return "Yesterday"
    if delta_h > 0:
        return "%dh %dm" % (delta_h, delta_m)
    if delta_m > 0:
        return "%dm %ds" % (delta_m, delta_s)
    else:
        return "%ds" % delta_s

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
#
## Use the DNS PTR to create logical groups of nodes. This method converts fqdn
## to group name.
#def extract_domain_from_fqdn(fqdn):
#    group = False
#    rule = re.compile('^[^\.]+\.(.*)')
#    res = rule.search(fqdn)
#    if res:
#        if res.group(1):
#            group = res.group(1)
#
#    return group
#
#def get_reverse_address(ip):
#    try:
#        reverse = socket.gethostbyaddr(ip)[0]
#    except:
#        reverse = False
#    return reverse


#@app.route("/")
#def index():
#    known = get_last_boot_requests(limit = 5)
#    unknown = get_last_boot_requests(limit = 5, status = [1])
#    return flask.render_template("index.html", title = "Overview", \
#        active = "overview", unknown = unknown, known = known)

@app.route("/configurations/")
@app.route("/configurations")
def configurations():
    return flask.render_template("configurations.html", \
        title = "Configurations", \
        active = "configurations")

#@app.route("/domains/")
#@app.route("/domains")
#def domains():
#    macs = get_all_mac_addresses()
#    domains = {}
#    for mac in macs:
#        reverse = False
#        boot = get_last_boot_requests(limit = 1, mac = mac)
#        if len(boot) == 1:
#            if 'reverse' in boot[0]:
#                reverse = boot[0]['reverse']
#                domain = extract_domain_from_fqdn(reverse)
#                if domain:
#                    if not domain in domains:
#                        domains[domain] = 1
#                    else:
#                        domains[domain] += 1
#
#    return flask.render_template("domains.html", title = "Domains", \
#        active = "domains", domains = domains)
#
#@app.route("/domain/<domain>")
#def domain(domain):
#    domain = clean_domain(domain)
#    if not domain:
#        return flask.make_response("The given domain is not valid", 400)
#
#    macs = get_all_mac_addresses()
#    hosts = []
#    for mac in macs:
#        reverse = False
#        boot = get_last_boot_requests(limit = 1, mac = mac)
#        if len(boot) == 1:
#            if 'reverse' in boot[0]:
#                reverse = boot[0]['reverse']
#                this_domain = extract_domain_from_fqdn(reverse)
#                if this_domain == domain:
#                    boot = get_last_boot_requests(limit = 1, mac = mac)
#                    if len(boot) == 1:
#                        data = boot[0]
#                        hosts.append(data)
#
#    return flask.render_template("domain.html", title = "Domain %s" % domain, \
#        active = "domain", hosts = hosts, domain = domain)
#
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
#
#@app.route("/mac/<mac>")
#@app.route("/mac/<mac>/")
#def mac(mac):
#    return flask.redirect('/mac/%s/history' % mac)
#
#@app.route("/mac/<mac>/security", methods = ['GET', 'POST'])
#def mac_security(mac):
#    mac = clean_mac(mac)
#    
#    if not mac:
#        return flask.make_response("The given mac address is not valid", 400)
#
#    boot = get_last_boot_requests(limit = 1, mac = mac)
#
#    if flask.request.method == 'POST':
#        try:
#            do = flask.request.form['do']
#        except:
#            pass
#        else:
#            host = get_host_configuration(mac)
#            if len(boot) == 1:
#                if do == "unlock-ip-filter":
#                    del(host['remote_addr'])
#                elif do == "unlock-uuid-filter":
#                    del(host['uuid'])
#                elif do == "unlock-hostname-filter":
#                    del(host['hostname'])
#                if do == "lock-ip-filter":
#                    host['remote_addr'] = boot[0]['remote_addr']
#                elif do == "lock-uuid-filter":
#                    host['uuid'] = boot[0]['uuid']
#                elif do == "lock-hostname-filter":
#                    host['hostname'] = boot[0]['hostname']
#    
#            save_host(mac, host)
#
#    host = get_host_configuration(mac)
#
#    return flask.render_template("mac_security.html", \
#        title = "%s security" % mac, mac = mac, \
#        active = "security", host = host, boot = boot)
#
#@app.route("/mac/<mac>/configuration")
#def mac_configuration(mac):
#    mac = clean_mac(mac)
#
#    if not mac:
#        return flask.make_response("The given mac address is not valid", 400)
#
#    boot = get_last_boot_requests(limit = 1, mac = mac)
#    host = get_host_configuration(mac)
#
#    return flask.render_template("mac_configuration.html", \
#        title = "%s configuration" % mac, mac = mac, \
#        active = "configuration", host = host, boot = boot)
#
#@app.route("/mac/<mac>/history")
#def mac_history(mac):
#    mac = clean_mac(mac)
#    if not mac:
#        return flask.make_response("The given mac address is not valid", 400)
#
#    return flask.redirect('/boot-history?mac=%s' % mac)

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

def save_host_boot_configuration(mac, ipxe, htaccess):
    status = False
    return status

def get_bootstrap_cfg():
    repository = app.config['REPOSITORY']
    cache = app.config['CACHE']

    if not os.path.isdir(cache):
        repo = git.Repo.clone_from(repository,cache)

    repo = git.Repo(cache)

    try:
        repo.remote().pull()

    except:
        print "Unable to pull remote origin"

    meta = {}
    data = {}
    
    head = repo.head.commit
    meta['tree'] = head.tree.hexsha
    meta['message'] = head.message
    meta['summary'] = head.summary
    meta['author_name'] = head.author.name
    meta['author_email'] = head.author.email
    meta['authored_date'] = head.authored_date
    meta['committed_date'] = head.committed_date

    for d in head.tree:
        if d.type == 'tree':
            mac = d.path
            if verify_mac(mac):
                if not mac in data:
                    data[mac] = {}
    
                data[mac]['tree'] = d.hexsha
    
                for f in d:
                    if f.type == 'blob':
                        if f.name == 'index.ipxe':
                            data[mac]['ipxe'] = f.data_stream.read()
    
                        if f.name == '.htaccess':
                            data[mac]['htaccess'] = f.data_stream.read()

    return meta, data

@app.route("/api/configuration/", methods = ['GET', 'POST'])
@app.route("/api/configuration", methods = ['GET', 'POST'])
def api_configuration():
    out = {}
    if flask.request.method == 'GET':
        meta, cfg = get_bootstrap_cfg()

        out['meta'] = meta
        out['cfg'] = cfg

    if flask.request.method == 'POST':
        try:
            mac = clean_mac(flask.request.form['mac'])
            ipxe = flask.request.form['ipxe']
            htaccess = flask.request.form['htaccess']

        except:
            out['error'] = 'The input data was invalid'

        else:
            if save_host_boot_configuration(mac, ipxe, htaccess):
                out['status'] = 'OK'

    response = flask.make_response(json.dumps(out, indent=2))
    response.headers['cache-control'] = 'max-age=0, must-revalidate'
    return response

@app.route("/")
def index():
    return flask.render_template("index.html", \
        title = "Overview", \
        active = "overview")

if __name__ == '__main__':
    app.run(host='0.0.0.0')

