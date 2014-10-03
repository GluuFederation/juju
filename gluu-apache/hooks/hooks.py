#!/usr/bin/python

import json
import os
import re
import sys
import subprocess
import base64
import urllib2

###############################################################################
# Constants
###############################################################################
MSG_CRITICAL = "CRITICAL"
MSG_DEBUG = "DEBUG"
MSG_INFO = "INFO"
MSG_ERROR = "ERROR"
MSG_WARNING = "WARNING"
TMP_DIR = "/tmp"
#resource files
OXD_FILE = "oxd-server.tar.gz"
OX_CONF_LOCATION = "/etc/apache2/mods-available/ox.conf"
HTTP_PORT = '80'
HTTPS_PORT = '443'
OXD_PORT = '8099'
OXD_HOST = '127.0.0.1'
JVM_KEYSTORE = '/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/security/cacerts'
JVM_KEYSTORE_PASS = 'changeit'

APT_PACKAGES = ["apache2","memcached","openjdk-7-jre-headless"]

###############################################################################
# Functions
###############################################################################
#log function
def juju_log(level, msg):
    subprocess.call(['juju-log', '-l', level, msg])

#update apt
def apt_get_update():
    cmd_line = ['apt-get', 'update']
    return(subprocess.call(cmd_line))

#oepn a port
def open_port(port=None, protocol="TCP"):
    if port is None:
        return(None)
    return(subprocess.call(['open-port', "%d/%s" %
        (int(port), protocol)]))

#close port
def close_port(port=None, protocol="TCP"):
    if port is None:
        return(None)
    return(subprocess.call(['close-port', "%d/%s" %
        (int(port), protocol)]))

#get config
def config_get(scope=None):
    try:
        config_cmd_line = ['config-get']
        if scope is not None:
            config_cmd_line.append(scope)
        config_cmd_line.append('--format=json')
        config_data = json.loads(subprocess.check_output(config_cmd_line))
    except:
        config_data = None
    finally:
        return config_data

#run any command
def run(command, exit_on_error=True, cwd=None):
    try:
        juju_log(MSG_DEBUG, command)
        return subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    except subprocess.CalledProcessError, e:
        juju_log(MSG_ERROR, "status=%d, output=%s" % (e.returncode, e.output))
        if exit_on_error:
            sys.exit(e.returncode)
        else:
            raise

#install apt packages
def apt_get_install(packages=None):
    if packages is None:
        return(False)
    cmd_line = ['apt-get', '-y', 'install', '-qq']
    if isinstance(packages, list):
        cmd_line.extend(packages)
    else:
        cmd_line.append(packages)
    return(subprocess.call(cmd_line))

#uninstall apt packages
def apt_get_purge(packages=None):
    if packages is None:
        return False
    cmd_line = ['apt-get', '-y', 'purge', '-qq']
    cmd_line.append(packages)
    return subprocess.call(cmd_line)

#render a file using template and writes it
def process_template(template_name, template_vars, destination):
    tmpl_file_path = get_template(template_name)
    with open(tmpl_file_path,'r') as fp:
        tmpl = fp.read()
    with open(destination, 'w') as inject_tmpl:
        inject_tmpl.write(tmpl.format(**template_vars))

def get_resource(resource_name):
    return os.path.join(charm_root_dir, "resources", resource_name)

def get_template(template_name):
    return os.path.join(charm_root_dir, "templates", template_name)

def get_unit_host():
    this_host = run("unit-get private-address")
    return this_host.strip()

def get_unit_public_host():
    this_host = run("unit-get public-address")
    return this_host.strip()

def relation_get(scope=None, unit_name=None, relation_id=None):
    j = relation_json(scope, unit_name, relation_id)
    if j:
        return json.loads(j)
    else:
        return None

def relation_json(scope=None, unit_name=None, relation_id=None):
    command = ['relation-get', '--format=json']
    if relation_id is not None:
        command.extend(('-r', relation_id))
    if scope is not None:
        command.append(scope)
    else:
        command.append('-')
    if unit_name is not None:
        command.append(unit_name)
    output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    return output or None

def download_urllib2(url=None,file_name=None):
    if url==None and file_name==None:
        return False
    fullpath = "{0}/{1}".format(DL_DIR,file_name)
    try:
        req = urllib2.urlopen(url)
        with open(fullpath, 'wb') as fp:
            while True:
                chunk = req.read(CHUNK)
                if not chunk: break
                fp.write(chunk)
                fp.flush()
    except urllib2.HTTPError, e:
        juju_log(MSG_ERROR,"HTTP Error, {0}, {1}".format(e.code,url))
        return False
    except urllib2.URLError, e:
        juju_log(MSG_ERROR,"URL Error, {0}, {1}".format(e.code,url))
        return False
    return fullpath

# gluu-apache related function
def is_apache24():
    return os.path.exists("/usr/sbin/a2enconf")

def install_modox(ox_file = ''):
    run("tar -xf {0} -C {1}".format(get_resource(ox_file), TMP_DIR))
    run("cp /tmp/bin_mod_ox/mod_ox.so /usr/lib/apache2/modules")
    run("cp /tmp/bin_mod_ox/ox.load /etc/apache2/mods-available")
    run("cp -r /tmp/bin_mod_ox/ox /var/www")
    run("rm -rf /tmp/bin_mod_ox")

def register_mod():
    run("ldconfig -n /usr/lib/apache2/modules")

def init_modox():
    conf_vars = {
        'dir' : 'ox',
        'idp' : config_data['idp'],
        'domain' : get_unit_public_host(),
        'oxdhostname' : OXD_HOST,
        'oxdport' : OXD_PORT,
    }
    process_template("ox.conf.tmpl", conf_vars, OX_CONF_LOCATION)
    index_var = {'dir' : 'ox', 'domain' : get_unit_public_host()}
    process_template("index.html.tmpl", index_var, '/var/www/ox/index.html')
    run('cp {} {}'.format(get_template('redirect.html.tmpl'), '/var/www/ox/redirect.html'))

def save_oxd_relation(data):
    jdata = json.dumps(data, indent=4)
    with open('/opt/oxd-relation.save', 'w') as fp:
        fp.write(jdata)

def read_saved_oxd_relation():
    with open('/opt/oxd-relation.save', 'r') as fp:
        data = fp.read()
    return json.loads(data)

def install_oxd():
    if os.path.isfile(os.path.join(TMP_DIR, OXD_FILE)):
        run("tar -xf {0} -C {1}".format(
            os.path.join(TMP_DIR,OXD_FILE), TMP_DIR))
        run("cp -r /tmp/oxd-server /opt")
        run("rm -rf /tmp/oxd-server")
    else:
        juju_log(MSG_ERROR,"oxd-server.tar.gz not found in /tmp")

def start_oxd():
    start_script = oxd_root_dir + '/bin/oxd-start.sh'
    # using os.system because this bash script fork a process
    os.system(start_script)

def stop_oxd():
    stop_script = oxd_root_dir + '/bin/oxd-stop.sh'
    run(stop_script)
    run("rm -rf /opt/oxd-server")
    run("update-rc.d -f oxd remove")
    run("rm -f /etc/init.d/oxd")

def restart_oxd():
    stop_script = oxd_root_dir + '/bin/oxd-stop.sh'
    run(stop_script)
    start_script = oxd_root_dir + '/bin/oxd-start.sh'
    # using os.system because this bash script fork a process
    os.system(start_script)

def import_crt(cf, alias):
    run('keytool -import -alias "{1}" -storepass "{3}" -keystore {2} \
        -file {0} -noprompt'.format(cf, alias, JVM_KEYSTORE, JVM_KEYSTORE_PASS))

def install_crt_in_jvm(base64crt, alias):
    crt = str(base64.b64decode(base64crt))
    with open(gluu_crt_file, 'w') as fp:
        fp.write(crt)
    import_crt(gluu_crt_file, alias)

def remove_crt_from_jvm(kf, kp, alias):
    run('keytool -delete -alias "{2}" -storepass "{1}" -keystore {0}'.
        format(kf, kp, alias))

#Create a self-signed certificate.
def gen_selfsigned_crt(crt_file, key_file):
    os.environ['OPENSSL_CN'] = get_unit_public_host()
    os.environ['OPENSSL_PUBLIC'] = get_unit_public_host()
    os.environ['OPENSSL_PRIVATE'] = get_unit_host()
    cmd_str = ' '.join(['openssl', 'req', '-new', '-x509', '-nodes', '-config',
         os.path.join(os.environ['CHARM_DIR'], 'data', 'openssl.cnf'),
         '-keyout', key_file, '-out', crt_file])
    run(cmd_str)

#install a self-signed certificate.
def install_apache2_selfsigned_crt():
    crt_file = '/etc/ssl/certs/ssl-cert.pem'
    key_file = '/etc/ssl/private/ssl-cert.key'
    gen_selfsigned_crt(crt_file, key_file)
    if is_apache24():
        ssl_sites = '/etc/apache2/sites-available/default-ssl.conf'
    else:
        ssl_sites = '/etc/apache2/sites-available/default-ssl'
    conf_vars = {
        'crtfile' : crt_file,
        'keyfile' : key_file,
    }
    process_template("default-ssl.tmpl", conf_vars, ssl_sites)

def http_to_https():
    if is_apache24():
        sites = '/etc/apache2/sites-available/default.conf'
    else:
        sites = '/etc/apache2/sites-available/default'
    conf_vars = {
        'domain' : get_unit_public_host(),
    }
    process_template("default.tmpl", conf_vars, sites)

def add_modox_vhost():
    data = config_data['addrel']
    juju_log(MSG_INFO, "#gluu-apache new app relation:"+ data)
    gluuidp = ''
    if os.path.isfile(gluussl + '/alias'):
        with open(gluussl + '/alias', 'r') as fp:
            gluuidp = fp.read()
    else:
        gluuidp = 'seed.gluu.org'
    try:
        reldic = json.loads(data)
    except ValueError, e:
        juju_log(MSG_DEBUG, "#gluu-apache add relation json format error")
        return
    if 'dir' in reldic:
        reldic['dir'] = re.sub('[^-a-zA-Z0-9]+', '', reldic['dir'])
        if reldic['dir'] == '':
            juju_log(MSG_CRITICAL, "#gluu-apache after validation dir name become empty. stoping vhost creation")
            return
    else: return
    if 'idp' in reldic and reldic['idp'] != '':
        juju_log(MSG_INFO, "#gluu-apache vhost idp: " + str(reldic['idp']))
    else:
        reldic['idp'] = gluuidp
    make_vhost(reldic['dir'], reldic['idp'])
    run("service apache2 restart")

def make_vhost(dirname, idp):
    base_dir = "/var/www/" + dirname
    run("mkdir -p " + base_dir)
    index_var = {'dir' : dirname, 'domain' : get_unit_public_host()}
    process_template("index.html.tmpl", index_var, base_dir + '/index.html')
    run('cp {} {}'.format(get_template('redirect.html.tmpl'), base_dir + '/redirect.html'))
    run('mkdir -p ' + base_dir + '/postlogout')
    run('cp {} {}'.format(get_template('postlogout.html.tmpl'), base_dir + '/postlogout/index.html'))
    conf_vars = {
        'dir' : dirname,
        'idp' : idp,
        'domain' : get_unit_public_host(),
        'oxdhostname' : OXD_HOST,
        'oxdport' : OXD_PORT,
    }
    ap_conf = "/etc/apache2/mods-available/" + dirname + ".conf"
    process_template("ox.conf.tmpl", conf_vars, ap_conf)
    run("ln -sf /etc/apache2/mods-available/{0} /etc/apache2/mods-enabled/".format(dirname + ".conf"))

###############################################################################
# Hook functions
###############################################################################
def install():
    juju_log(MSG_INFO, "#gluu-apache install called")
    apt_get_update()
    apt_get_install(APT_PACKAGES)
    if is_apache24():
        run("rm /etc/apache2/sites-available/*.conf")
        run("rm /etc/apache2/sites-enabled/*.conf")
    #install selfsigned crt for apache
    install_apache2_selfsigned_crt()
    # all http request redirect to https
    http_to_https()
    #install mod_ox
    ox_file = "bin_mod_ox_ap24.tar.gz" if is_apache24() else "bin_mod_ox.tar.gz"
    install_modox(ox_file)
    register_mod()
    init_modox()
    #install oxd
    run("cp {0} {1}".format(get_resource(OXD_FILE), TMP_DIR))
    install_oxd()
    run('chmod 755 ' + oxd_root_dir + '/bin/oxd-start.sh')
    run('chmod 755 ' + oxd_root_dir + '/bin/oxd-stop.sh')
    process_template('configuration.json.tmpl',
                     {'oxdport' : OXD_PORT},
                     oxd_param['oxd_conf'])
    #install oxd init.d script
    run("cp {0} /etc/init.d/oxd".format(get_template("oxd.tmpl")))
    run("chmod 755 /etc/init.d/oxd")
    run("update-rc.d oxd defaults")
    #create crt location for oxd
    run("mkdir -p " + gluussl)

def config_changed():
    juju_log(MSG_INFO, "#gluu-apache config changed called")
    process_template('log4j.xml.tmpl',
                    {'oxdlog' : config_data['oxdlog']},
                    oxd_param['oxd_log4j'])
    if os.path.isfile(oxd_param['oxd_pidfile']):
        restart_oxd()
    add_modox_vhost()

def start():
    run("a2enmod ssl")
    run("a2enmod ox")
    run("a2ensite default-ssl")
    run("a2ensite default")
    run("service apache2 restart")
    start_oxd()
    open_port(HTTP_PORT)
    open_port(HTTPS_PORT)

def stop():
    run("a2dismod ssl")
    run("a2dismod ox")
    run("a2dissite default-ssl")
    run("a2dissite default")
    run("rm /etc/apache2/mods-available/ox.conf")
    run("rm /etc/apache2/mods-available/ox.load")
    run("rm /usr/lib/apache2/modules/mod_ox.so")
    register_mod()
    run("service apache2 stop")
    stop_oxd()
    run("rm -rf "+ gluussl)
    close_port(HTTP_PORT)
    close_port(HTTPS_PORT)

def upgrade():
    pass

def gluuserver_relation_joined():
    juju_log(MSG_INFO,"#gluu-apache gluu server relation joined called")

def gluuserver_relation_changed():
    juju_log(MSG_INFO,"#gluu-apache gluu server relation changed called")
    gluuserver = relation_get("oxserver")
    if gluuserver == 'gluuserver':
        juju_log(MSG_INFO,"#gluu-apache gluu server relation found :)")
        conf_vars = {
            'dir' : 'ox',
            'idp' : relation_get('gluuhostname'),
            'domain' : get_unit_public_host(),
            'oxdhostname' : OXD_HOST,
            'oxdport' : OXD_PORT,
        }
        process_template("ox.conf.tmpl", conf_vars, OX_CONF_LOCATION)
        gluucrt = relation_get('gluucrt')
        alias = relation_get('gluuhostname')
        with open(gluussl + '/alias', 'w') as fp:
            fp.write(alias)
        install_crt_in_jvm(gluucrt, alias)
        run("service apache2 restart")
    else:
        juju_log(MSG_WARNING,"#gluu-apache gluu server relation not found !!!")

def gluuserver_relation_departed():
    with open(gluussl + '/alias', 'r') as fp:
        alias = fp.read()
    remove_crt_from_jvm(JVM_KEYSTORE, JVM_KEYSTORE_PASS, alias)
    init_modox()

def gluuserver_relation_broken():
    juju_log(MSG_INFO,"#gluu-apache gluu server relation broken called")

def website_relation_joined():
    juju_log(MSG_INFO, "#gluu-apache website relation joined called")
    relation_set({
                    'gluuapache' : get_unit_host(),
    })

###############################################################################
# Global variables
###############################################################################
hook_name = os.path.basename(sys.argv[0])
charm_root_dir = os.environ['CHARM_DIR']
config_data = config_get()
oxd_root_dir = '/opt/oxd-server'

oxd_param = {
'oxd_pidfile' : '/opt/oxd-server/pid',
'oxd_conf' : '/opt/oxd-server/conf/configuration.json',
'oxd_log4j' : '/opt/oxd-server/conf/log4j.xml',
'oxd_bcprov_lib' : '/opt/oxd-server/lib/bcprov-jdk16-1.46.jar',
'oxd_resteasy_lib' : '/opt/oxd-server/lib/resteasy-jaxrs-2.3.4.Final.jar',
'oxd_server_lib' : '/opt/oxd-server/lib/oxd-server-jar-with-dependencies.jar',
}
gluussl = '/opt/gluussl'
gluu_crt_file = gluussl + '/gluuserver.crt'

###############################################################################
# Main section
###############################################################################
def main():
    juju_log(MSG_INFO, "Running {} hook".format(hook_name))
    if hook_name == "install":
        install()

    elif hook_name == "start":
        start()

    elif hook_name == "stop":
        stop()

    elif hook_name == "config-changed":
        config_changed()
    
    elif hook_name == "gluuserver-relation-joined":
        gluuserver_relation_joined()

    elif hook_name == "gluuserver-relation-changed":
        gluuserver_relation_changed()

    elif hook_name == "gluuserver-relation-departed":
        gluuserver_relation_departed()

    elif hook_name == "gluuserver-relation-broken":
        gluuserver_relation_broken()

    elif hook_name == "website-relation-joined":
        website_relation_joined()

    elif hook_name == "upgrade-charm":
        upgrade()

    else:
        print("Unknown hook {}".format(hook_name))
        juju_log(MSG_WARNING, "Unknown hook {}".format(hook_name))
        raise SystemExit(1)



if __name__ == '__main__':
    raise SystemExit(main())

