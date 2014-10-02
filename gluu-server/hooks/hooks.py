#!/usr/bin/python

import time
import json
import os
import sys
import subprocess
import base64
import urllib2
from pyDes import triple_des, ECB, PAD_PKCS5

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
OXAUTH_FILE = "oxauth-server-1.4.1.Final.war"
OXTRUST_FILE = "oxTrust-1.4.0-SNAPSHOT.war"
RENAMED_OXAUTH_FILE = "oxauth.war"
RENAMED_OXTRUST_FILE = "oxTrust.war"
TOMCAT_FILE = "apache-tomcat-7.0.54.tar.gz"

APT_PACKAGES = ["openjdk-7-jre-headless","ldap-utils"]
KEYSTORE_PATH = '/opt/gluussl'
KEYSTORE_PASS = 'passpass'
JVM_KEYSTORE = '/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/security/cacerts'
JVM_KEYSTORE_PASS = 'changeit'
BINDPASS = 'justaplaceholder'

#ox conf constants
USE_SSL = 'true'

###############################################################################
# Functions
###############################################################################
#log function
def juju_log(level, msg):
    subprocess.call(['juju-log', '-l', level, msg])

#update apt
def apt_get_update():
    cmd_line = ['apt-get', 'update']
    return subprocess.call(cmd_line)

#oepn a port
def open_port(port=None, protocol="TCP"):
    if port is None:
        return None
    return subprocess.call(['open-port', "%d/%s" % (int(port), protocol)])

#close port
def close_port(port=None, protocol="TCP"):
    if port is None:
        return None
    return subprocess.call(['close-port', "%d/%s" % (int(port), protocol)])

#get config
def config_get(scope=None):
    try:
        config_cmd_line = ['config-get']
        if scope is not None:
            config_cmd_line.append(scope)
        config_cmd_line.append('--format=json')
        data = json.loads(subprocess.check_output(config_cmd_line))
    except:
        data = None
    finally:
        return data

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
        return False
    cmd_line = ['apt-get', '-y', 'install', '-qq']
    if isinstance(packages, list):
        cmd_line.extend(packages)
    else:
        cmd_line.append(packages)
    return subprocess.call(cmd_line)

#render a file using template and writes it
def process_template(template_name, template_vars, destination):
    tmpl_file_path = get_template(template_name)
    with open(tmpl_file_path, 'r') as fp:
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

def relation_set(keyvalues, relation_id=None):
    args = []
    if relation_id:
        args.extend(['-r', relation_id])
    args.extend(["{}='{}'".format(k, v or '') for k, v in keyvalues.items()])
    run("relation-set {}".format(' '.join(args)))

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

#oxserver function
def triple_des_encrypt(data):
    key = '123456789012345678901234'
    engine = triple_des(key, ECB, pad=None, padmode=PAD_PKCS5)
    data = data.encode('ascii')
    en_data = engine.encrypt(data)
    return base64.b64encode(en_data)

def restart():
    run(tomcat_home + "/bin/shutdown.sh")
    time.sleep(3)
    run(tomcat_home + "/bin/startup.sh")

def ox_conf_init(config):
    #oxAuth section
    oxAvars = {
        'oxhost' : get_unit_public_host(),
        'org-inum' : config['org-inum'],
        'basedn' : 'o=gluu'
    }
    process_template("oxauth-config.xml.tmpl",
                     oxAvars, tomcat_conf + "/oxauth-config.xml")

    run("cp {0} {1}".format(get_template("oxauth-errors.json"), tomcat_conf))
    run("cp {0} {1}".format(get_template("oxauth-id-gen.py"), tomcat_conf))

    oxAvars = {
        'bindpass' : triple_des_encrypt(BINDPASS),
        'ldaphost' : 'localhost',
        'port' : '1636',
        'ssl' : USE_SSL,
        'org-inum' : config['org-inum'],
        'basedn' : 'o=gluu'
    }
    process_template("oxauth-ldap.properties.tmpl",
                     oxAvars, tomcat_conf + "/oxauth-ldap.properties")

    oxAvars = {
        'org-inum' : config['org-inum'],
    }
    process_template("oxauth-static-conf.json.tmpl",
                     oxAvars, tomcat_conf + "/oxauth-static-conf.json")

    run("cp {0} {1}".format(get_template("oxauth-web-keys.json"), tomcat_conf))

    #oxTust section
    process_template("oxTrust.properties.tmpl", oxTrust_properties_vars,
                     tomcat_conf + "/oxTrust.properties")

    run("cp {0} {1}".
        format(get_template("oxTrustCacheRefresh.properties"), tomcat_conf))

    oxTvars = {
        'bindpass' : triple_des_encrypt(BINDPASS),
        'ldaphost' : 'localhost',
        'port' : '1636',
        'ssl' : USE_SSL,
        'org-inum' : config['org-inum'],
        'basedn' : 'o=gluu'
    }
    process_template("oxTrustLdap.properties.tmpl",
                     oxTvars, tomcat_conf + "/oxTrustLdap.properties")

    run("cp {0} {1}".
        format(get_template("oxTrustLogRotationConfiguration.xml"),
               tomcat_conf))

    #tomcat section
    #configure tomcat server.xml
    tomcat_server_vars = {
        'keystorefile' : keystore_file,
        'keystorepass' : KEYSTORE_PASS,
    }
    process_template("server.xml.tmpl", tomcat_server_vars,
                     tomcat_conf + "/server.xml")

def make_keystore(kf, kp, alias):
    run('keytool -genkey -alias "{2}" -keyalg RSA -storepass "{1}" \
        -keypass "{1}" -validity 90 -keystore {0} -dname "CN={2}, OU=gluu, \
        O=gluu.org, L=Austin, S=Texas, C=US"'.format(kf, kp, alias))

def export_crt(cf, kf, kp, alias):
    run('keytool -export -alias "{3}" -storepass "{2}" -keystore {1} -file {0}'
        .format(cf, kf, kp, alias))

def import_crt(cf, alias):
    run('keytool -import -alias "{1}" -storepass "{3}" -keystore {2} \
        -file {0} -noprompt'.format(cf, alias, JVM_KEYSTORE, JVM_KEYSTORE_PASS))

def install_crt():
    run("mkdir -p " + KEYSTORE_PATH)
    make_keystore(keystore_file, KEYSTORE_PASS, crt_alias)
    export_crt(crt_file, keystore_file, KEYSTORE_PASS, crt_alias)
    import_crt(crt_file, crt_alias)

def remove_crt_from_jvm(kf, kp, alias):
    run('keytool -delete -alias "{2}" -storepass "{1}" -keystore {0}'.
        format(kf, kp, alias))

###############################################################################
# Hook functions
###############################################################################
def install():
    juju_log(MSG_DEBUG, "#gluu-server installing packages")
    apt_get_update()
    apt_get_install(APT_PACKAGES)
    juju_log(MSG_DEBUG, "#gluu-server installing tomcat to /opt")
    run("tar xzf {0} -C /opt".format(get_resource(TOMCAT_FILE)))
    run('rm -rf ' + tomcat_home)
    run("mv -f /opt/apache-tomcat-7.0.54 " + tomcat_home)
    run('rm -rf ' + tomcat_webapps + '/ROOT/*')
    run('cp {} {}'.format(get_template('index.html'), tomcat_webapps + '/ROOT'))
    juju_log(MSG_DEBUG, "#gluu-server deploying war files")
    run("cp {0} {1}".format(get_resource(OXAUTH_FILE), tomcat_webapps + '/' + RENAMED_OXAUTH_FILE))
    run("cp {0} {1}".format(get_resource(OXTRUST_FILE), tomcat_webapps + '/' + RENAMED_OXTRUST_FILE))
    juju_log(MSG_DEBUG, "#gluu-server genarate and install certificate")
    install_crt()
    juju_log(MSG_DEBUG, "#gluu-server install default conf")
    ox_conf_init(config_data)
    #install init.d script
    run("cp {0} /etc/init.d/tomcat".format(get_template("tomcat.tmpl")))
    run("chmod 755 /etc/init.d/tomcat")
    run("update-rc.d tomcat defaults")

def config_changed():
    changed = False
    #oxAuth section
    if config_data['web-keys'] != '':
        run("echo " + config_data['web-keys'] + " | base64 -d > "
            + tomcat_conf + "/oxauth-web-keys.json")
        changed = True
    if config_data['py-id-gen'] != '':
        run("echo " + config_data['py-id-gen'] + " | base64 -d > "
            + tomcat_conf + "/oxauth-id-gen.py")
        changed = True
    #oxTrust section
    #....
    #restart condition
    if changed == True:
        restart()

def start():
    open_port(http_port)
    open_port(https_port)
    run(tomcat_home + "/bin/startup.sh")

def stop():
    run(tomcat_home + "/bin/shutdown.sh")
    close_port(http_port)
    close_port(https_port)
    remove_crt_from_jvm(JVM_KEYSTORE, JVM_KEYSTORE_PASS, crt_alias)
    run("rm -rf " + KEYSTORE_PATH)
    run("rm -rf " + tomcat_home)
    run("update-rc.d -f tomcat remove")
    run("rm -f /etc/init.d/tomcat")

def upgrade():
    pass

def ldapserver_relation_joined():
    juju_log(MSG_INFO, "#gluu-server ldapserver relation joined called")

def ldapserver_relation_changed():
    juju_log(MSG_INFO, "#gluu-server ldapserver relation changed called")
    ldapserver = relation_get("ldapserver")
    if ldapserver == "gluuldap":
        juju_log(MSG_INFO, "#gluu-server ldapserver relation found")
        #run("touch " + tomcat_home + "/oxserver-ldapserver-relation.lock")
        password = relation_get('password')
        port_1389 = relation_get('port1389')
        ldapvars = {
            'bindpass' : triple_des_encrypt(password),
            'ldaphost' : relation_get('hostname'),
            'port' : relation_get('port'),
            'ssl' : USE_SSL,
            'org-inum' : config_data['org-inum'],
            'basedn' : relation_get('basedn')
        }
        #oxAuth section
        process_template("oxauth-ldap.properties.tmpl",
                         ldapvars, tomcat_conf + "/oxauth-ldap.properties")
        #oxtrust section
        process_template("oxTrustLdap.properties.tmpl", ldapvars,
                         tomcat_conf + "/oxTrustLdap.properties")

        oxTrust_properties_vars['ldaphost'] = relation_get('hostname')
        oxTrust_properties_vars['ldapport'] = relation_get('port')
        process_template("oxTrust.properties.tmpl", oxTrust_properties_vars,
                         tomcat_conf + "/oxTrust.properties")
        #insert oxTrust Client dn here
        tmplvars = {
            'gluuhostname' : get_unit_public_host(),
        }
        process_template("oxTrust-client-entry.ldif.tmpl", tmplvars, TMP_DIR + "/oxTrust-client-entry.ldif")
        data = TMP_DIR + "/oxTrust-client-entry.ldif"
        run('ldapmodify -h {0} -D "cn=Directory Manager" -w {2} -p {1} -a -f {3}'.format(ldapvars['ldaphost'], port_1389, password, data))
        #restart tomcat
        restart()
    else:
        juju_log(MSG_WARNING, "#ldapserver relation not found !!!")

def ldapserver_relation_broken():
    juju_log(MSG_INFO, "#ldapserver relation broken called")

def ldapserver_relation_departed():
    juju_log(MSG_INFO, "#ldapserver relation departed called")
    ox_conf_init(config_data)
    restart()

def oxserver_relation_joined():
    juju_log(MSG_INFO, "#gluu-server oxserver relation joined called")
    with open(crt_file, 'r') as fp:
        crt_b64 = base64.b64encode(fp.read())
    relation_set({
                    'oxserver' : 'gluuserver',
                    'gluuhostname' : get_unit_public_host(),
                    'gluucrt' : crt_b64,
    })

def oxserver_relation_changed():
    juju_log(MSG_INFO, "#gluu-server oxserver relation changed called")

def oxserver_relation_broken():
    juju_log(MSG_INFO, "#gluu-server oxserver relation broken called")

def oxserver_relation_departed():
    juju_log(MSG_INFO, "#gluu-server oxserver relation departed called")


###############################################################################
# Global variables
###############################################################################
hook_name = os.path.basename(sys.argv[0])
charm_root_dir = os.environ['CHARM_DIR']

config_data = config_get()

tomcat_home = '/opt/tomcat'
tomcat_conf = tomcat_home + '/conf'
http_port = '80'
https_port = '443'
tomcat_webapps = tomcat_home + '/webapps'
keystore_file = KEYSTORE_PATH + '/' + get_unit_public_host() + '.keystore'
crt_file = KEYSTORE_PATH + '/' + get_unit_public_host() + '.crt'
crt_alias = get_unit_public_host()

oxTrust_properties_vars = {
    'oxhost' : get_unit_public_host(),
    'display-name' : config_data['display-name'],
    'org-iname' : config_data['org-iname'],
    'org-short-name' : config_data['org-short-name'],
    'appliance-iname' : config_data['appliance-iname'],
    'org-inum' : config_data['org-inum'],
    'oxTkeystore-pass' : triple_des_encrypt(config_data['oxTkeystore-pass']),
    'oxTidpsecuritykey-pass' : triple_des_encrypt(config_data['oxTidpsecuritykey-pass']),
    'oxTidpldap-pass' : triple_des_encrypt(config_data['oxTidpldap-pass']),
    'oxTvdsldap-pass' : triple_des_encrypt(config_data['oxTvdsldap-pass']),
    'oxTmysql-pass' : triple_des_encrypt(config_data['oxTmysql-pass']),
    'ldaphost' : 'localhost',
    'ldapport' : '1636',
    'ssl' : USE_SSL,
    'basedn' : 'o\=gluu'
}

###############################################################################
# Main section
###############################################################################
def main():
    juju_log(MSG_INFO, "Running {} hook".format(hook_name))
    fnmap = {
        'install' : install,
        'start' : start,
        'stop' : stop,
        'config-changed' : config_changed,
        'upgrade-charm' : upgrade,
        'ldapserver-relation-joined' : ldapserver_relation_joined,
        'ldapserver-relation-changed' : ldapserver_relation_changed,
        'ldapserver-relation-broken' : ldapserver_relation_broken,
        'ldapserver-relation-departed' : ldapserver_relation_departed,
        'oxserver-relation-joined' : oxserver_relation_joined,
        'oxserver-relation-changed' : oxserver_relation_changed,
        'oxserver-relation-broken' : oxserver_relation_broken,
        'oxserver-relation-departed' : oxserver_relation_departed
    }
    if hook_name in fnmap:
        fnmap[hook_name]()
    else:
        print "Unknown hook {}".format(hook_name)
        juju_log(MSG_WARNING, "Unknown hook {}".format(hook_name))
        raise SystemExit(1)


if __name__ == '__main__':
    raise SystemExit(main())
