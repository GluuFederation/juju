#!/usr/bin/python

import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.environ['CHARM_DIR'], 'lib'))

from charmhelpers.core import (
    hookenv,
    host,
)

hooks = hookenv.Hooks()
log = hookenv.log

SERVICE = 'gluu-server'
RIPO = 'http://repo.gluu.org/GLUU/ubuntu/pool/gluu/Gluu-CE-Repo-1.9-0.amd64.deb'

#run any command
def run(command, exit_on_error=True, cwd=None):
    try:
        log(command)
        return subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    except subprocess.CalledProcessError, e:
        log("status=%d, output=%s" % (e.returncode, e.output))
        if exit_on_error:
            sys.exit(e.returncode)
        else:
            raise


def unit_public_ip():
    this_host = run("unit-get public-address")
    return this_host.strip()


@hooks.hook('install')
def install():
    log('Installing gluu-server...')
    run('wget {} -P /tmp'.format(RIPO))
    deb = RIPO.rsplit('/',1)[1]
    run('dpkg -i /tmp/{}'.format(deb))
    run('apt-get update')
    run('apt-get -y --force-yes install gluu-server')


@hooks.hook('config-changed')
def config_changed():
    config = hookenv.config()

    for key in config:
        if config.changed(key):
            log("config['{}'] changed from {} to {}".format(
                key, config.previous(key), config[key]))

    config.save()
    #start()


@hooks.hook('upgrade-charm')
def upgrade_charm():
    log('Upgrading gluu-server')


@hooks.hook('start')
def start():
    log('Starting gluu-server...')
    #host.service_restart(SERVICE) or host.service_start(SERVICE)
    host.service_start(SERVICE)
    hookenv.open_port(80)
    hookenv.open_port(443)


@hooks.hook('stop')
def stop():
    log('Stoping gluu-server...')
    host.service_stop(SERVICE)
    hookenv.close_port(80)
    hookenv.close_port(443)


@hooks.hook('gluuserver-relation-joined')
def joined():
    log('gluu-server relation joined called...')
    rel_data  = {
                    'unit' : 'gluu-server',
                    'host' : unit_public_ip(),
                }
    hookenv.relation_set(rel_data)


@hooks.hook('gluuserver-relation-departed')
def departed():
    log('gluu-server relation departed called...')


@hooks.hook('gluuserver-relation-changed')
def changed():
    log('gluu-server relation changed called...')


@hooks.hook('gluuserver-relation-broken')
def broken():
    log('gluu-server relation broken called...')


if __name__ == "__main__":
    # execute a hook based on the name the program is called by
    hooks.execute(sys.argv)
