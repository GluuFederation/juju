#Overview

gluu-server is a combination of oxAuth and oxTrust using tomcat7 container.
oxAuth - OAuth 2 server and client, OpenID Connect & UMA implementation.
oxTrust - GUI for centrally managing authentication, authorization and identity using oxAuth.
gluu-server need to make a relation to a gluu-ldap to work.

#Usage

To deploy gluu-server
```
juju deploy gluu-server
```
test setup:
```
url: https://ip_or_dns/oxTrust
username: admin
password: passpass
```

# Configuration

web-keys : set a base64 encoded string
py-id-gen : set a base64 encoded string
you should set other config variables before deployment
```
example: juju deploy --config myconfig.yaml gluu-server
```

#Relation

to make relation with gluu-opendj
```    
juju add-relation gluu-opendj gluu-server
```

# Contact

shouro@gluu.org
