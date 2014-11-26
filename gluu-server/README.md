# Overview

The Gluu Server is like a router for authentication and authorization.
It support SSO via OpenID Connect, and can be used by an organization to manage
both inbound and outbound authentication and authorization requirements.
Through the use of "interception scripts", system administrators can mold the
Gluu Server to solve the exact access management task at hand, including
protecting APIs and enforcing multi-factor authentication.

# Limitations

gluu server will not work in lxc container.

# About config variable 'properties'

'properties' example data format,
'{"IP":"public-ip-address-of-your-box","HOSTNAME":"your-hostname.org","ORGNAME":"your-org-name","COUNTRYCODE":"US","CITY":"Austin","STATE":"TX","EMAIL":"support@anycom.com","LDAPPASS":"abcd5678"}'

You can only set this once, after that charm will discard any change in 'properties'.
JSON value must not blank.
