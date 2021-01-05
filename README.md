# ee_ldap
LDAP Login support for ExpressionEngine v6, and maybe v5.

Allows EE logins and member creation via LDAP, or by the native member managment system.

## Installation
Installs like any other add-on.  On install:
Member fields are created unless they match existing fields:
```php
first_name
last_name
ldap_affiliation
ignore_ldap_role
ferpa_withdraw
ldap_dump
```
(v6) LDAP Role Group is created.
```php
LDAP Authenticated Roles
```

- A login is first checked against LDAP.
- If the member exists and the login is valid then directory information is pulled into fields, and an optional log is made for the member.
- If the member does not exist, or the login is invaild then EE's native members login takes over.
- Members can be automatically sorted based on their LDAP affiliation.

- Option per member to ignore group assignment changes.
- FERPA flag per member.
- Creates an LDAP Role Group.  Member Roles are added to this group to use LDAP.