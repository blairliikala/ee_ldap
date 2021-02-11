# ee_ldap
LDAP Login support for ExpressionEngine v6, and maybe v5.

Allows EE logins and member creation via LDAP, or by the native member managment system, by member role group.  Includes sorting, overrides and custom member fields.

## Installation and Setup
Copy files like any other add-on.  On install:
Member fields are created unless they match existing field short names below:
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



## Login Process:

- For new members (not in EE yet), if the member is in LDAP but not in EE, then the member is added to the EE member database, and put into a role group based on LDAP fields.

- For existing members, if their ole is in an LDAP role group then the directory information is synced with EE.

- If the member is not in LDAP then EE's native members login takes over.


- Members can be automatically sorted based on their LDAP affiliation.
- The Super Admin (#1) is always skipped.

- Option per member to ignore group assignment changes.
- FERPA flag per member.
- Creates an LDAP Role Group.  Member Roles are added to this group to use LDAP.
