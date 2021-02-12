# ExpressionEngine LDAP Login
LDAP Login support for ExpressionEngine v6.  v5 tags are included, but untested.

EE logins and member creation via LDAP, or by the native member managment system.  Includes logins by Role Group roles, and basic member fields.

## Installation and Setup
Copy files like any other add-on.  On install:
Member fields are created unless they match existing field short names below:
"first_name"
"last_name"
"ldap_dump" (json dump of LDAP record response)

(v6) LDAP Role Group is created.

## Login Process:
By default new members authenticated over LDAP are put in the "Members" #5 role, and can be changed in the Settings.  Additional roles that need to use LDAP can be added to the LDAP Role Group.  Members can be moved into roles while still authenticating through LDAP.  Roles not in the LDAP Role Group will use the native login process.

Example:
- LDAP Role Group (LDAP)
    - Members, uses LDAP & Default member group.
    - Subscribers, uses LDAP,

- Editors Role Group, Native Login
    - Supervisors
    - Reviewers

Everyone's directory services are slightly different so there may always be additional parameters needed in the LDAP searching fucntions

Also the Super Admin (ID 1) is skipped.
