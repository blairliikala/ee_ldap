<?php

$lang = array(

	'ldap_character_encode'     => 'LDAP encoding type',
	'use_ldap_account_creation' => 'Use LDAP for account creation',
	'groupID_facultystaff'		=> '<h2>Primary Role: Faculty/Staff</h2>',
	'groupID_student'			=> '<h2>Primary Role: Students</h2>',
	'groupID_alumni'			=> '<h2>Primary Role: Alumni and Gradudates</h2>',
	'groupID_guest'				=> '<h2>Primary Role: Guest</h2>',
	'groupID_edu'				=> '<h2>Primary Role: Educators</h2>',
	'groupID_discontinued'		=> '<h2>Primary Role: Discontinued</h2>',
	'groupID_editors'			=> '<h2>Primary Role: Editors</h2><p>Those who can access CP and edit entries, typically student workers.</p>',
	'groupID_affiliate'			=> '<h2>Primary Role: Affiliate</h2><p>Contractors and other.</p>',

	'first_name_field_id'       => '<h2>First Name Field</h2>',
	'last_name_field_id'        => '<h2>Last Name Field</h2>',
	'ignore_ldap_role_field_id' => '<h2>Ignore Primary Role Assigments Field</h2><p>The custom member field that flags a member not to be sorted into a group using LDAP and this add-ons sorting process.</p>',
	'ferpa_withdraw_field_id'   => '<h2>FERPA protect information field</h2><p>Used in templates for opting-out the member ID to be used in other services like stats and tracking.</p>',
	'ldap_dump_field_id'	    => '<h2>LDAP Log Dump Field</h2>',
	'protected_roles'			=> '<h2>Roles that will not use LDAP to Authenticate</h2><p>Members in this group will use EEs build-in member system.</p>',
	'ldap_affiliation_id'	    => '<h2>Affiliation ID</h2><p>LDAP Affiliation field.</p>',
	'ldap_url'					=> 'LDAP URL  <p><small>example.com:1234</small></p>',
	'exempt_from_role_changes'  => '<h2>Disable Auto Role Sorting</h2><p>Members can get in, but not automatically assigned out.',

	'yes_ldap_account_creation' => 'Yes',
	'no_ldap_account_creation'  => 'No',

	'' => ''
);
// end array