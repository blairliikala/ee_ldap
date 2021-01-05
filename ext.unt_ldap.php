<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/*
 * LDAP Authentication
 *
 * Based on: NCE LDAP http://code.google.com/p/ee-ldap-extension/
 * Site: http://code.google.com/p/ee-ldap-extension/wiki/Introduction
 * 
 * Based on the DesignByFront.
 * http://github.com/designbyfront/LDAP-Authentication-for-ExpressionEngine
 * 
 * Rewritten by Blair Liikala for use at UNT.
 * 
 */

/*

To Do:
- Create Roles on install.
This seems to be very complicated.

- Remove v5 code?
- Change classname to ee_ldap?

- use regex to get ldaps:// out.

*/


class Unt_ldap_ext {

  public $name           = 'LDAP Authentication 3';
  public $version        = '3.0.0';
  public $description    = 'Handles LDAP login / account creation. Written by Blair';
  public $settings_exist = 'y';
  public $docs_url       = '';
  protected $debug         = false;

  /*
    Assuming Defaults:
    Super Admin = 1
    Banned = 2
    Guest = 3
    Pending = 4
    Members = 5
  */

  protected $defaults = array(
    // Possible Roles:
    'groupID_student'            => 8,
    'groupID_facultystaff'       => 9,
    'groupID_alumni'             => 10,
    'groupID_edu'                => 11,
    'groupID_discontinued'       => 12,
    'groupID_editors'            => 6,
    'groupID_affiliate'          => 0,

    // Roles that will not use LDAP to authenticate. v5
    'protected_roles'            => array(),

    // Roles assigned to this group will use LDAP. v6
    'use_LDAP_rolegroup_id'      => 1,

    // A member will not be auto moved out of these roles.
    'exempt_from_role_changes'   => array(1, 6, 9),

    // Custom Member Field Ids:
    'ignore_ldap_role_field_id'  => 0, // A member will not be auto moved out of their current role.
    'ferpa_withdraw_field_id'    => 0, // Used in the templates to hide directory data from scripts.
    'ldap_dump_field_id'         => 0, // Log
    'ldap_affiliation_id'        => 0, // From LDAP.
    'first_name_field_id'        => 0, // From LDAP.
    'last_name_field_id'         => 0, // From LDAP.

    // Misc
    'ldap_url'                   => 'id.ldap.untsystem.edu:389',
    'use_ldap_account_creation'  => 'yes',
    'ldap_character_encode'      => 'Windows-1252',
  );



  function __construct($settings = '')
  {
    $this->settings = $settings;
    ee()->load->library('logger');
  }	

//-------------------------------------------------------
/*
          Addon Setup Things
*/        

  /*
    EE method called when the extension is activated
  */
  public function activate_extension ()
  {
   
    $settings = $this->defaults;

    /************************** Create Custom Member Fields **************************/
    $member_fields = ee('Model')->get('MemberField')->all();

    $fields = array();
    foreach($member_fields as $field) {
      $fields[] = $field->m_field_name;
    }

    // Each Field.
    $field_setttings = array(
      [
        "type"          => "text",
        "label"         => "First Name",
        "name"          => "first_name",
        "id"            => "first_name_field_id",
      ], 
      [
        "type"          => "text",
        "label"         => "Last Name",
        "name"          => "last_name",
        "id"            => "last_name_field_id",
      ],
      [
        "type"          => "text",
        "label"         => "LDAP Affiliation",
        "name"          => "ldap_affiliation",
        "id"            => "ldap_affiliation_id", // Field that stores its ID used in the script.  Must match var name.
        "description"   => "Will bypass LDAP group sorting and keep member in the set member group.",
      ], 
      [
        "type"          => "select",
        "label"         => "Ignore Role Auto Assignment",
        "name"          => "ignore_ldap_role",
        "id"            => "ignore_ldap_role_field_id", // Field that stores its ID used in the script.  Must match var name.
        "description"   => "Will bypass LDAP group sorting and keep member in the set member group.",
        "settings"      => array('value_label_pairs' => 
                            array(
                              '' => "No",
                              'yes' => "Yes Ignore auto assignment",
                            )
                            ),
      ],    
      [
        "type"          => "select",
        "label"         => "FERPA Directory Removal Flag",
        "name"          => "ferpa_withdraw",
        "id"            => "ferpa_withdraw_field_id",
        "description"   => "Set to yes automatically if the flag exists to have directory info omitted by reqeuest of the student.",
        "settings"      => array('value_label_pairs' => 
                            array(
                              '' => "No",
                              'yes' => "Yes Flag is Set",
                            )
                            ),
      ],
      [
        "type"          => "textarea",
        "label"         => "LDAP Log",
        "name"          => "ldap_dump",
        "id"            => "ldap_dump_field_id",
        "description"   => "Response from the LDAP query. Used for debugging.",
      ],             
    );

    foreach($field_setttings as $thisfield) {
      if (in_array($thisfield['name'], $fields)) {
        // The field already exists, so get the current ID for the matching field and assign to the settings.
        $settings[ $thisfield['id'] ] = $member_fields->filter('m_field_name',$thisfield['name'])->first()->m_field_id;
      } else {
        // Create Field
        $new_field = ee('Model')->make('MemberField');
        $new_field->m_field_type        = $thisfield['type'];
        $new_field->m_field_label       = $thisfield['label'];
        $new_field->m_field_name        = $thisfield['name'];
        $new_field->m_field_description = $thisfield['description'];
        $new_field->m_field_settings    = $thisfield['settings'];
        $new_field->m_field_show_fmt    = 'n'; // hide format option.
        $new_field->save(); 
        $settings[$thisfield->id] = $new_field->m_field_id;        
      }      
    }

    /**************************/


    /************************** Preset primary roles, and Role Group **************************/
    // Look for any existing roles or role groups and assign to settings.
    if (version_compare(APP_VER, '6.0.0', '<')) {

      // v5
      $allRoles = ee('Model')->get('MemberGroup')->fields('short_name', 'group_id')->all();
      foreach($allRoles as $role)
      {

        if ($role->short_name === 'alumni') {
          $settings['groupID_alumni'] = $role->group_id;
        }
        if ($role->short_name === 'faculty_staff') {
          $settings['groupID_facultystaff'] = $role->group_id;
        }
        if ($role->short_name === 'students') {
          $settings['groupID_student'] = $role->group_id;        
        }
        if ($role->short_name === 'educators') {
          $settings['groupID_edu'] = $role->group_id;        
        }
        if ($role->short_name === 'editors') {
          $settings['groupID_editors'] = $role->group_id;        
        }    
        if ($role->short_name === 'discontinued') {
          $settings['groupID_discontinued'] = $role->group_id;        
        }        
        if ($role->short_name === 'affiliate') {
          $settings['groupID_affiliate'] = $role->group_id;        
        }

      }

    } else {

      // v6
      $allRoles = ee('Model')->get('Role')->fields('short_name', 'role_id')->all();
      foreach($allRoles as $role)
      {

        if ($role->short_name === 'alumni') {
          $settings['groupID_alumni'] = $role->role_id;
        }
        if ($role->short_name === 'faculty_staff') {
          $settings['groupID_facultystaff'] = $role->role_id;
        }
        if ($role->short_name === 'students') {
          $settings['groupID_student'] = $role->role_id;        
        }
        if ($role->short_name === 'educators') {
          $settings['groupID_edu'] = $role->role_id;        
        }
        if ($role->short_name === 'editors') {
          $settings['groupID_editors'] = $role->role_id;        
        }    
        if ($role->short_name === 'discontinued') {
          $settings['groupID_discontinued'] = $role->role_id;        
        }        
        if ($role->short_name === 'affiliate') {
          $settings['groupID_affiliate'] = $role->role_id;        
        }

      }

      // Check or create Role Group
      $rolegroups = ee('Model')->get('RoleGroup')->fields('name', 'group_id')->all();
      $existing = false;
      if ($rolegroups !== NULL)
      {
        foreach($rolegroups as $group)
        {
          if ( stripos( $group->name, "dap" ) )
          {
            $settings['use_LDAP_rolegroup_id'] = $group->group_id;
            $existing = true;
          }
        }
      }

      if ($existing === false)
      {
        // Create Role Group and add roles to the group.
        $group_data = array(
          "name" => "LDAP Authenticated Roles",
        );

        // Initial dataset of roles that will use LDAP.
        $role_members = array(
          1,
          $settings['groupID_alumni'],
          $settings['groupID_facultystaff'],
          $settings['groupID_student'],
          $settings['groupID_editors'],
          $settings['groupID_discontinued'],
          $settings['groupID_affiliate'],
        );

        // Remove Empty roles.
        foreach($role_members as $key=>$role_id)
        {
          if (!$role_id OR $role_id ==='') {
            unset($role_members[$key]);
          }
        }
        
        $role_group = ee('Model')->make('RoleGroup');
        $role_group->Roles = ee('Model')->get('Role', $role_members)->all();
        $role_group->set($group_data);
        $role_group->save();
      }

    }

    /**************************/


    /************************** Install the Extension **************************/
    $hooks = array(
      'login_authenticate_start'  => 'login_authenticate_start',
      'member_member_login_start' => 'member_member_login_start'
    );

    foreach ($hooks as $hook => $method)
    {
      ee()->db->query(ee()->db->insert_string('exp_extensions',
        array(
          'extension_id' => '',
          'class'        => __CLASS__,
          'method'       => $method,
          'hook'         => $hook,
          'settings'     => serialize($settings),
          'priority'     => 10,
          'version'      => $this->version,
          'enabled'      => "y"
        )
      ));
    }

  }

  /*
    EE method called when the extension is updated
  */
  public function update_extension($current = '')
  {

    if ($current < '3.0')
    {
        // Update to version 2.0
    }
    ee()->db->where('class', __CLASS__);
    ee()->db->update(
                'extensions',
                array('version' => $this->version)
    );

  }

  /*
    EE method called when the extension is disabled
  */
  public function disable_extension()
  {
    ee()->db->where('class', __CLASS__);
    ee()->db->delete('extensions');    
  }

  /*
    Configuration for the extension settings page
  */
  public function settings()
  {


    if (version_compare(APP_VER, '6.0.0', '<')) {
      
      // v5 Get Member Groups.
      $role_list = ee('Model')->get('MemberGroup')->fields('group_id','name')->all()->getDictionary('group_id','name');

    } else {

      // v6 Get Member Groups.
      $role_list = ee('Model')->get('Role')->fields('role_id','name')->all()->getDictionary('role_id','name');
      $role_list["0"] = "Off";

      // Get Role Groups. array(1 =>'super admin' ...etc)
      $rolegroups = ee('Model')->get('RoleGroup')->fields('name', 'group_id')->all()->getDictionary('group_id', 'name');

      // Opt In.  new way using role group.
      $settings['use_LDAP_rolegroup_id']      = array('r', $rolegroups, array($this->defaults['use_LDAP_rolegroup_id'] ));

    }

    // Remove Super Admin from list.
    unset($role_list[1]);

    // Get custom member fields for settings options.
    $all_member_fields = ee('Model')->get('MemberField')->fields('m_field_label','m_field_id')->all()->getDictionary('m_field_id', 'm_field_label');
    $all_member_fields["0"] = "Off";
    
    $settings['groupID_facultystaff']		 = array('r', $role_list, $this->defaults['groupID_facultystaff']);
    $settings['groupID_student']			   = array('r', $role_list, $this->defaults['groupID_student']);
    $settings['groupID_alumni']				   = array('r', $role_list, $this->defaults['groupID_alumni']);
    $settings['groupID_edu']             = array('r', $role_list, $this->defaults['groupID_edu']);
    $settings['groupID_discontinued']    = array('r', $role_list, $this->defaults['groupID_discontinued']);
    $settings['groupID_affiliate']       = array('r', $role_list, $this->defaults['groupID_affiliate']);
    $settings['groupID_editors']         = array('r', $role_list, $this->defaults['groupID_editors']);

    $settings['first_name_field_id']        = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['first_name_field_id']);
    $settings['last_name_field_id']         = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['last_name_field_id']);
    $settings['ignore_ldap_role_field_id']  = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['ignore_ldap_role_field_id']);
    $settings['ferpa_withdraw_field_id']    = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['ferpa_withdraw_field_id']);
    $settings['ldap_dump_field_id']         = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['ldap_dump_field_id']);
    $settings['ldap_affiliation_id']        = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['ldap_affiliation_id']);
    $settings['exempt_from_role_changes']   = array('c', $role_list, $this->defaults['exempt_from_role_changes'] );

    if (version_compare(APP_VER, '6.0.0', '<')) {     
      // Opt Out.  Old way.
      $settings['protected_roles']            = array('c', $role_list, array(1, 3, $this->defaults['groupID_edu'] ));
    }
    
    $settings['ldap_url']                   = array('i', '', $this->defaults['ldap_url']); // example.com:port
    $settings['ldap_character_encode']      = array('i', '', $this->defaults['ldap_character_encode']);
    $settings['use_ldap_account_creation'] 	= array('r', array('yes' => 'yes_ldap_account_creation',
                                                              'no'  => 'no_ldap_account_creation'),
                                                    $this->defaults['use_ldap_account_creation']);


    // Remove the ldaps:// if it was included by accident. Probably should use regex.
    $ldap_url = explode(':', $settings['ldap_url']);
    if ( count($ldap_url) > 2 ) {
      $ldap_url[1] = ltrim($ldap_url[1], "//");
      unset($ldap_url[0]);
      $setttings['ldap_url'] = $ldap_url;
    }                                              

    return $settings;
  }

  /*
    Called by the member_member_login_start hook
  */
  public function member_member_login_start()
  {
    return $this->login_authenticate_start();
  }
//-------------------------------------------------------




//-------------------------------------------------------
  /*
    Where it all begins!
  */
  public function login_authenticate_start()
  {
   
    $user_info = array(); // Store extra user info.
    $user_info['username'] = ee()->input->post('username', true);

    // Keep the password separated for security so it does not accidently get printed.
    $unencrypted_password = ee()->input->post('password', false);

    // Search for member in EE database.  Will return NULL if no member is found.
    $member_obj = ee('Model')->get('Member')->filter('username', $user_info['username'])->first();

    // Get member's info from the EE database, and add it to the user_info array.
    if ($member_obj === NULL) {

      $this->debug_print("No EE username found in local user database.  Assuming this is a new user.");

    } else  {   

      // Get the existing member's ID from EE.
      $this->debug_print( 'Initial user search found user ID: '.$member_obj->getId() );

      // if ( $member_obj->isSuperAdmin() )  Won't update Password for staff with super admin accounts.
      if ( $member_obj->getId() == 1) 
      {
        $this->debug_print('<span class="color:red">This user is the Super Admin primary account and does not use LDAP (never should!). Bypassing LDAP and exiting this add-on to use standard EE login process.</span>');
        if ($this->debug) {
          exit();
        }
        return;
      }


      // Role Groups to skip LDAP and use EE member.  Guests & Educators.
      if (version_compare(APP_VER, '6.0.0', '<')) {     
        //v5
        // $user_info['current_primaryrole_id'] = $member_obj->group_id; // I think "group_id" is the right name.

        if ( in_array($member_obj->group_id, $this->settings['protected_roles']) )
        {
          $this->debug_print('<span class="color:red">This members group ID does not use LDAP to check login, so exiting this Extension and using normal EE login proceses.</span>');
          if ($this->debug) {
            exit();
          }
          return;          
        }

      } else {

        // v6
        // $user_info['current_primaryrole_id'] = $member_obj->PrimaryRole->getId();

        // Get all the member's current roles in an array.
        foreach($member_obj->getAllRoles() as $role)
        {
          $member_role_ids[] = $role->role_id; 
        }

        // Get All the roles under the LDAP role group.
        $ldap_role_group = ee('Model')->get('RoleGroup', $this->settings['use_LDAP_rolegroup_id'])->first();
        foreach($ldap_role_group->Roles as $role)
        {
          $ldap_role_ids[] = $role->role_id;
        }

        // See if any of the roles match.
        foreach($member_role_ids as $member_role_id)
        {
          if ( !in_array($member_role_id, $ldap_role_ids) ) {
            $this->debug_print('<span class="color:red">This members group ID does not use LDAP to check login, so exiting this Extension and using normal EE login proceses.</span>');
            if ($this->debug) {
              exit();
            }
            return;          
          }
        }        

      }

    }


    // Get LDAP info to authenticate password, and either create new member or sync exisiting member.
    $result = $this->authenticate_user_ldap($user_info, $unencrypted_password);

    if ($result['authenticated'])
    {
      // Combine the LDAP data and the login info.
      $everything = array_merge($result, $user_info);

      $this->debug_print('Attempting to sync or create user \''.$user_info['username'].'\' with EE member system...');
      $this->sync_user_details($everything, $unencrypted_password, $member_obj);
    }
    else
    {
      $this->debug_print('Could not authenticate username \''.$user_info['username'].'\' with LDAP');
      $this->debug_print('Will try to authenticate with local EE member system.');
    }

    if ($this->debug) {

      echo '<h5>Dump of user_info:</h5>';
      echo '<pre>';
      var_dump($user_info);
      echo'</pre>';

      echo '<h5>Dump of LDAP result:</h5>';
      echo '<pre>';
      var_dump($result);
      echo '</pre>';

    }
    $this->debug_print('Script Complete.');

    if ($this->debug) {
      exit();
    }

    return; // End of LDAP Script.

  }
//-------------------------------------------------------



//-------------------------------------------------------
/*
  Update password, and custom fields.
  Create EE user too....?
*/

private function sync_user_details($user_info, $unencrypted_password, $member_obj)
{
  
  // Add random password so real passwords are not stored.  This won't work with EE yet.
  // $password_array   = ee()->auth->hash_password(strtolower(substr(md5(mt_rand()),0,8)));


  // If the member already exists update password, visit, IP, and group/role.
  if ($member_obj !== NULL)
  {

    //**************** Updating Password fields.

      // Native Member Model method to create hashed/salted password and clear things.
      $this->debug_print("Syncing password.");
      $member_obj->hashAndUpdatePassword($unencrypted_password);
      //$member_obj->password = $password_array['password'];
      //$member_obj->salt     = $password_array['salt']; // Depreciated in V6

      $this->debug_print("Updating Last Visit and IP address.");
      $member_obj->set(array(
        'last_visit'  => ee()->localize->now,
        'ip_address'  => ee()->input->ip_address(),
        //'ip_address'  => ee()->session->userdata['ip_address']; ?
      ));

    //**************** Update Groups ***************/
    $member_ignore_role_assignments = $member_obj->{'m_field_id_' . $this->settings['ignore_ldap_role_field_id']};

    if ($member_ignore_role_assignments === "yes") {

      $this->debug_print("Member HAS the ignore role assigment flag enabled. <strong>Not changing roles.</strong>");

    } else {
      
      $this->debug_print("Member does not have ignore role assignment flag enabled.");
      
      if (version_compare(APP_VER, '6.0.0', '<')) {

        $allRoleIds = array( $member_obj->group_id ); //v5

      } else {

        // Get all role IDs the member is in.
        foreach($member_obj->getAllRoles() as $role) {
          $allRoleIds[] = $role->role_id;
        }

      }

      // If any match, then the member should be excluded from auto group assignments.
      $exempt = false;
      foreach($this->settings['exempt_from_role_changes'] as $role) {
        if ( in_array($role, $allRoleIds) ) {
          $this->debug_print("Member Role Group matches an except: ".$role);
          $exempt = true;
        }
      }

      if ($exempt === true) {

        $this->debug_print("<strong>Member is in a role group that bypasses automatic group changes.</strong>");

      } else {

        $this->debug_print('Determining roles....');

        $new_group_id = $this->get_primaryrole_id_assignment($user_info);

        if (version_compare(APP_VER, '6.0.0', '>')) {
          //v6
          if ( (int) $new_group_id !== (int) $member_obj->role_id) {
            $this->debug_print("<strong>Member role changing from ".$member_obj->role_id." to ".$new_group_id."</strong>");
            $member_obj->role_id = $new_group_id;  // v6+
          }
          
        } else {
          //v5
          if ( (int) $new_group_id !== (int) $member_obj->group_id) {
            $this->debug_print("<strong>Member role changing from ".$member_obj->group_id." to ".$new_group_id."</strong>");
            $member_obj->group_id = $new_group_id; // v5
          }
          
        }

      }

    }

  } // end user ID is there.




  //********************************* EE account creation  *********************************//
  if ($this->settings['use_ldap_account_creation'] === 'yes' && $member_obj === NULL) {

    $this->debug_print('Attempting to create EE user...');

    $member_obj = $this->create_ee_user($user_info, $unencrypted_password);

  }


  //********************************* Last Use of the Password, remove it. ****************//
  unset($user_info['hashed_password'], $unencrypted_password, $password_array);
 


  //********************************* Update Custom Fields. *********************************//
  if (array_key_exists('givenname', $user_info) AND $this->settings['first_name_field_id'] !='0') {

    $member_obj->{'m_field_id_'.$this->settings['first_name_field_id']} = $user_info['givenname'][0];

  }


  if (array_key_exists('sn', $user_info) AND $this->settings['last_name_field_id'] !='0') {

    $member_obj->{'m_field_id_'.$this->settings['last_name_field_id']} = $user_info['sn'][0];

  }


  if (array_key_exists('publishstudentinfo', $user_info) AND $this->settings['ferpa_withdraw_field_id'] !='0') {
  
    $member_obj->{'m_field_id_'.$this->settings['ferpa_withdraw_field_id']} = $user_info['publishstudentinfo'][0];

  } else {
    $member_obj->{'m_field_id_'.$this->settings['ferpa_withdraw_field_id']} = ''; // Set to no, or blank.
  }


  if (array_key_exists('edupersonaffiliation', $user_info) AND $this->settings['ldap_affiliation_id'] !='0') {

    $member_obj->{'m_field_id_'.$this->settings['ldap_affiliation_id']} = $user_info['edupersonaffiliation'][0];
    
  }


  if ($this->settings['ldap_dump_field_id'] != '0') {

    $member_obj->{'m_field_id_'.$this->settings['ldap_dump_field_id']} = json_encode($user_info, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);

  }
  /*********************************/

  $result = $member_obj->validate();

  if ($result->failed())
  {
      var_dump($result);
      return;
  }

  $member_obj->save();

  return;

}
// -------------------------------------------------------




// -------------------------------------------------------
/*
  Create user in EE database.
  - Figure out what group ID to assign.
  - Return a freshly made member ID.
*/

private function create_ee_user($user_info, $unencrypted_password)
{

  $this->debug_print('Creating EE account using LDAP data...');

  ee()->load->library('auth');
  $password_array = ee()->auth->hash_password($unencrypted_password);

  $data['username']         		= $user_info['username'];
  $data['email']            		= $user_info['mail'][0];
  $data['ip_address']       		= ee()->input->ip_address();
  $data['join_date']        		= ee()->localize->now;
  $data['unique_id']        		= ee('Encrypt')->generateKey();
  $data['crypt_key']				    = ee('Encrypt')->generateKey();
  $data['password']             = $password_array['password'];
 
  if (version_compare(APP_VER, '6.0.0', '<')) {
    $data['salt'] = $password_array['salt']; // Not in use in v6.
  }

  if ( array_key_exists('givenname', $user_info) && array_key_exists('sn', $user_info) )
  {

    $data['screen_name'] = $user_info['givenname'][0]." ".$user_info['sn'][0];

  } else {

    $data['screen_name'] = $data['username'];

  }

   if (version_compare(APP_VER, '6.0.0', '<')) {

    $data['group_id'] = $this->get_primaryrole_id_assignment($user_info);

  } else {

    $data['role_id'] = $this->get_primaryrole_id_assignment($user_info);

  }

  $this->debug_print('Inserting user with data:<pre> '.print_r($data, TRUE).'</pre>');

  // Create member using Model.
  $member = ee('Model')->make('Member');
  $member->set($data);
  $member->validate();
  $member->save();

  if ($member !== NULL)
  {
    $this->debug_print('Created EE Member');
    
    ee()->stats->update_member_stats();

    return $member;

  } else {
    $this->debug_print('EE user not created.  Exiting...');
    exit('Could not create user account for '.$user_info['username'].'<br/>'."\n");
  }
}

// -------------------------------------------------------




// -------------------------------------------------------
/*
  Figure out the Primary Role based on LDAP affiliation.
  ...Because it just isn't that simple...
*/

private function get_primaryrole_id_assignment ($user_info)
{

  $discontinued     = false;
  $current_student  = false;
  $faculty          = false;
  $hourly_worker    = false;
  $alumni           = false;
  $staff            = false;
  $affiliate        = false;

  if( array_key_exists('edupersonaffiliation', $user_info) && isset($user_info['edupersonaffiliation']) ) {

    if(in_array("student", $user_info['edupersonaffiliation'])) {
      $current_student = true;
    }

    if(in_array("faculty", $user_info['edupersonaffiliation'])) {
      $faculty = true;
    }

    if(in_array("staff", $user_info['edupersonaffiliation'])) {
      $staff = true;
    }

    if(in_array("alum", $user_info['edupersonaffiliation'])) {
      $alumni = true;
    }
    if(in_array("affiliate", $user_info['edupersonaffiliation'])) {
      $affiliate = true;
    }

  } else {
    $discontinued = true;
  }

  if( array_key_exists('untjobtitle', $user_info) && isset($user_info['untjobtitle']) ) {
    if(in_array("Student Assistant", $user_info['untjobtitle'])) {
      $hourly_worker = true;
    }
  }

  $this->debug_print('<p><strong>Group Logic:</strong>');
  $this->debug_print("Discontinued: ".$discontinued);
  $this->debug_print("Current Student: ".$current_student);
  $this->debug_print("Faculty: ".$faculty);
  $this->debug_print("Hourly: ".$hourly_worker);
  $this->debug_print("Hourly: ".$alumni);
  $this->debug_print("Staff: ".$staff."</p>");


  switch (true) {

    case ($discontinued AND $this->settings['groupID_discontinued'] !='0' ):
      $this->debug_print('Returning Role of 12');
      return $this->settings['groupID_discontinued'];
      //return 12;
      break;

    case ($current_student AND $this->settings['groupID_student'] !='0' ) :
      $this->debug_print('Returning Role of '.$this->settings['groupID_student']);
      return $this->settings['groupID_student'];
      break;

    case ($faculty AND $this->settings['groupID_facultystaff'] !='0') :
      $this->debug_print('Returning Role of '.$this->settings['groupID_facultystaff']);
      return $this->settings['groupID_facultystaff'];
      break;

    case ($hourly_worker AND $this->settings['groupID_student'] !='0') :
      $this->debug_print('Returning Role of '.$this->settings['groupID_student']);
      return $this->settings['groupID_student'];
      break;        

    case ($alumni AND $this->settings['groupID_alumni'] !='0') :
      $this->debug_print('Returning Role of '.$this->settings['groupID_alumni']);
      return $this->settings['groupID_alumni'];
      break;

    case ($staff AND $this->settings['groupID_facultystaff'] !='0') :
      $this->debug_print('Returning Role of '.$this->settings['groupID_facultystaff']);
      return $this->settings['groupID_facultystaff'];
      break;

    case ($affiliate AND $this->settings['groupID_affiliate'] !='0') :
      $this->debug_print('Returning Role of '.$this->settings['groupID_affiliate']);
      return $this->settings['groupID_affiliate'];
      break;      

    default;
      $this->debug_print('Returning Role of default of 3, "guest."');
      return 3; // Defaulted to Guest.  Guest should always be 3.
      break;

  }

}
//-------------------------------------------------------




//-------------------------------------------------------
/*
  Make the LDAP connection, and bind using the user's credentials.
*/
private function authenticate_user_ldap($user_info, $unencrypted_password)
{
  if ($this->settings['ldap_url'] =='') {
    ee()->logger->developer('LDAP URL is empty, can not authenticate.');
    // show_error(lang('LDAP URL is empty, can not authenticate'), 403);
    return;
  }

  $login_settings        = array();
  $login_settings['ds']  = ldap_connect("ldaps://".$ldap_url_array[0], $ldap_url_array[1]);
  $login_settings['dn']  = "uid=".$user_info['username'].",ou=people,o=unt";

  $bind_result = @ldap_bind($login_settings['ds'] , $login_settings['dn'] , $unencrypted_password );

  $this->debug_print("Bind result: $bind_result");
  $this->debug_print("LDAP Error: " . ldap_error($login_settings['ds']) );

  //If the login was correct, assume they were a student with the correct login.
  if ($bind_result){
    $this->debug_print("LDAP Bind successful, so login is correct.");
    return $this->greedy_ldap_grab($login_settings, $user_info);
    
  }

  @ldap_unbind($login_settings['ds']);

}

//-------------------------------------------------------




// -------------------------------------------------------
/*
  After binding, searches the directory for the record and returns user's data record.
*/  

private function greedy_ldap_grab($login_settings, $user_info)
{

  //$filter = "(cn={$user_info['username']})";
  $filter = "(uid=".$user_info['username'].")";
  $this->debug_print('...Searching the database for user record that matches '.$filter.' and returning meta...');
  
  // The fields to pull from the directory entry.
  // $attributes = array('givenName','mail','sn','cn','edupersonaffiliation','title'); // Not used?

  // Actually do the search of the user, and pull the above info.
  $result = ldap_search($login_settings['ds'], $login_settings['dn'], $filter);
  $this->debug_print("Search Result: {$result}");

  // If the search comes up empty, end and report the error.
  if (ldap_count_entries($login_settings['ds'], $result) != 1)
  {
    $this->debug_print('User NOT authenticated.');
    return array('authenticated' => false);
  }

  // If no error searching:

  // Get all the entries that match.
  $info = ldap_get_entries($login_settings['ds'], $result);
  $this->debug_print('Data for '.$info["count"].' item returned.  Should be 1.');

  // Since there could be more than one, only use the first entry it finds.
  $user_info = $info[0];

  // Authentication successful!
  $user_info['authenticated'] = true;
  $this->debug_print('Users details obtains, LDAP query complete.');

  return $user_info;
}
//-------------------------------------------------------




//-------------------------------------------------------
  /*

    Print Debug messages to the webpage.  Accepts strings or arrays.

  */

  private function debug_print($message, $br="<br/>\n")
  {
    if ($this->debug)
    {
      if (is_array($message))
      {
        print('<pre>');
        print_r($message);
        print('</pre>'.$br);
      }
      else
      {
        print($message.' '.$br);
      }
    }
  }


  private function ldap_encode($text)
  {
    return iconv("UTF-8", $this->settings['ldap_character_encode'], $text);
  }


}
// END CLASS unt_ldap