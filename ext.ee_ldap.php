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
 * Rewritten by Blair Liikala.
 * 
 */

class Ee_ldap_ext {

  public $name           = 'LDAP Authentication';
  public $version        = '3.0.0';
  public $description    = 'Handles LDAP login / account creation.';
  public $settings_exist = 'y';
  public $docs_url       = '';
  public $settings       = array();
  protected $debug       = true;


  /*
    Assumed Defaults:
    Super Admin = 1
    Banned = 2
    Guest = 3
    Pending = 4
    Members = 5
  */

  // First time install settings.
  protected $defaults = array(
    // Possible Roles.        Existing Role ID.
    'role_ldap'            => 5,

    // Roles that will not use LDAP to authenticate. v5
    'protected_roles'            => array(),

    // RoleGroup ID.  Roles in this RoleGroup will use LDAP. v6
    'use_LDAP_rolegroup_id'      => 1,

    // Custom Member Field Ids:
    'ldap_dump_field_id'         => 0, // Log
    'first_name_field_id'        => 0, // From LDAP.
    'last_name_field_id'         => 0, // From LDAP.

    // Misc
    'ldap_url'                   => '', // ldaps://myLDAPserver.com:389
    'ldap_character_encode'      => 'Windows-1252',
    'ldap_username_attribute'    => 'uid', // uid.
    'ldap_attributes'            => '', // Comma-seperated that needs to be an array.

    'ldap_search_user'           => '',
    'ldap_search_password'       => '',
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

    /************************** Create Custom Member Fields, or get their IDs **************************/

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
        "type"          => "textarea",
        "label"         => "LDAP Log",
        "name"          => "ldap_dump",
        "id"            => "ldap_dump_field_id",
        "description"   => "Response from the LDAP query. Used for debugging.",
      ],             
    );

    $member_fields = ee('Model')->get('MemberField')->all();

    $fields = array();
    foreach($member_fields as $field)
    {
      $fields[] = $field->m_field_name;
    }    

    foreach($field_setttings as $thisfield)
    {

      if (in_array($thisfield['name'], $fields)) {

        // The field already exists, so get the current ID for the matching field and assign to the settings.
        $settings[ $thisfield['id'] ] = $member_fields->filter('m_field_name',$thisfield['name'])->first()->m_field_id;
      
      } else {

        // Create Field
        $new_field = ee('Model')->make('MemberField');
        $new_field->m_field_type        = $thisfield['type'];
        $new_field->m_field_label       = $thisfield['label'];
        $new_field->m_field_name        = $thisfield['name'];
        $new_field->m_field_description = isset($thisfield['description']) ? $thisfield['description'] : '';
        //$new_field->m_field_settings    = isset($thisfield['settings']) ? $thisfield['settings'] : array('type' => 'text');
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

        if ($role->short_name === 'role_ldap') {
          $settings['role_ldap'] = $role->group_id;
        }

      }

    } else {

      // v6
      $allRoles = ee('Model')->get('Role')->fields('short_name', 'role_id')->all();
      foreach($allRoles as $role)
      {

        if ($role->short_name === 'role_ldap') {
          $settings['role_ldap'] = $role->role_id;
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
          $settings['role_ldap'],
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

    $settings['role_ldap']         = array('r', $role_list, $this->defaults['role_ldap']);

    $settings['first_name_field_id']      = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['first_name_field_id']);
    $settings['last_name_field_id']       = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['last_name_field_id']);
    $settings['ldap_dump_field_id']       = array('s', $all_member_fields, 'm_field_id_' . $this->defaults['ldap_dump_field_id']);

    if (version_compare(APP_VER, '6.0.0', '<')) {     
      // Opt Out.  Old way.
      $settings['protected_roles']        = array('c', $role_list, array(1, 3, $this->defaults['role_educators'] ));
    }
    
    $settings['ldap_url']                  = array('i', '', $this->defaults['ldap_url']); // example.com:port
    $settings['ldap_character_encode']     = array('i', '', $this->defaults['ldap_character_encode']);
    $settings['ldap_username_attribute']   = array('i', '', $this->defaults['ldap_username_attribute']);
    $settings['ldap_attributes']           = array('i', '', $this->defaults['ldap_attributes']);
    $settings['ldap_search_user']          = array('i', '', $this->defaults['ldap_search_user']);
    $settings['ldap_search_password']      = array('i', '', $this->defaults['ldap_search_password']);                                            

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
   
    $ldap_data = array(); // Store extra user info.
    $ldap_data['username'] = ee()->input->post('username', true);

    // Keep the password separated for security so it does not accidently get printed.
    $unencrypted_password = ee()->input->post('password', false);

    // Search for member in EE database.  Will return NULL if no member is found.
    $member_obj = ee('Model')->get('Member')->filter('username', $ldap_data['username'])->first();

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
        // $ldap_data['current_primaryrole_id'] = $member_obj->group_id; // I think "group_id" is the right name.

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
    $result = $this->authenticate_user_ldap($ldap_data, $unencrypted_password);

    if ($result['authenticated'] )
    {

      // Combine the LDAP data and the login info.
      $everything = array_merge($result, $ldap_data);

      $this->debug_print('Attempting to sync or create user \''.$ldap_data['username'].'\' with EE member system...');
      $this->sync_user_details($everything, $unencrypted_password, $member_obj);

    }
    else
    {
      $this->debug_print('Could not authenticate username \''.$ldap_data['username'].'\' with LDAP');
      $this->debug_print('Will try to authenticate with local EE member system.');
    }

    if ($this->debug) {

      echo '<h5>Dump of user_info:</h5>';
      echo '<pre>';
      var_dump($ldap_data);
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

private function sync_user_details($ldap_data, $unencrypted_password, $member_obj)
{
  
  // Add random password so real passwords are not stored.  This won't work with EE yet, or I missed something.
  // $password_array   = ee()->auth->hash_password(strtolower(substr(md5(mt_rand()),0,8)));


  // If the member already exists update password, visit, IP, and group/role.
  if ($member_obj !== NULL)
  {

    //**************** Updating Password fields.

      // Native Member Model method to create hashed/salted password and clear things.
      $this->debug_print("Syncing password.");
      $member_obj->hashAndUpdatePassword($unencrypted_password);

      $this->debug_print("Updating Last Visit and IP address.");
      $member_obj->set(array(
        'last_visit'  => ee()->localize->now,
        'ip_address'  => ee()->input->ip_address(),
      ));

  } // end user ID is there.




  //********************************* EE account creation  *********************************//
  if ($member_obj === NULL) {

    $this->debug_print('Attempting to create EE user...');

    $member_obj = $this->create_ee_user($ldap_data, $unencrypted_password);

  }


  //********************************* Last Use of the Password, remove it. ****************//
  unset($ldap_data['hashed_password'], $unencrypted_password, $password_array);
 


  //********************************* Update Custom Fields. *********************************//
  if (array_key_exists('givenname', $ldap_data) AND $this->settings['first_name_field_id'])
  {

    $member_obj->{'m_field_id_'.$this->settings['first_name_field_id']} = $ldap_data['givenname'][0];

  }


  if (array_key_exists('sn', $ldap_data) AND $this->settings['last_name_field_id'])
  {

    $member_obj->{'m_field_id_'.$this->settings['last_name_field_id']} = $ldap_data['sn'][0];

  }


  if ($this->settings['ldap_dump_field_id'])
  {

    $member_obj->{'m_field_id_'.$this->settings['ldap_dump_field_id']} = json_encode($ldap_data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);

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

private function create_ee_user($ldap_data, $unencrypted_password)
{

  $this->debug_print('Creating EE account using LDAP data...');

  ee()->load->library('auth');
  $password_array = ee()->auth->hash_password($unencrypted_password);

  $data['username']             = $ldap_data['username'];
  $data['email']                = $ldap_data['mail'][0];
  $data['ip_address']           = ee()->input->ip_address();
  $data['join_date']            = ee()->localize->now;
  $data['unique_id']            = ee('Encrypt')->generateKey();
  $data['crypt_key']            = ee('Encrypt')->generateKey();
  $data['password']             = $password_array['password'];
  $data['language']             = ee()->config->item('deft_lang');
 
  if (version_compare(APP_VER, '6.0.0', '<')) {
    $data['salt'] = $password_array['salt']; // Not in use in v6.
  }

  if ( array_key_exists('givenname', $ldap_data) && array_key_exists('sn', $ldap_data) )
  {

    $data['screen_name'] = $ldap_data['givenname'][0]." ".$ldap_data['sn'][0];

  } else {

    $data['screen_name'] = $data['username'];

  }

  if (version_compare(APP_VER, '6.0.0', '<'))
  {

    $data['group_id'] = $this->settings['role_ldap'];

  } else {

    $data['role_id'] = $this->settings['role_ldap'];

  }

  // If all else fails, give it a guest role.
  if ($data['role_id'] == 0)
  {
    if (version_compare(APP_VER, '6.0.0', '<'))
    {
  
      $data['group_id'] = 3;
  
    } else {
  
      $data['role_id'] = 3;
  
    }
  }

  $this->debug_print('Inserting user with data:<pre> '.print_r($data, TRUE).'</pre>');

  // Create member using Model.
  $member = ee('Model')->make('Member');
  $member->set($data);
  $member->save();

  if ($member !== NULL)
  {
    $this->debug_print('Created EE Member');
    
    ee()->stats->update_member_stats();

    return $member;

  } else {
    $this->debug_print('EE user not created.  Exiting...');
    exit('Could not create user account for '.$ldap_data['username'].'<br/>'."\n");
  }
}

// -------------------------------------------------------




//-------------------------------------------------------
/*
  Make the LDAP connection, and bind using the user's credentials.
*/
private function authenticate_user_ldap($ldap_data, $unencrypted_password)
{
  if ($this->settings['ldap_url'] =='') {
    ee()->logger->developer('LDAP URL is empty, can not authenticate.');
    $this->debug_print('LDAP URL is empty, can not authenticate.');
    // show_error(lang('LDAP URL is empty, can not authenticate'), 403);
    return;
  }

  $ldap_array = explode("," ,$this->settings['ldap_url']); // pull out each url.

  foreach($ldap_array as $ldap)
  {

    // Should be ldaps://example.com:123, so split into 3 items by :
    $ldap_parts = explode(":",$ldap);
    $url  = $ldap_parts[0].":".$ldap_parts[1];
    $port = $ldap_parts[2];

    // Connect to LDAP.
    $connection = ldap_connect($url, $port);

    if (!$connection)
    {
      $this->debug_print('Could not connect to LDAP server: '.$ldap);
      return false;
    }

    // Bind to LDAP.
    //$ldap_search_user = $this->settings['ldap_username_attribute']."=".$ldap_data['username'];
    $ldap_search_user = $this->settings['ldap_username_attribute']."=".$ldap_data['username'].",ou=people,o=unt";


    if ( empty($this->settings['ldap_search_user']))
    {

			$this->debug_print('Binding anonymously...');
			$bind_result = @ldap_bind($connection); // this is an "anonymous" bind, typically read-only access

    } else {

      $this->debug_print('Binding with user: '.$ldap_search_user);
      $bind_result = @ldap_bind($connection , $this->settings['ldap_search_user'], $this->settings['ldap_search_password'] );
      //$bind_result = @ldap_bind($connection , $ldap_data['username'], $unencrypted_password );

    }

    $this->debug_print("Bind result: $bind_result");
    $this->debug_print("LDAP Error: " . ldap_error($connection) );

    //If the login was correct, pull the record.
    if ($bind_result){
      $this->debug_print("LDAP Bind successful, so login is correct.");
      return $this->get_user_record($connection, $ldap_search_user, $ldap_data);
      
    }

    @ldap_unbind($connection);

  }

}

//-------------------------------------------------------




// -------------------------------------------------------
/*
  After binding, searches the directory for the record and returns user's data record.
*/  

private function get_user_record($connection, $ldap_search_user, $ldap_data)
{

  $filter = "(".$this->settings['ldap_username_attribute']."=".$ldap_data['username'].")";
  $this->debug_print('...Searching the database for user record that matches '.$filter.' and returning meta...');
  
  // Actually do the search of the user, and pull the above info.
  if (empty($this->settings['ldap_attributes']))
  {

    $result = ldap_search($connection, $ldap_search_user, $filter);

  } 
  else 
  {
    // The fields to pull from the directory entry.
    // $attributes = array('givenName','mail','sn','cn','edupersonaffiliation','title'); // Not used?
    $attributes = explode(",", $this->settings['ldap_attributes']);

    $result = ldap_search($connection, $ldap_search_user, $filter, $attributes);  

  }

  if (!$result)
  {
    return false;
  }
  
  $this->debug_print("Search Result: {$result}");

  // If the search comes up empty, end and report the error.
  if (ldap_count_entries($connection, $result) != 1)
  {
    $this->debug_print('User NOT authenticated.');
    return array('authenticated' => false);
  }

  // If no error searching:

  // Get all the entries that match.
  $info = ldap_get_entries($connection, $result);
  $this->debug_print('Data for '.$info["count"].' item returned.  Should be 1.');

  // Since there could be more than one, only use the first entry it finds.
  $ldap_data = $info[0];

  // Authentication successful!
  $ldap_data['authenticated'] = true;
  $this->debug_print('Users details obtains, LDAP query complete.');

  return $ldap_data;
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
