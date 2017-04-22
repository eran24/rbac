<?php
namespace rbac;

class Rbac {

    protected $ci;
    protected $db;

    public $model_name = 'rbac_model';
    public $table_groups;
    public $table_permissions;
    public $table_roles;
    public $table_roles_permissions;
    public $table_users;

    public $errors;
    public $rules;
    
    public $rbac_status;
    public $register_status;
    public $validation;
    public $session_name;

    public static $permissions;
    public static $owners;
    public $row;

    public $validation_singin;
    public $validation_singup;


    public function __construct()
    {
        $this->ci = get_instance();
        $this->db = &$this->ci->db;
        $this->ci->load->model('rbac_model');

        $this->table_groups = 'rbac_groups';
        $this->table_permissions = 'rbac_permissions';
        $this->table_roles = 'rbac_roles';
        $this->table_roles_permissions = 'rbac_roles_permissions';
        //$this->table_users = 'rbac_admins';

        $this->rbac_status = false;
        $this->register_status = true;
        $this->validation = true;
        
        $this->session_name = 'admin_id';
        $this->row = new \stdClass();
        self::$permissions = array();
        self::$owners = array();

        // $this->validation_singin = $this->_validation_signin();
        // $this->validation_singup = $this->_validation_signup();

        //$this->init();
    }






    public function init()
    {
        if($this->is_login()){
            $this->set_login( $this->get_session() );
        }
    }






    /**
    * Authentication a user
    *
    * @param void
    * @return boolean
    */
    public function signin()
    {
        if( $this->validation == true ){
            $this->ci->form_validation->set_rules( $this->_validation_signin() );

            if ( $this->ci->form_validation->run() == FALSE ){
                $this->errors = str_ireplace("''",'',validation_errors('<li>','</li>'));
                return false;
            }
        }

        $email = $this->ci->input->post('email', true);
        $password = $this->password_hash($this->ci->input->post('password'));

        $auth = $this->ci->rbac_model->signin_by_email($email, $password);
        if ( $auth->num_rows() == 0 ){
            $this->errors = 'ایمیل یا گذرواژه اشتباه است';
            return false;
        }  
        $row = $auth->row_array();

        // set login setting
        $this->set_login( $row['id'] );

        return true;
    }



    /**
    * register a new user
    *
    * @param void
    * @return boolean
    */
    public function signup()
    {
        $this->ci->form_validation->set_rules( $this->_validation_signup() );

        if ( $this->ci->form_validation->run() == FALSE ){
            $this->errors = str_ireplace("''",'',validation_errors('<li>','</li>'));
            return false;
        } 
        
        if( $this->register_status == false ){
            $this->errors = 'عضویت در حال حاضر غیرفعال است';
            return false;            
        }

        $fields = array(
        'first_name' => $this->ci->input->post('first_name', true),
        'last_name' => $this->ci->input->post('last_name', true),
        'password' => $this->password_hash($this->ci->input->post('password')),
        'email' => $this->ci->input->post('email', true),
        'mobile' => $this->ci->input->post('mobile', true),
        'status' => 0,
        'avatar' => NULL,
        'register_date' => DATE,
        'login_date' => DATE
        );

        $activate_code = self::create_hash();

        $user_id = $this->ci->rbac_model->user_create($fields, $activate_code);

        if( !$user_id ){
            $this->errors = 'مشکلی در ثبت نام بوجود آمده است';
            return false;            
        }

        // set login setting
        $this->set_login(  $user_id );

        return $user_id;
    }





    public function is_login()
    {
        if( isset($this->row->id) ){
            return true;
        }

        $user_id = $this->get_session();
        if( is_null($user_id) ){
            return false;
        }

        $row = $this->get_by_id($user_id);
        if( $row->num_rows() > 0 ){
            return true;
        }
        else{
            return false;
        }
    }




    public function get_by_id($id)
    {
        return $this->ci->rbac_model->get_by_id($id);
    }



    public function set_user_active($id)
    {
        return $this->db->update($this->table_users, array('status' => 1), array('id' => $id));
    }


    public function is_user_active($id)
    {
        return ($this->row->status == 1)? true : false;
    }



    public function logout()
    {  
        $this->row = new \stdClass();
        $this->ci->session->unset_userdata( $this->session_name );
    }






    public function set_login($user_id)
    {
        $row = $this->ci->rbac_model->get_by_id( $user_id );

        // set user fileds
        $this->_set_fields( $row->row_array() );

        if($this->rbac_status){
            // set user permissions
            $this->_rbac_set_permissions();            
        }


        // set user session
        $this->_set_session();        
    }



    public function captcha_check($value)
    {
        return TRUE;
        //return TRUE;
        $value = strtoupper($value);
        
        $msg = 'کد امنیتی اشتباه است';
        if($value != $this->ci->session->userdata('captcha') ){
            $this->ci->form_validation->set_message('captcha_check', $msg);            
            return FALSE;
        }
        return TRUE;
    }




    public static function create_hash()
    {
        return md5(uniqid(rand()));
    }



    public function password_hash($str)
    {
        $salt =  $this->ci->config->item('encryption_key');
        return sha1($str.$salt);
    }




    public function errors()
    {
        return $this->errors;
    }


    public function get_session()
    {
        return $this->ci->session->userdata($this->session_name);
    }




    protected function _set_session()
    {
        $this->ci->session->set_userdata(array($this->session_name => $this->row->id));        
    }


    protected function _set_fields($rows)
    {
        foreach($rows as $k => $v){
            $this->row->{$k} = $v;
        }
    }


    protected function _set_login_date()
    {
        $this->db->update($this->table_users, array('login_date' => DATE), array('id' => $this->row->id));
    }




     private function _validation_signin()
     {
        return array(
                array(
                        'field' => 'email',
                        'label' => 'ایمیل',
                        'rules' => 'required|valid_email'
                ),
                array(
                        'field' => 'password',
                        'label' => 'گذرواژه',
                        'rules' => 'required|min_length[6]|max_length[20]'
                ),
                array(
                        'field' => 'captcha',
                        'label' => 'کد امنیتی',
                        'rules' => 'required|callback_captcha_check'
                )
            );
     }




     private function _validation_signup()
     {
        return  array(
                    array(
                            'field' => 'first_name',
                            'label' => 'نام',
                            'rules' => 'required|max_length[200]'
                    ),
                    array(
                            'field' => 'last_name',
                            'label' => 'نام خانوادگی',
                            'rules' => 'required|max_length[200]'
                    ),
                    array(
                            'field' => 'password',
                            'label' => 'گذرواژه',
                            'rules' => 'required|min_length[6]|max_length[20]'
                    ),
                    array(
                            'field' => 'repassword',
                            'label' => 'تکرار گذرواژه',
                            'rules' => 'required|min_length[6]|max_length[20]|matches[password]'
                    ),
                    array(
                            'field' => 'email',
                            'label' => 'ایمیل',
                            'rules' => 'required|valid_email|is_unique['.$this->table_users.'.email]'
                    ),
                    array(
                            'field' => 'mobile',
                            'label' => 'موبایل',
                            'rules' => 'required|trim|integer|exact_length[11]|regex_match[/^09[0-3][0-9]{8}$/]|is_unique['.$this->table_users.'.mobile]'
                    ),
                    array(
                            'field' => 'captcha',
                            'label' => 'کد امنیتی',
                            'rules' => 'required|callback_captcha_check'
                    )
                );
     }










    /* RBAC ========================================================================= */


    public function _rbac_set_permissions()
    {
        $rows = $this->ci->rbac_model->rbac_permissions_by_role($this->row->role_id);

        // echo '<pre>';
        // var_dump($rows->num_rows());
        // exit;
        //echo '<pre>';
        if( $rows->num_rows() > 0 ){
            foreach($rows->result_array() as $row){
                //print_r($row);
                if( strpos($row['slug'], '|') !== false ){
                    $words = explode('|', $row['slug']);
                    foreach($words as $word){
                        self::$permissions["{$row['group_slug']}/$word"] = true;
                        self::$owners["{$row['group_slug']}/$word"] = $row['owner'];
                        //echo "{$row['group_slug']}/$word \n\r";
                    }
                }
                else{
                    self::$permissions["{$row['group_slug']}/{$row['slug']}"] = true;
                    self::$owners["{$row['group_slug']}/{$row['slug']}"] = $row['owner'];                  

                    //echo "{$row['group_slug']}/$word \n\r";             
                }
            }
        }

        //print_r($this->permissions);
        // exit;
    }



    public function rbac_has_permission($slug)
    {
        return isset( self::$permissions[$slug] );
    }



    public function rbac_has_permission_owner($slug)
    {
        //var_dump(self::$permissions);

        //var_dump(self::$owners);
        return (isset( self::$owners[$slug] ) && self::$owners[$slug] == 1)?true:false;
    }



    public function get_permissions()
    {
        return self::$permissions;
    }




//end class
}
