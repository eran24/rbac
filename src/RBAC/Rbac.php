<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

class Rbac {

    private $ci;
    private $db;
    private $row;

    public $is_login;
    public $errors;
    public $rules;
    public $table;
    public $register_status;
    public $validation;
    public $user_session;
    public $admin_session;

    public $user;


    public function __construct()
    {
        $this->ci = get_instance();
        $this->db = &$this->ci->db;
        $this->ci->load->model('users_model');
        $this->table = $this->ci->users_model->table;
        $this->register_status = true;
        $this->validation = true;
        $this->user_session = 'user_id';
        $this->admin_session = 'admin_id';
        $this->user = new stdClass();
        $this->user->role = null;
        $this->user->permissions = array();
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
            $this->ci->form_validation->set_rules($this->_rules('signin'));

            if ( $this->ci->form_validation->run() == FALSE ){
                $this->errors = str_ireplace("''",'',validation_errors('<li>','</li>'));
                return false;
            }
        }

        $email = $this->ci->input->post('email', true);
        $password = $this->password_hash($this->ci->input->post('password'));

        $auth = $this->ci->users_model->signin_by_email($email, $password);
        if ( $auth->num_rows() == 0 ){
            $this->errors = 'ایمیل یا گذرواژه اشتباه است';
            return false;
        }  

        // set user fileds
        $this->_set_fields( $auth->row_array() );

        // set user role
        $this->_rbac_set_role();

        // set user permissions
        $this->_rbac_set_permissions();

        // set user session
        $this->_set_session();

        //update user login date
        $this->_set_login_date();

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
        $this->ci->form_validation->set_rules($this->_rules('signup'));

        if ( $this->ci->form_validation->run() == FALSE ){
            $this->errors = str_ireplace("''",'',validation_errors('<li>','</li>'));
            return false;
        } 
        
        if( $this->register_status == false ){
            $this->errors = 'عضویت در حال حاضر غیرفعال است';
            return false;            
        }

        $email = $this->input->post('email', true);

        $fields = array(
        'first_name' => $this->ci->input->post('first_name', true),
        'last_name' => $this->ci->input->post('last_name', true),
        'password' => $this->password_hash($this->ci->input->post('password')),
        'email' => $email,
        'mobile' => $this->ci->input->post('mobile', true),
        'status' => 0,
        'avatar' => NULL,
        'register_date' => DATE,
        'login_date' => DATE
        );

        $activate_code = self::create_hash();

        $user_id = $this->ci->users_model->user_create($fields, $activate_code);

        if( !$user_id ){
            $this->errors = 'مشکلی در ثبت نام بوجود آمده است';
            return false;            
        }

        $row = $this->ci->users_model->get_by_id( $user_id );

        // set user fileds
        $this->_set_fields( $row->row_array() );

        // set user role
        $this->_rbac_set_role();

        // set user permissions
        $this->_rbac_set_permissions();

        // set user session
        $this->_set_session();

        return true;
    }




    public function is_login()
    {
        if( isset($this->user->id) ){
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
        return $this->ci->users_model->get_by_id($id);
    }



    public function set_user_active($id)
    {
        return $this->db->update($this->table, array('status' => 1), array('id' => $id));
    }


    public function is_user_active($id)
    {
        return ($this->user->status == 1)? true : false;
    }



    public function logout()
    {  
        $this->user = new stdClass();
        $this->ci->session->unset_userdata($this->ci->user_session);
    }



    private function _set_fields(&$rows)
    {
        foreach($rows as $k => $v){
            $this->user->{$k} = $v;
        }
    }



    public function get_session()
    {
        return $this->ci->session->userdata($this->ci->user_session);
    }


    private function _set_session()
    {
        $this->ci->session->set_userdata(array($this->ci->user_session => $this->user->id));        
    }




    private function _set_login_date()
    {
        $this->db->update($this->table, array('login_date' => DATE), array('id' => $this->user->id));
    }




    public function errors()
    {
        return $this->errors;
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



    private function _rules($type = 'signin')
    {
        $config = array(
            'signin' => array(
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
            ),
            'signup' => array(
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
                        'rules' => 'required|valid_email|is_unique['.$this->table.'.email]'
                ),
                array(
                        'field' => 'mobile',
                        'label' => 'موبایل',
                        'rules' => 'required|trim|integer|exact_length[11]|regex_match[/^09[0-3][0-9]{8}$/]|is_unique['.$this->table.'.mobile]'
                ),
                array(
                        'field' => 'captcha',
                        'label' => 'کد امنیتی',
                        'rules' => 'required|callback_captcha_check'
                )
            )
        );
        return $config[$type]; 
    }




    /* RBAC ========================================================================= */

    public function _rbac_set_role()
    {
        $this->user->role = $this->ci->users_model->rbac_get_role($this->user->id);
    }



    public function _rbac_set_permissions()
    {
        $rows = $this->ci->users_model->rbac_permissions_by_role($this->user->id);
        foreach($rows as $row){
            $this->user->permissions[$row['slug']] = true;
        }
        
    }



    public function rbac_has_permission($slug)
    {
        return isset( $this->user->permissions[$slug] );
    }






































//end class
}
