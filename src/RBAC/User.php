<?php
namespace rbac;


class User extends Rbac{

    public function __construct()
    {
        parent::__construct();
        $this->table_users = 'users';
        $this->ci->rbac_model->table = 'users';
        $this->session_name = 'user_id';
        $this->rbac_status = false;

        $this->init();
    }



//end class
}
