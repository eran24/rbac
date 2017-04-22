<?php
namespace rbac;


class Admin extends Rbac{

    public function __construct()
    {
        parent::__construct();
        $this->table_users = 'admins';
        $this->ci->rbac_model->table = 'admins';
        $this->session_name = 'admin_id';
        $this->rbac_status = true;

        $this->init();
    }



//end class
}
