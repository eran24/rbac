<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

namespace rbac;


class Users extends Rbac{

    public function __construct()
    {
        parent::__construct();
        $this->table = 'users';
        $this->session_name = 'user_id';
    }



//end class
}
