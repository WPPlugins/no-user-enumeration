<?php
/*
 * Plugin Name: No User Enumeration
 * Description: Disallow user enumeration for security. Also, in administrators posts hide the username unless it have a nickname.
 * Version: 1.2
 * Author: Carlos Montiers Aguilera
 */
require_once (trailingslashit(ABSPATH) . 'wp-includes/pluggable.php');

class T800_NoUserEnumeration
{

    private static $_instance = null;

    private function __construct()
    {
        // No constructor
    }

    private static function getInstance()
    {
        if (self::$_instance === null) {
            self::$_instance = new self();
        }
        return self::$_instance;
    }

    public function filtro_ocultar_desactivacion($actions, $plugin_file, $plugin_data, $context)
    {
        if ($plugin_file === plugin_basename(__FILE__)) {
            unset($actions['deactivate']);
            unset($actions['delete']);
        }
        return $actions;
    }

    public function filtro_autor_admin_ocultar_username($display_name)
    {
        $user = self::traer_usuario_por_login($display_name);
        if (user_can($user, 'administrator')) { // admin without nickname
            if (strcasecmp($user->display_name, $display_name) !== 0) {
                return $user->display_name; // display username that is not equal user_login
            } else {
                return '';
            }
        } else {
            return $display_name;
        }
    }

    public function filtro_autor_admin_ocultar_url($link)
    {
        $nicename = ltrim(strrchr(rtrim($link, '/'), '/'), '/');
        
        $user = self::traer_usuario_por_nicename($nicename);
        if (user_can($user, 'administrator')) { // admin url page
            return '';
        } else {
            return $link;
        }
    }

    public function filtro_remover_autor_de_clases($classes)
    {
        $some_removed = false;
        reset($classes);
        while (($k = key($classes)) !== null) {
            if (strpos($classes[$k], 'comment-author-') === 0) {
                unset($classes[$k]);
                $some_removed = true;
            }
            next($classes);
        }
        if ($some_removed) {
            $classes = array_values($classes);
        }
        return $classes;
    }

    public function filtro_remover_autor_de_boton_responder($link, $args, $comment, $post)
    {
        $link = preg_replace('/aria-label=\'.+\'/', 'aria-label=\'\'', $link);
        return $link;
    }

    public function traer_usuario_por_nicename($nicename)
    {
        global $wpdb;
        
        if (! $user = $wpdb->get_row($wpdb->prepare("SELECT `ID` FROM $wpdb->users WHERE `user_nicename` = %s", $nicename))) {
            return false;
        }
        
        return get_user_by('id', $user->ID);
    }

    public function traer_usuario_por_login($login)
    {
        return get_user_by('login', $login);
    }

    public static function from_archives()
    {
        if (array_key_exists('author', $_REQUEST) && ($_REQUEST['author'] !== '')) {
            wp_die('Forbidden', 403);
        }
    }

    public static function from_posts()
    {
        $instance = self::getInstance();
        add_filter('the_author', array(
            $instance,
            'filtro_autor_admin_ocultar_username'
        ), 10, 1);
        add_filter('get_comment_author', array(
            $instance,
            'filtro_autor_admin_ocultar_username'
        ), 10, 1);
        add_filter('author_link', array(
            $instance,
            'filtro_autor_admin_ocultar_url'
        ), 10, 1);
        add_filter('comment_class', array(
            $instance,
            'filtro_remover_autor_de_clases'
        ), 10, 1);
        add_filter('comment_reply_link', array(
            $instance,
            'filtro_remover_autor_de_boton_responder'
        ), 10, 4);
    }

    public static function from_rest_api()
    {
        $header_error_403 = 'HTTP/1.1 403 Forbidden';
        $header_content_type_json = 'Content-Type: application/json; charset=UTF-8';
        
        // rest api v2 merged in v4.7
        if (preg_match('@/wp-json/wp/v2/users\b@', $_SERVER['REQUEST_URI'])) {
            header($header_error_403);
            header($header_content_type_json);
            die('{"code":"rest_user_cannot_view","message":"Sorry, you are not allowed to list users.","data":{"status":403}}');
        } else {
            // rest api v1
            if (preg_match('@/wp-json/users\b@', $_SERVER['REQUEST_URI'])) {
                header($header_error_403);
                header($header_content_type_json);
                die('[{"code":"json_user_cannot_list","message":"Sorry, you are not allowed to list users."}]');
            }
        }
    }

    public static function hide_desactivation()
    {
        $instance = self::getInstance();
        add_filter('plugin_action_links', array(
            $instance,
            'filtro_ocultar_desactivacion'
        ), 10, 4);
    }
}

T800_NoUserEnumeration::from_archives();
T800_NoUserEnumeration::from_posts();
T800_NoUserEnumeration::from_rest_api();
T800_NoUserEnumeration::hide_desactivation();
