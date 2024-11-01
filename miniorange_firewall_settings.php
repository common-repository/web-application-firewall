<?php
/**
 * Plugin Name: Web Application Firewall
 * Description: Detect and prevent DoS attacks made by bots, crawlers. Restrict access based on country and IP ranges.
 * Version: 2.1.3
 * Author: miniOrange
 * Author URI: https://miniorange.com
 * License: GPL2
 *
 * @package web-application-firewall
 */

define( 'MO_WAF_VERSION', '2.1.3' );
global $main_dir;
$main_dir = plugin_dir_url( __FILE__ );

class MOWAF {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'my_plugin_add_thickbox' ) );
		register_deactivation_hook( __FILE__, array( $this, 'mo_wpns_deactivate' ) );
		register_activation_hook( __FILE__, array( $this, 'mo_wpns_activate' ) );
		register_activation_hook( __FILE__, array( $this, 'mo_wpns_scan_automatic' ) );
		add_action( 'admin_menu', array( $this, 'mo_wpns_widget_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'mo_wpns_settings_style' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'mo_wpns_settings_script' ) );
		add_action( 'wp_footer', array( $this, 'footer_link' ), 100 );
		add_action( 'admin_footer', array( $this, 'feedback_request' ) );
		add_action( 'plugins_loaded', array( $this, 'mo_mmp_update_db' ) );
		add_action( 'admin_notices', array( $this, 'mo_wpns_malware_notices' ) );
		if ( get_option( 'disable_file_editing' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		$this->includes();
		$notify = new mmp_miniorange_security_notification();
		add_action( 'wp_dashboard_setup', array( $notify, 'my_custom_dashboard_widgets' ) );
		add_action( 'scan_cron_hook', array( $this, 'mo_wpns_scheduled_scan' ) );
		add_action( 'admin_init', array( $this, 'mo_mmp_redirect_page' ) );
	}

	public function feedback_request() {
		$server_php_self = isset( $_SERVER['PHP_SELF'] ) ? esc_url_raw( wp_unslash( $_SERVER['PHP_SELF'] ) ) : null;
		if ( 'plugins.php' !== basename( $server_php_self ) ) {
			return;
		}
		global $mmp_dir_name;

		$email = get_option( 'mo_wpns_admin_email' );
		if ( empty( $email ) ) {
			$user  = wp_get_current_user();
			$email = $user->user_email;
		}
		$imagepath = plugins_url( '/includes/images/', __FILE__ );

		wp_enqueue_style( 'wp-pointer' );
		wp_enqueue_script( 'wp-pointer' );
		wp_enqueue_script( 'utils' );
		wp_enqueue_style( 'mo_wpns_admin_plugins_page_style', plugins_url( '/includes/css/style_settings.css', __FILE__ ), array(), MO_WAF_VERSION );

	}
	public function mo_mmp_redirect_page() {
		if ( get_site_option( 'mo_mmp_plugin_redirect' ) ) {
			delete_site_option( 'mo_mmp_plugin_redirect' );
			wp_redirect( admin_url() . 'admin.php?page=mo_mmp_dashboard' );
			exit();
		}
	}


	public function mo_mmp_update_db() {
		global $wpns_db_queries;
		$wpns_db_queries->mo_plugin_activate();
	}

	public function mo_wpns_malware_notices() {
		$args          = array();
		$theme_current = wp_get_themes( $args );
		$theme_last    = get_option( 'mo_wpns_last_themes' );
		$flag_theme    = 0;
		if ( is_array( $theme_last ) ) {
			if ( sizeof( $theme_current ) == sizeof( $theme_last ) ) {
				foreach ( $theme_current as $key => $value ) {
					if ( $theme_current[ $key ] != $theme_last[ $key ] ) {
						$flag_theme = 1;
						break;
					}
				}
			} else {
				$flag_theme = 1;
			}
		} else {
			$flag_theme = 1;
		}

		$plugins_found = get_plugins();
		$plugin_last   = get_option( 'mo_wpns_last_plugins' );
		$flag_plugin   = 0;
		if ( is_array( $plugin_last ) ) {
			if ( count( $plugins_found ) === count( $plugin_last ) ) {
				foreach ( $plugins_found as $key => $value ) {
					if ( $plugins_found[ $key ] != $plugin_last[ $key ] ) {
						$flag_plugin = 1;
						break;
					}
				}
			} else {
				$flag_plugin = 1;
			}
		} else {
			$flag_plugin = 1;
		}
		$days = ( time() - get_option( 'mo_mmp_last_scan_time' ) ) / ( 60 * 60 * 24 );
		$days = (int) $days;

		$day_infected = ( time() - get_option( 'infected_dismiss' ) ) / ( 60 * 60 * 24 );
		$day_infected = floor( $day_infected );
		$day_weekly   = ( time() - get_option( 'weekly_dismiss' ) ) / ( 60 * 60 * 24 );
		$day_weekly   = floor( $day_weekly );
		$allowed_html = array(
			'div' => array(
				'class' => array(),
				'style' => array(),
			),
			'p'   => array(
				'class' => array(),
				'style' => array(),
			),
		);
		if ( isset( $_GET['page'] ) && strpos( sanitize_text_field( wp_unslash( $_GET['page'] ) ), 'mo_mmp_' ) !== false ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
			echo wp_kses( MoMmpMessages::showMessage( 'NEW_PLUGIN_THEME_CHECK' ), $allowed_html );
		}
	}

	public function mo_wpns_widget_menu() {
		$menu_slug = 'mo_mmp_waf';
		add_menu_page( 'Firewall', 'Firewall', 'activate_plugins', $menu_slug, array( $this, 'mo_wpns' ), plugin_dir_url( __FILE__ ) . 'includes/images/miniorange_icon.png' );

		add_submenu_page( $menu_slug, 'Firewall', 'Dashboard', 'administrator', 'mo_mmp_dashboard', array( $this, 'mo_wpns' ) );
		add_submenu_page( $menu_slug, 'Firewall', 'Malware Scan', 'administrator', 'mo_mmp_malwarescan', array( $this, 'mo_wpns' ) );
		add_submenu_page( $menu_slug, 'Firewall', 'WAF', 'administrator', 'mo_mmp_waf', array( $this, 'mo_wpns' ) );
	}

	public function mo_wpns() {
		global $wpns_db_queries;
		$wpns_db_queries->mo_plugin_activate();

		add_option( 'mo_wpns_enable_ip_blocked_email_to_admin', true );
		add_option( 'SQLInjection', 1 );
		add_option( 'WAFEnabled', 0 );
		add_option( 'XSSAttack', 1 );
		add_option( 'mo_mmp_check_sql_injection', 1 );
		add_option( 'mo_mmp_scan_plugins', true );
		add_option( 'mo_mmp_scan_themes', true );
		include 'controllers/main_controller.php';
	}

	public function mo_wpns_activate() {
		global $wpns_db_queries;
		$wpns_db_queries->mo_plugin_activate();
		update_site_option( 'mo_mmp_plugin_redirect', true );
		add_option( 'mo_mmp_scan_initialize', 1 );
		add_option( 'mo_mmp_last_scan_time', time() );
	}

	public function mo_wpns_scan_automatic() {
		if ( ! wp_next_scheduled( 'scan_cron_hook' ) ) {
			wp_schedule_single_event( time() + 21600, 'scan_cron_hook' );
		}
	}

	public function mo_wpns_scheduled_scan() {
		if ( get_option( 'mo_mmp_scan_initialize' ) ) {
			$nonce        = wp_create_nonce( 'wpns-quick-scan' );
			$config_array = array(
				'scan'     => 'scan_start',
				'scantype' => 'quick_scan',
				'nonce'    => $nonce,
			);
			$scan_obj     = new Mo_mmp_scan_malware();
			$scan_obj->mo_wpns_start_malware_scan( $config_array );
		}
	}

	public function mo_wpns_deactivate() {
		global $mo_mmp_utility;
		if ( ! $mo_mmp_utility->check_empty_or_null( get_option( 'mo_wpns_registration_status' ) ) ) {
			delete_option( 'mo_wpns_admin_email' );
		}

		delete_option( 'mo_wpns_admin_customer_key' );
		delete_option( 'mo_wpns_admin_api_key' );
		delete_option( 'mo_wpns_customer_token' );
		delete_option( 'mo_wpns_transactionId' );
		delete_option( 'mo_wpns_registration_status' );
	}

	public function mo_wpns_settings_style( $hook ) {

		if ( strpos( $hook, 'page_mo_mmp' ) ) {
			wp_enqueue_style( 'mo_wpns_admin_settings_style', plugins_url( 'includes/css/style_settings.css', __FILE__ ), array(), MO_WAF_VERSION );
			wp_enqueue_style( 'mo_wpns_admin_settings_phone_style', plugins_url( 'includes/css/phone.css', __FILE__ ), array(), MO_WAF_VERSION );
			wp_enqueue_style( 'mo_wpns_admin_settings_datatable_style', plugins_url( 'includes/css/jquery.dataTables.min.css', __FILE__ ), array(), MO_WAF_VERSION );
			wp_enqueue_style( 'mo_wpns_button_settings_style', plugins_url( 'includes/css/button_styles.css', __FILE__ ), array(), MO_WAF_VERSION );
			wp_enqueue_style( 'mo_wpns_other_plugins', plugins_url( 'includes/css/other_plugins.css', __FILE__ ), array(), MO_WAF_VERSION );

		}

	}

	public function my_plugin_add_thickbox() {
		add_thickbox();
	}

	public function mo_wpns_settings_script( $hook ) {
		wp_enqueue_script( 'mo_wpns_admin_settings_script', plugins_url( 'includes/js/settings_page.js', __FILE__ ), array( 'jquery' ), MO_WAF_VERSION, false );
		if ( strpos( $hook, 'mo_mmp_upgrade' ) ) {

			wp_enqueue_script( 'footerScript', plugins_url( 'includes/js/jquery.dataTables.max.js', __FILE__ ), array(), MO_WAF_VERSION, false );

		}
		if ( strpos( $hook, 'page_mo_mmp' ) ) {
			wp_enqueue_script( 'mo_wpns_admin_settings_phone_script', plugins_url( 'includes/js/phone.js', __FILE__ ), array(), MO_WAF_VERSION, false );
			wp_enqueue_script( 'mo_wpns_admin_datatable_script', plugins_url( 'includes/js/jquery.dataTables.min.js', __FILE__ ), array( 'jquery' ), MO_WAF_VERSION, false );
		}
	}

	public function footer_link() {
		echo esc_url( MoMmpConstants::FOOTER_LINK );
	}

	public function includes() {
		require 'helper/pluginUtility.php';
		require 'database/database_functions.php';
		require 'helper/utility.php';
		require 'handler/ajax.php';
		require 'helper/constants.php';
		require 'helper/messages.php';
		require 'helper/dashboard_security_notification.php';

		require 'controllers/wpns-loginsecurity-ajax.php';
		require 'controllers/malware_scanner/malware_scan_ajax.php';
		require 'handler/malware_scanner/class-mo-wpns-scan-handler-cron.php';
		require 'handler/malware_scanner/scanner_set_cron.php';
	}

}
new MOWAF();

