<?php
/**
 * Navbar functions.
 *
 * @package web-application-firewall.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
	global $mo_mmp_utility,$mmp_dir_name;

if ( isset( $_GET['page'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
	$tab_count = get_site_option( 'mo_mmp_tab_count', 0 );
	if ( '6' === $tab_count ) {
			update_site_option( 'mo_mmp_switch_all', 1 );
	} else {
		update_site_option( 'mo_mmp_switch_all', 0 );
	}
	switch ( sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
		case 'mo_mmp_waf':
			update_option( 'mo_mmp_switch_waf', 1 );
			if ( $tab_count < 6 ) {
				update_site_option( 'mo_mmp_tab_count', get_site_option( 'mo_mmp_tab_count' ) + 1 );
			}
			break;
	}
}

	$waf      = add_query_arg( array( 'page' => 'mo_mmp_waf' ), ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) );
	$scan_url = add_query_arg( array( 'page' => 'mo_mmp_malwarescan' ), ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) );
	// Added for new design.
	$dashboard_url = add_query_arg( array( 'page' => 'mo_mmp_dashboard' ), ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) );
	// dynamic.
	$logo_url     = plugin_dir_url( dirname( __FILE__ ) ) . 'includes/images/miniorange_logo.png';
	$shw_feedback = get_option( 'donot_show_feedback_message' ) ? false : true;

	$mo_plugin_handler = new MoMmpHandler();

	$safe = $mo_plugin_handler->is_whitelisted( $mo_mmp_utility->get_client_ip() );

	$active_tab = sanitize_text_field( wp_unslash( $_GET['page'] ) ); //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.

	require $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'navbar.php';
