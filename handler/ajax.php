<?php
/**
 * Handler file
 *
 * @package web-application-firewall/handler
 */

/**
 * Class
 */
class mo_mmp_AjaxHandler {

	function __construct() {
		add_action( 'admin_init', array( $this, 'mo_wpns_saml_actions' ) );
	}

	function mo_wpns_saml_actions() {

		if ( current_user_can( 'manage_options' ) && isset( $_REQUEST['option'] ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
			switch ( sanitize_text_field( wp_unslash( $_REQUEST['option'] ) ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
				case 'iplookup':
					$this->lookupIP( isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : null );//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
					break;
				case 'dissmissfeedback':
					$this->handle_feedback();
					break;
				case 'whitelistself':
					$this->whitelist_self();
					break;
				case 'dismissinfected':
					$this->wpns_infected_notice();
					break;
				case 'dismissinfected_always':
					$this->wpns_infected_notice_always();
					break;
				case 'dismissplugin':
					$this->wpns_plugin_notice();
					break;
				case 'dismissplugin_always':
					$this->wpns_plugin_notice_always();
					break;
				case 'dismissweekly':
					$this->wpns_weekly_notice();
					break;
				case 'dismissweekly_always':
					$this->wpns_weekly_notice_always();
					break;
			}
		}
	}

	private function lookupIP( $ip ) {
		global $wp_filesystem;
		$result   = json_decode( $wp_filesystem->get_contents( 'http://www.geoplugin.net/json.gp?ip=' . $ip ), true );
		$hostname = gethostbyaddr( $result['geoplugin_request'] );
		try {
			$timeoffset = timezone_offset_get( new DateTimeZone( $result['geoplugin_timezone'] ), new DateTime( 'now' ) );
			$timeoffset = $timeoffset / 3600;

		} catch ( Exception $e ) {
			$result['geoplugin_timezone'] = '';
			$timeoffset                   = '';
		}

		$ip_look_up_template = MoMmpConstants::IP_LOOKUP_TEMPLATE;
		if ( $result['geoplugin_request'] == $ip ) {

			$ip_look_up_template = str_replace( '{{status}}', $result['geoplugin_status'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{ip}}', $result['geoplugin_request'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{region}}', $result['geoplugin_region'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{country}}', $result['geoplugin_countryName'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{city}}', $result['geoplugin_city'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{continent}}', $result['geoplugin_continentName'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{latitude}}', $result['geoplugin_latitude'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{longitude}}', $result['geoplugin_longitude'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{timezone}}', $result['geoplugin_timezone'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{curreny_code}}', $result['geoplugin_currencyCode'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{curreny_symbol}}', $result['geoplugin_currencySymbol'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{per_dollar_value}}', $result['geoplugin_currencyConverter'], $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{hostname}}', $hostname, $ip_look_up_template );
			$ip_look_up_template = str_replace( '{{offset}}', $timeoffset, $ip_look_up_template );

			$result['ipDetails'] = $ip_look_up_template;
		} else {
			$result['ipDetails']['status'] = 'ERROR';
		}

		wp_send_json( $result );

	}

	private function handle_feedback() {
		update_option( 'donot_show_feedback_message', 1 );
		wp_send_json( 'success' );
	}

	private function whitelist_self() {
		 global $mo_mmp_utility;
		$moPluginsUtility = new MoMmpHandler();
		$moPluginsUtility->whitelist_ip( $mo_mmp_utility->get_client_ip() );
		wp_send_json( 'success' );
	}

	private function wpns_infected_notice() {
		update_option( 'infected_dismiss', time() );
		wp_send_json( 'success' );
	}

	private function wpns_infected_notice_always() {
		update_option( 'donot_show_infected_file_notice', 1 );
		wp_send_json( 'success' );
	}

	private function wpns_plugin_notice() {
		 $plugin_current = get_plugins();
		update_option( 'mo_wpns_last_plugins', $plugin_current );
		$args          = array();
		$theme_current = wp_get_themes( $args );
		update_option( 'mo_wpns_last_themes', $theme_current );
		wp_send_json( 'success' );
	}

	private function wpns_plugin_notice_always() {
		update_option( 'donot_show_new_plugin_theme_notice', 1 );
		wp_send_json( 'success' );
	}

	private function wpns_weekly_notice() {
		update_option( 'weekly_dismiss', time() );
		wp_send_json( 'success' );
	}

	private function wpns_weekly_notice_always() {
		update_option( 'donot_show_weekly_scan_notice', 1 );
		wp_send_json( 'success' );
	}

}new mo_mmp_AjaxHandler();
