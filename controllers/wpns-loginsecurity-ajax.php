<?php
class mo_mmp_ajax {

	public function __construct() {
		add_action( 'admin_init', array( $this, 'mo_login_security_ajax' ) );
	}

	public function mo_login_security_ajax() {

		add_action( 'wp_ajax_wpns_login_security', array( $this, 'wpns_login_security' ) );
	}

	public function wpns_login_security() {
		$nonce = isset( $_POST['nonce'] ) ? filter_var( wp_unslash( $_POST['nonce'] ) ) : null;
		if ( ! wp_verify_nonce( $nonce, 'loginsecuritynonce' ) ) {
			echo 'NonceDidNotMatch';
			exit;
		}
		$case = isset( $_POST['wpns_loginsecurity_ajax'] ) ? sanitize_text_field( wp_unslash( $_POST['wpns_loginsecurity_ajax'] ) ) : null;
		switch ( $case ) {
			case 'wpns_ManualIPBlock_form':
				$this->wpns_handle_IP_blocking();
				break;
			case 'wpns_WhitelistIP_form':
				$this->wpns_whitelist_ip();
				break;
			case 'wpns_waf_settings_form':
				$this->wpns_waf_settings_form( $_POST );
				break;
			case 'wpns_ip_lookup':
				$this->wpns_ip_lookup( $_POST );
				break;
		}
	}

	public function wpns_handle_IP_blocking() {
		global $mmp_dir_name;
		include_once $mmp_dir_name . 'controllers' . DIRECTORY_SEPARATOR . 'ip-blocking.php';
	}
	public function wpns_whitelist_ip() {
		global $mmp_dir_name;
		include_once $mmp_dir_name . 'controllers' . DIRECTORY_SEPARATOR . 'ip-blocking.php';
	}
	public function wpns_ip_lookup( $post ) {
		global $wp_filesystem;
		$ip = isset( $post['IP'] ) ? filter_var( wp_unslash( $post['IP'] ) ) : null;
		if ( ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/', $ip ) ) {
			echo( 'INVALID_IP_FORMAT' );
			exit;
		} elseif ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			echo( 'INVALID_IP' );
			exit;
		}
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
	public function wpns_waf_settings_form( $post ) {
		$dir_name = dirname( dirname( dirname( dirname( __FILE__ ) ) ) ) . DIRECTORY_SEPARATOR . 'uploads';

		$dir_name .= DIRECTORY_SEPARATOR . 'miniOrange';

		$string  = '<?php' . PHP_EOL;
		$string .= '$SQL=1;' . PHP_EOL;
		$string .= '$XSS=1;' . PHP_EOL;
		$string .= '$LFI=0;' . PHP_EOL;

		switch ( sanitize_text_field( $post['optionValue'] ) ) {
			case 'WAF':
				$this->saveWAF( $post );
				break;
			default:
				break;
		}

	}

	public function add_mo_waf_config_cont( $string, $value ) {
		global $wp_filesystem;
		$dir_name  = dirname( dirname( dirname( dirname( __FILE__ ) ) ) );
		$file_name = $dir_name . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'miniOrange' . DIRECTORY_SEPARATOR . 'mo-waf-config.php';
		$file      = $wp_filesystem->get_contents( $file_name );
		if ( strpos( $file, $string ) !== false ) {
			$content = explode( PHP_EOL, $file );
			$con     = '';
			foreach ( $content as $line => $line_v ) {
				if ( strpos( $line_v, $string ) != false ) {
					$con .= '$' . $string . '=' . $value . ';' . PHP_EOL;
				} else {
					$con .= $line_v . PHP_EOL;
				}
			}
			$wp_filesystem->put_contents( $file_name, $con );
		} else {
			$file .= '$' . $string . '=' . $value . ';' . PHP_EOL;
			$wp_filesystem->put_contents( $file_name, $file );

		}
		$file = $wp_filesystem->get_contents( $file_name );
		$file = preg_replace( '/^[ \t]*[\r\n]+/m', '', $file );
		$wp_filesystem->put_contents( $file_name, $file );
	}

	private function saveWAF( $post ) {
		if ( isset( $post['pluginWAF'] ) ) {
			if ( sanitize_text_field( $post['pluginWAF'] ) === 'on' ) {
				update_option( 'WAF', 'PluginLevel' );
				update_option( 'WAFEnabled', '1' );
				echo( 'PWAFenabled' );
				exit;
			}
		} else {
			update_option( 'WAFEnabled', '0' );
			update_option( 'WAF', 'wafDisable' );
			update_option( 'SQLInjection', 0 );
			update_option( 'XSSAttack', 0 );
			update_option( 'LFIAttack', 0 );
			$this->add_mo_waf_config_cont( 'SQL', 0 );
			$this->add_mo_waf_config_cont( 'XSS', 0 );
			$this->add_mo_waf_config_cont( 'LFI', 0 );
			echo( 'PWAFdisabled' );
			exit;
		}
	}
}
new mo_mmp_ajax();


