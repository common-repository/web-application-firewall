<?php

class MoMmpConstants {

	const SUCCESS            = 'success';
	const FAILED             = 'failed';
	const PAST_FAILED        = 'pastfailed';
	const DB_VERSION         = 150;
	const IP_LOOKUP_TEMPLATE = '<span style="font-size:14px;font-weight:bold">GENERAL INFORMATION</span><table style="margin-left:2%;"><tr><td style="width:100px;">Response</td><td >:</td><td>{{status}}</td></tr><tr><td style="width:100px;">IP Address</td><td>:</td><td>{{ip}}</td></tr><tr><td>HostName</td><td>:</td><td>{{hostname}}</td></tr><tr><td>TimeZone</td><td>:</td><td>{{timezone}}</td></tr><tr><td>Time Difference</td><td>:</td><td>{{offset}}</td></tr></table><hr><span style="font-size:14px;font-weight:bold">LOCATION INFORMATION</span><table style="margin-left:2%;"><tr><td>Latitude</td><td>:</td><td>{{latitude}}</td></tr><tr><td>Longitude</td><td>:</td><td>{{longitude}}</td></tr><tr><td>Region</td><td>:</td><td>{{region}}</td></tr><tr><td>Country</td><td>:</td><td>{{country}}</td></tr><tr><td>City</td><td>:</td><td>{{city}}</td></tr><tr><td>Continent</td><td>:</td><td>{{continent}}</td></tr><tr><td>Curreny Code</td><td>:</td><td>{{curreny_code}}</td></tr><tr><td>Curreny Symbol</td><td>:</td><td>{{curreny_symbol}}</td></tr><tr><td>Per Dollar Value</td><td>:</td><td>{{per_dollar_value}}</td></tr></table>';

	const HOST_NAME   = 'https://login.xecurify.com';
	const FOOTER_LINK = '<a style="display:none;" href="http://miniorange.com/cyber-security">Secured By miniOrange</a>';

	const TWO_FACTOR_SETTINGS       = 'miniorange-2-factor-authentication/miniorange_2_factor_settings.php';
	const OTP_VERIFICATION_SETTINGS = 'miniorange-otp-verification/miniorange_validation_settings.php';


	const LOGIN_ATTEMPTS_EXCEEDED           = 'User exceeded allowed login attempts.';
	const BLOCKED_BY_ADMIN                  = 'Blocked by Admin';
	const IP_RANGE_BLOCKING                 = 'IP Range Blocking';
	const FAILED_LOGIN_ATTEMPTS_FROM_NEW_IP = 'Failed login attempts from new IP.';
	const LOGGED_IN_FROM_NEW_IP             = 'Logged in from new IP.';
	const PLUGIN                            = 'plugin';

	public static $host = 'http://scanner.api.xecurify.com/malwareservice/rest/file/upload';

	public static $hostname = 'scanner.api.xecurify.com';

	public static $quick_scan_configuration = array(
		'plugin_scan'      => 1,
		'theme_scan'       => 1,
		'core_scan'        => 0,
		'file_extension'   => '',
		'check_vulnerable' => 1,
		'check_sql'        => 1,
		'ext_link_check'   => 0,
		'check_repo'       => 0,
		'path_skip'        => '',
		'type_scan'        => 'Quick Scan',
	);

	function __construct() {
		$this->define_global();
	}

	function define_global() {
		global $wpns_db_queries, $mo_mmp_utility,$mmp_dir_name;
		$wpns_db_queries = new MoMmpDB();
		$mo_mmp_utility  = new MoMmpUtility();
		$mmp_dir_name    = dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR;
	}

}
	new MoMmpConstants();


