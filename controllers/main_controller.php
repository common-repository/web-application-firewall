<?php

global $mo_mmp_utility,$mmp_dir_name;

$controller = $mmp_dir_name . 'controllers' . DIRECTORY_SEPARATOR;

require $controller . 'navbar.php';

if ( isset( $_GET['page'] ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
	switch ( sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
		case 'mo_mmp_dashboard':
			include $controller . 'dashboard.php';
			break;
		case 'mo_mmp_waf':
			include $controller . 'waf.php';
			break;
		case 'mo_mmp_blockedips':
			include $controller . 'ip-blocking.php';
			break;
		case 'mo_mmp_malwarescan':
			include $controller . 'malware_scanner' . DIRECTORY_SEPARATOR . 'scan_malware.php';
			break;
	}
}

