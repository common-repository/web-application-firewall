<?php
/**
 * Dashboard functions.
 *
 * @package web-application-firewall.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
$wpns_database              = new MoMmpDB();
$wpns_count_ips_blocked     = $wpns_database->get_count_of_blocked_ips();
$wpns_count_ips_whitelisted = $wpns_database->get_number_of_whitelisted_ips();
$wpns_attacks_blocked       = $wpns_database->get_count_of_attacks_blocked();

$mo_wpns_handler = new MoMmpHandler();
$sql_c           = $mo_wpns_handler->get_blocked_attacks_count( 'SQL' );
$lfi_c           = $mo_wpns_handler->get_blocked_attacks_count( 'LFI' );
$xss_c           = $mo_wpns_handler->get_blocked_attacks_count( 'XSS' );
$total_attacks   = $sql_c + $lfi_c + $xss_c;
$total_malicious = $wpns_database->count_malicious_files();
if ( $total_malicious > 999 ) {
	$total_malicious = ( $total_malicious / 1000 );
	$total_malicious = round( $total_malicious, 1 ) . 'k';
}
	require $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'dashboard.php';
