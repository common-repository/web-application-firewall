<?php
	global $mo_mmp_utility,$mmp_dir_name;
	$mo_wpns_handler     = new MoMmpHandler();
	$sql_c               = $mo_wpns_handler->get_blocked_attacks_count( 'SQL' );
	$lfi_c               = $mo_wpns_handler->get_blocked_attacks_count( 'LFI' );
	$xss_c               = $mo_wpns_handler->get_blocked_attacks_count( 'XSS' );
	$xss_c               = $sql_c + $lfi_c + $xss_c;
	$manualblocks        = $mo_wpns_handler->get_manual_blocked_ip_count();
	$realtime            = 0;
	$i_pblocked_by_w_a_f = $mo_wpns_handler->get_blocked_ip_waf();
	$total_i_p_blocked   = $manualblocks + $realtime + $i_pblocked_by_w_a_f;
	$mo_waf              = get_site_option( 'WAFEnabled' );
if ( $mo_waf ) {
	$mo_waf = false;
} else {
	$mo_waf = true;
}

	$img_loader_url = plugin_dir_url( dirname( dirname( __FILE__ ) ) . '/includes/images/loader.gif' );

if ( $total_i_p_blocked > 999 ) {
	$total_i_p_blocked = strval( intval( $total_i_p_blocked / 1000 ) ) . 'k+';
}

if ( $xss_c > 999 ) {
	$xss_c = strval( intval( $xss_c / 1000 ) ) . 'k+';
}


	require $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'waf.php';




