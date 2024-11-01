<?php
global $mo_mmp_utility,$mmp_dir_name;
require_once $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'navbar.php';
add_action( 'admin_footer', 'mo_mmp_dashboard_switch' );
$toggle     = get_site_option( 'mo_mmp_toggle' );
$all_on     = get_site_option( 'mo_mmp_switch_all' ) ? 'checked' : '';
$waf_on     = get_site_option( 'mo_mmp_switch_waf' ) ? 'checked' : '';
$malware_on = get_site_option( 'mo_mmp_switch_malware' ) ? 'checked' : '';
$nonce      = wp_create_nonce( 'mo2f-common-nonce' );
echo '<div id="mo_switch_message" style=" padding:8px"></div>';
echo '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
	<div class="mo_wpns_divided_layout">
		
		<div class="mo_wpns_dashboard_layout">
				<div class ="mo_wpns_inside_dashboard_layout">Infected Files<p class =" mo_wpns_dashboard_text" >' . esc_html( $total_malicious ) . '</p></div>
				<div class ="mo_wpns_inside_dashboard_layout ">Failed Login<p class =" mo_wpns_dashboard_text" >' . esc_html( $wpns_attacks_blocked ) . '</p></div>
				<div class ="mo_wpns_inside_dashboard_layout">Attacks Blocked <p class =" mo_wpns_dashboard_text">' . esc_html( $total_attacks ) . '</p></div>
				<div class ="mo_wpns_inside_dashboard_layout">Blocked IPs<p class =" mo_wpns_dashboard_text">' . esc_html( $wpns_count_ips_blocked ) . '</p></div>
				<div class ="mo_wpns_inside_dashboard_layout">White-listed IPs<p class =" mo_wpns_dashboard_text">' . esc_html( $wpns_count_ips_whitelisted ) . '</p></div>		
		</div>
		<div class="mo_wpns_small_layout_container">
			<div class="mo_wpns_small_layout">
				<form name="mmp_tab_malware" id="mmp_tab_malware" method="post">
				<h3><span class="dashicons dashicons-search"></span>  Malware Scan';
if ( $toggle ) {
	echo ' <label class="mo_wpns_switch" style="float: right">
				<input type="hidden" name="option" value="tab_malware_switch"/>
				</label>';
} else {
	echo ' <b style="color:green;">(Enabled)</b>';
}
			echo ' </h3>
				</form>
				 A malware scanner / detector or virus scanner is a <b>software that detects the malware</b> into the system. It detects different kinds of malware and categories based on the <b>strength of vulnerability or harmfulness.</b> <br>
			</div>
			
			<div class="mo_wpns_small_layout">
				<form name="mmp_tab_waf" id="mmp_tab_waf" method="post">
				<h3><span class="dashicons dashicons-shield"></span> Web Application Firewall (WAF)
				<label class="mo_wpns_switch" style="float: right">
				</label>
				</h3>
				</form>
				Web Application Firewall protects your website from several website attacks such as <b>SQL Injection(SQLI), Cross Site Scripting(XSS), Remote File Inclusion</b> and many more cyber attacks.It also protects your website from <b>critical attacks</b> such as <b>Dos and DDos attacks.</b><br>
			</div>
			</div>
	</div>	';

function mo_mmp_dashboard_switch() {
	if ( ( 'admin.php' !== basename( isset( $_SERVER['PHP_SELF'] ) ? sanitize_text_field( wp_unslash( $_SERVER['PHP_SELF'] ) ) : null ) ) || ( isset( $_GET['page'] ) && sanitize_text_field( wp_unslash( $_GET['page'] ) ) !== 'mo_mmp_dashboard' ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
		return;
	}
}

