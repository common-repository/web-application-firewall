<?php
/**
 * IP blocking functions.
 *
 * @package web-application-firewall.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
global $mo_mmp_utility,$mmp_dir_name;
$mo_wpns_handler = new MoMmpHandler();
$nonce           = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';
if ( ! wp_verify_nonce( $nonce, 'loginsecuritynonce' ) ) {
	return;
}
if ( current_user_can( 'manage_options' ) && isset( $_POST['option'] ) ) {
	$option  = sanitize_text_field( wp_unslash( $_POST['option'] ) );
	$option  = isset( $_POST['option'] ) ? sanitize_text_field( wp_unslash( $_POST['option'] ) ) : '';
	$ip      = isset( $_POST['IP'] ) ? sanitize_text_field( wp_unslash( $_POST['IP'] ) ) : '';
	$mo2f_id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
	switch ( $option ) {
		case 'mo_wpns_manual_block_ip':
			mmp_handle_manual_block_ip( filter_var( sanitize_text_field( wp_unslash( $_POST['IP'] ) ) ) );
			break;
		case 'mo_wpns_unblock_ip':
			mmp_handle_unblock_ip( sanitize_text_field( sanitize_text_field( wp_unslash( $_POST['id'] ) ) ) );
			break;
		case 'mo_wpns_whitelist_ip':
			mmp_handle_whitelist_ip( filter_var( sanitize_text_field( wp_unslash( $_POST['IP'] ) ) ) );
			break;
		case 'mo_wpns_remove_whitelist':
			mmp_handle_remove_whitelist( sanitize_text_field( wp_unslash( $_POST['id'] ) ) );
			break;
	}
}

$blockedips      = $mo_wpns_handler->get_blocked_ips();
$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();
$img_loader_url  = plugins_url( 'web-application-firewall/includes/images/loader.gif' );
$page_url        = '';
$license_url     = add_query_arg( array( 'page' => 'mo_mmp_upgrade' ), isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : null );



/**
 * Function to handle Manual Block IP form submit.
 *
 * @param string $ip IP.
 * @return void
 */
function mmp_handle_manual_block_ip( $ip ) {

	global $mo_mmp_utility;
	if ( $mo_mmp_utility->check_empty_or_null( $ip ) ) {
		echo( 'empty IP' );
		exit;
	}
	if ( ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/', $ip ) ) {
		echo( 'INVALID_IP_FORMAT' );
		exit;
	} else {
		$ip_address     = sanitize_text_field( $ip );
		$mo_wpns_config = new MoMmpHandler();
		$is_whitelisted = $mo_wpns_config->is_whitelisted( $ip_address );
		if ( ! $is_whitelisted ) {
			if ( $mo_wpns_config->is_ip_blocked( $ip_address ) ) {

				echo( 'already blocked' );
				exit;
			} else {
				$mo_wpns_config->block_ip( $ip_address, MoMmpConstants::BLOCKED_BY_ADMIN, true );

				?>
					<table id="blockedips_table1" class="display">
				<thead><tr><th>IP Address&emsp;&emsp;</th><th>Reason&emsp;&emsp;</th><th>Blocked Until&emsp;&emsp;</th><th>Blocked Date&emsp;&emsp;</th><th>Action&emsp;&emsp;</th></tr></thead>
				<tbody>
				<?php
				$mo_wpns_handler = new MoMmpHandler();
				$blockedips      = $mo_wpns_handler->get_blocked_ips();
				$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();
				global $mmp_dir_name;
				foreach ( $blockedips as $blockedip ) {
					echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $blockedip->ip_address ) . '</td><td>' . esc_html( $blockedip->reason ) . '</td><td>';
					if ( empty( $blockedip->blocked_for_time ) ) {
						echo '<span class=redtext>Permanently</span>';
					} else {
						echo esc_html( gmdate( 'M j, Y, g:i:s a', $blockedip->blocked_for_time ) );
					}
					echo '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', $blockedip->created_timestamp ) ) . "</td><td><a  onclick=unblockip('" . esc_js( $blockedip->id ) . "')>Unblock IP</a></td></tr>";
				}
				?>
					</tbody>
					</table>
					<script type="text/javascript">
						jQuery("#blockedips_table1").DataTable({
						"order": [[ 3, "desc" ]]
						});
					</script>
				<?php
				exit;
			}
		} else {

			echo( 'IP_IN_WHITELISTED' );
			exit;
		}
	}
}

/**
 * Function to handle Manual Block IP form submit
 *
 * @param string $entry_i_d ID.
 * @return void
 */
function mmp_handle_unblock_ip( $entry_i_d ) {
	global $mo_mmp_utility;

	if ( $mo_mmp_utility->check_empty_or_null( $entry_i_d ) ) {
		echo( 'UNKNOWN_ERROR' );
		exit;
	} else {
		$entry_i_d      = sanitize_text_field( $entry_i_d );
		$mo_wpns_config = new MoMmpHandler();
		$mo_wpns_config->unblock_ip_entry( $entry_i_d );

		?>
				<table id="blockedips_table1" class="display">
				<thead><tr><th>IP Address&emsp;&emsp;</th><th>Reason&emsp;&emsp;</th><th>Blocked Until&emsp;&emsp;</th><th>Blocked Date&emsp;&emsp;</th><th>Action&emsp;&emsp;</th></tr></thead>
				<tbody>
		<?php
			$mo_wpns_handler = new MoMmpHandler();
			$blockedips      = $mo_wpns_handler->get_blocked_ips();
			$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();
			global $mmp_dir_name;
		foreach ( $blockedips as $blockedip ) {
			echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $blockedip->ip_address ) . '</td><td>' . esc_html( $blockedip->reason ) . '</td><td>';
			if ( empty( $blockedip->blocked_for_time ) ) {
				echo '<span class=redtext>Permanently</span>';
			} else {
				echo esc_html( gmdate( 'M j, Y, g:i:s a', $blockedip->blocked_for_time ) );
			}
			echo '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', $blockedip->created_timestamp ) ) . "</td><td><a onclick=unblockip('" . esc_js( $blockedip->id ) . "')>Unblock IP</a></td></tr>";
		}
		?>
					</tbody>
					</table>
					<script type="text/javascript">
						jQuery("#blockedips_table1").DataTable({
						"order": [[ 3, "desc" ]]
						});
					</script>
				<?php

				exit;
	}
}

/**
 * Function to handle Whitelist IP form submit
 *
 * @param string $ip IP.
 * @return void
 */
function mmp_handle_whitelist_ip( $ip ) {
	global $mo_mmp_utility;
	if ( $mo_mmp_utility->check_empty_or_null( $ip ) ) {

		echo( 'EMPTY IP' );
		exit;
	}
	if ( ! preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/', $ip ) ) {
			echo( 'INVALID_IP' );
			exit;
	} else {
		$ip_address     = sanitize_text_field( $ip );
		$mo_wpns_config = new MoMmpHandler();
		if ( $mo_wpns_config->is_whitelisted( $ip_address ) ) {

			echo( 'IP_ALREADY_WHITELISTED' );
			exit;
		} else {
			$mo_wpns_config->whitelist_ip( $ip );

			$mo_wpns_handler = new MoMmpHandler();
			$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();

			?>
				<table id="whitelistedips_table1" class="display">
				<thead><tr><th >IP Address</th><th >Whitelisted Date</th><th >Remove from Whitelist</th></tr></thead>
				<tbody>
			<?php
			foreach ( $whitelisted_ips as $whitelisted_ip ) {
				echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $whitelisted_ip->ip_address ) . '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', esc_html( $whitelisted_ip->created_timestamp ) ) ) . "</td><td><a  onclick=removefromwhitelist('" . esc_js( $whitelisted_ip->id ) . "')>Remove</a></td></tr>";
			}

			?>
				</tbody>
				</table>
			<script type="text/javascript">
				jQuery("#whitelistedips_table1").DataTable({
				"order": [[ 1, "desc" ]]
				});
			</script>

			<?php
			exit;
		}
	}
}


/**
 * Function to handle remove whitelisted IP form submit
 *
 * @param string $entry_i_d ID.
 * @return void
 */
function mmp_handle_remove_whitelist( $entry_i_d ) {
	global $mo_mmp_utility;
	if ( $mo_mmp_utility->check_empty_or_null( $entry_i_d ) ) {

		echo( 'UNKNOWN_ERROR' );
		exit;
	} else {
		$entry_i_d      = sanitize_text_field( $entry_i_d );
		$mo_wpns_config = new MoMmpHandler();
		$mo_wpns_config->remove_whitelist_entry( $entry_i_d );

			$mo_wpns_handler = new MoMmpHandler();
			$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();

		?>
				<table id="whitelistedips_table1" class="display">
				<thead><tr><th >IP Address</th><th >Whitelisted Date</th><th >Remove from Whitelist</th></tr></thead>
				<tbody>
		<?php
		foreach ( $whitelisted_ips as $whitelisted_ip ) {
			echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $whitelisted_ip->ip_address ) . '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', esc_html( $whitelisted_ip->created_timestamp ) ) ) . "</td><td><a onclick=removefromwhitelist('" . esc_js( $whitelisted_ip->id ) . "')>Remove</a></td></tr>";
		}

		?>
				</tbody>
				</table>
			<script type="text/javascript">
				jQuery("#whitelistedips_table1").DataTable({
				"order": [[ 1, "desc" ]]
				});
			</script>

		<?php
		exit;
	}
}


