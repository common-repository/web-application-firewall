<?php
/** Copyright (C) 2015  miniOrange

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * @package      miniOrange OAuth
 * @license      http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
 **/


// need to have different classes here for each ipblocking, whitelisting, htaccess and transaction related functions
class MoMmpHandler {


	public function is_ip_blocked( $ip_address ) {
		global $wpns_db_queries;
		if ( empty( $ip_address ) ) {
			return false;
		}

		$user_count = $wpns_db_queries->get_ip_blocked_count( $ip_address );

		if ( $user_count ) {
			$user_count = intval( $user_count );
		}
		if ( $user_count > 0 ) {
			return true;
		}

		return false;
	}
	public function get_blocked_attacks_count( $attackName ) {
		global $wpns_db_queries;
		$attackCount = $wpns_db_queries->get_blocked_attack_count( $attackName );
		if ( $attackCount ) {
			$attackCount = intval( $attackCount );
		}
		return $attackCount;
	}

	public function get_blocked_ip_waf() {
		global $wpns_db_queries;
		$ip_count = $wpns_db_queries->get_total_blocked_ips_waf();
		if ( $ip_count ) {
			$ip_count = intval( $ip_count );
		}

		return $ip_count;
	}
	public function get_manual_blocked_ip_count() {
		global $wpns_db_queries;
		$ip_count = $wpns_db_queries->get_total_manual_blocked_ips();
		if ( $ip_count ) {
			$ip_count = intval( $ip_count );
		}

		return $ip_count;
	}
	public function get_blocked_ips() {
		global $wpns_db_queries;
		return $wpns_db_queries->get_blocked_ip_list();
	}
	public function get_blocked_sqli() {
		global $wpns_db_queries;
		return $wpns_db_queries->get_blocked_sqli_list();
	}
	public function get_blocked_lfi() {
		global $wpns_db_queries;
		return $wpns_db_queries->get_blocked_lfi_list();
	}
	public function get_blocked_xss() {
		global $wpns_db_queries;
		return $wpns_db_queries->get_blocked_xss_list();
	}

	public function block_ip( $ip_address, $reason, $permenently ) {
		global $wpns_db_queries,$wp_filesystem;
		if ( empty( $ip_address ) ) {
			return;
		}
		if ( $this->is_ip_blocked( $ip_address ) ) {
			return;
		}
		$blocked_for_time = null;
		if ( ! $permenently && get_option( 'mo_wpns_time_of_blocking_type' ) ) {
			$blocking_type        = get_option( 'mo_wpns_time_of_blocking_type' );
			$time_of_blocking_val = 3;
			if ( get_option( 'mo_wpns_time_of_blocking_val' ) ) {
				$time_of_blocking_val = get_option( 'mo_wpns_time_of_blocking_val' );
			}
			if ( 'months' === $blocking_type ) {
				$blocked_for_time = current_time( 'timestamp' ) + $time_of_blocking_val * 30 * 24 * 60 * 60;
			} elseif ( $blocking_type == 'days' ) {
				$blocked_for_time = current_time( 'timestamp' ) + $time_of_blocking_val * 24 * 60 * 60;
			} elseif ( $blocking_type == 'hours' ) {
				$blocked_for_time = current_time( 'timestamp' ) + $time_of_blocking_val * 60 * 60;
			}
		}

		if ( get_option( 'mo_wpns_enable_htaccess_blocking' ) ) {
			$base = dirname( dirname( dirname( dirname( dirname( __FILE__ ) ) ) ) );
			$f    = $wp_filesystem->open( $base . DIRECTORY_SEPARATOR . '.htaccess', 'a' );
			$wp_filesystem->put_contents( $f, "\ndeny from " . trim( $ip_address ) );
			$wp_filesystem->fclose( $f );
		}

		$wpns_db_queries->insert_blocked_ip( $ip_address, $reason, $blocked_for_time );

		global $mo_mmp_utility;
		if ( get_option( 'mo_wpns_enable_ip_blocked_email_to_admin' ) ) {
			$mo_mmp_utility->sendIpBlockedNotification( $ip_address, MoMmpConstants::LOGIN_ATTEMPTS_EXCEEDED );
		}

	}

	public function unblock_ip_entry( $entryid ) {
		global $wpns_db_queries, $wp_filesystem;
		$myrows = $wpns_db_queries->get_blocked_ip( $entryid );
		if ( count( $myrows ) > 0 ) {
			if ( get_option( 'mo_wpns_enable_htaccess_blocking' ) ) {
				$ip_address = $myrows[0]->ip_address;
				$base       = dirname( dirname( dirname( dirname( dirname( __FILE__ ) ) ) ) );
				$hpath      = $base . DIRECTORY_SEPARATOR . '.htaccess';
				$contents   = $wp_filesystem->get_contents( $hpath );
				if ( strpos( $contents, "\ndeny from " . trim( $ip_address ) ) !== false ) {
					$contents = str_replace( "\ndeny from " . trim( $ip_address ), '', $contents );
					$wp_filesystem->put_contents( $hpath, $contents );
				}
			}
		}

		$wpns_db_queries->delete_blocked_ip( $entryid );
	}
	public function is_whitelisted( $ip_address ) {
		global $wpns_db_queries;
		$count = $wpns_db_queries->get_whitelisted_ip_count( $ip_address );

		if ( empty( $ip_address ) ) {
			return false;
		}
		if ( $count ) {
			$count = intval( $count );
		}

		if ( $count > 0 ) {
			return true;
		}
		return false;
	}

	public function whitelist_ip( $ip_address ) {
		global $wpns_db_queries, $wp_filesystem;
		if ( get_option( 'mo_wpns_enable_htaccess_blocking' ) ) {
			$base     = dirname( dirname( dirname( dirname( dirname( __FILE__ ) ) ) ) );
			$hpath    = $base . DIRECTORY_SEPARATOR . '.htaccess';
			$contents = wp_remote_get( $hpath );
			if ( strpos( $contents, "\ndeny from " . trim( $ip_address ) ) !== false ) {
				$contents = str_replace( "\ndeny from " . trim( $ip_address ), '', $contents );
				$wp_filesystem->put_contents( $hpath, $contents );
			}
		}

		if ( empty( $ip_address ) ) {
			return;
		}
		if ( $this->is_whitelisted( $ip_address ) ) {
			return;
		}

		$wpns_db_queries->insert_whitelisted_ip( $ip_address );
	}

	public function remove_whitelist_entry( $entryid ) {
		global $wpns_db_queries;
		$wpns_db_queries->delete_whitelisted_ip( $entryid );
	}

	public function get_whitelisted_ips() {
		global $wpns_db_queries;
		return $wpns_db_queries->get_whitelisted_ips_list();
	}

	public function is_email_sent_to_user( $username, $ip_address ) {
		global $wpns_db_queries;
		if ( empty( $ip_address ) ) {
			return false;
		}
		$sent_count = $wpns_db_queries->get_email_audit_count( $ip_address, $username );
		if ( $sent_count ) {
			$sent_count = intval( $sent_count );
		}
		if ( $sent_count > 0 ) {
			return true;
		}
		return false;
	}

	public static function random_str( $length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' ) {
		$randomString     = '';
		$charactersLength = strlen( $keyspace );
		$keyspace         = $keyspace . microtime( true );
		$keyspace         = str_shuffle( $keyspace );
		for ( $i = 0; $i < $length; $i ++ ) {
			$randomString .= $keyspace[ wp_rand( 0, $charactersLength - 1 ) ];
		}

		return $randomString;

	}

}
