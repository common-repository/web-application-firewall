<?php
/**
 * Handler file
 *
 * @package web-application-firewall/handler/malware_scanner
 */

/**
 * Class
 */
class mo2f_scanner_parts {

	public function mo2f_make_next_request( $scan_config, $reportid, $scanverification, $repo_file_path ) {
		$download_info             = get_site_option( 'mo2f_download_info' );
		$download_done             = get_site_option( 'mo2f_download_done' );
		$mo_wpns_scan_handler_cron = new Mo_Wpns_Scan_Handler_Cron();
		if ( is_dir( $repo_file_path ) ) {
			$mo_wpns_scan_handler_cron->remove_dir( $repo_file_path );
		}
		if ( 'plugins' === $download_info['stage'] ) {
			if ( $download_done < $download_info['plugin_count'] ) {
				$next_stage = 3;
			} else {
				update_site_option( 'mo2f_download_done', 0 );
				$next_stage = 4;
			}
		} elseif ( 'themes' === $download_info['stage'] ) {
			if ( $download_done < $download_info['theme_count'] ) {
				$next_stage = 4;
			} else {
				update_site_option( 'mo2f_download_done', 0 );
				$next_stage = 5;
			}
		} else {
			$next_stage = 7;
		}

		$response = $mo_wpns_scan_handler_cron->mo2f_wp_remote_get( $scan_config['type_scan'], $reportid, $scanverification, $next_stage );
	}

}new mo2f_scanner_parts();
