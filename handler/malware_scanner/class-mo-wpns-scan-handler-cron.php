<?php
/**
 * Handler file
 *
 * @package web-application-firewall/handler/malware_scanner
 */

/**
 * Class
 */
class Mo_Wpns_Scan_Handler_Cron {
	/**
	 * Undocumented variable
	 *
	 * @var array
	 */
	public $scanned_files = array();
	/**
	 * Undocumented function
	 */
	public function __construct() {

	}
	/**
	 * Undocumented function
	 *
	 * @param array  $scan_config .
	 * @param string $start_time .
	 * @return void
	 */
	public function mo2f_scan_all_files( $scan_config, $start_time ) {
		global $wp_filesystem;
		wp_raise_memory_limit( 'memory_limit', '-1' );
		wp_raise_memory_limit( 'max_execution_time', 0 );

		$folderpaths            = array();
		$folder_names           = '';
		$repo_check_status_code = 0;
		update_site_option( 'mo_stop_scan', '0' );
		$base         = get_home_path();
		$hostname     = 'wordpress.org';
		$uploads_dir  = wp_upload_dir();
		$uploads_path = $uploads_dir['basedir'];
		if ( ! $wp_filesystem->is_writable( $uploads_path ) ) {
			$scan_config['check_repo'] = 0;
			$repo_check_status_code    = -97;
		} else {
			$wordpress_server_status = $this->mo_wpns_check_malware_server_status( $hostname );
			if ( ! $wordpress_server_status ) {
				$scan_config['check_repo'] = 0;
				$repo_check_status_code    = -98;
			}
		}

		if ( 1 === $scan_config['core_scan'] ) {
			$folderpaths['base'] = $base;
			$folder_names       .= 'WP Files;';
		}
		if ( 1 === $scan_config['plugin_scan'] ) {
			$folderpaths['plugins'] = WP_PLUGIN_DIR;
			$folder_names          .= 'Plugins;';
		}
		if ( 1 === $scan_config['theme_scan'] ) {
			$folderpaths['themes'] = get_theme_root();
			$folder_names         .= 'Themes;';
		}
		if ( 1 === $scan_config['check_repo'] ) {
			$folder_names .= 'WP Repo Files;';
		}

		$this->count_total_files( $folderpaths, $base, $scan_config );
		update_site_option( 'mo_mmp_repo_status', $repo_check_status_code );

		$mo2f_malware_db_handler = new MoMmpDB();
		$reportid                = $mo2f_malware_db_handler->create_scan_report( $folder_names, $scan_config['type_scan'], $start_time, $repo_check_status_code );
		update_site_option( 'mo2f_report_id', $reportid );

		$scanverification = $this->create_key_current_scan( $scan_config['type_scan'], $reportid );

		$response = $this->mo2f_wp_remote_get( $scan_config['type_scan'], $reportid, $scanverification, 1 );

		wp_send_json( 'success' );
	}
	/**
	 * Undocumented function
	 *
	 * @param string $scan_mode .
	 * @param int    $reportid .
	 * @return mixed
	 */
	public function create_key_current_scan( $scan_mode, $reportid ) {

		$scanverification = md5( $scan_mode . MoMmpHandler::random_str( 24 ) . $reportid );
		update_site_option( 'mo2f_scanverification', $scanverification );
		return $scanverification;
	}
	/**
	 * Undocumented function
	 *
	 * @param string  $scan_mode .
	 * @param integer $reportid .
	 * @param string  $scanverification .
	 * @param integer $scan_stage_complete .
	 * @return void
	 */
	public function mo2f_wp_remote_get( $scan_mode, $reportid, $scanverification, $scan_stage_complete = 1 ) {

		$scan_nonce        = wp_rand( 10, 100000 );
		$http_header_array = array(
			'Content-Type'  => 'application/json',
			'charset'       => 'UTF-8',
			'Authorization' => 'Basic',
		);
		$url               = get_site_url() . '?scan_request=1&scanverification=' . $scanverification . '&reportid=' . $reportid . '&scan_stage_complete=' . $scan_stage_complete . '&scan_mode=' . $scan_mode . '&scan_nonce=' . $scan_nonce;// scanverification,report_id, scan_stage_complete and scan_mode.

		$args     = array(
			'method'      => 'GET',
			'body'        => '',
			'timeout'     => '5',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $http_header_array,
		);
		$response = wp_remote_get( $url, $args );

	}

	public function mo_wpns_check_malware_server_status( $host ) {
		global $wp_filesystem;
		$fsock = $wp_filesystem->open( $host, 'w' );
		if ( ! $fsock ) {
			return false;
		} else {
			$wp_filesystem->fclose( $fsock );
			return true;
		}
	}

	public function getlines( $contents, $href ) {
		$newissues   = 0;
		$lines       = preg_split( "/((\r?\n)|(\r\n?))/", $contents );
		$lines_count = count( $lines );
		for ( $i = 0; $i < $lines_count; $i++ ) {
			$line = $lines[ $i ];
			if ( strpos( $line, $href ) !== false ) {
				$newissues = $i + 1;
			}
		}
		return $newissues;
	}

	public function check_external_link( $contents ) {
		$issues = array();
		$hrefs  = preg_match_all( '/<a\s+(?:[^"\'>]+|"[^"]*"|\'[^\']*\')*href=("[^"]+"|\'[^\'‌​]+\'|[^<>\s]+)/i', $contents, $matches ) ? $matches : array();
		if ( isset( $hrefs[1] ) ) {
			foreach ( $hrefs[1] as $href ) {
				if ( $this->isexternal( $href ) ) {
					$line     = $this->getlines( $contents, $href );
					$issues[] = array(
						'i' => 'eld',
						'd' => $href,
						'l' => $line,
					);
				}
			}
		}
		return $issues;
	}

	public function isexternal( $url ) {
		$url        = trim( $url );
		$url        = trim( $url, ';' );
		$url        = trim( $url, '(' );
		$url        = trim( $url, ')' );
		$url        = trim( $url, "'" );
		$url        = trim( $url, '"' );
		$components = wp_parse_url( $url );
		if ( isset( $components['host'] ) ) {
			if ( preg_match( '/(WordPress|google|miniorange|xecurify|facebook|themeisle|adobe|phppot|php.net)/i', $components['host'] ) === 1 ) {
			} else {
				if ( ! empty( $components['host'] ) && strpos( strtolower( $components['host'] ), strtolower( sanitize_text_field( $_SERVER['HTTP_HOST'] ) ) ) === false ) {
					return true;
				}
			}
		}
		return false;
	}

	public function remove_dir( $repo_path ) {
		global $wp_filesystem;
		$dir   = $repo_path;
		$it    = new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS );
		$files = new RecursiveIteratorIterator( $it, RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $files as $file ) {
			if ( $file->isDir() ) {
				$wp_filesystem->rmdir( $file->getPathname() );
			} else {
				wp_delete_file( $file->getPathname() );
			}
		}
		$wp_filesystem->rmdir( $dir );
	}

	public function count_total_files( $folder_paths, $base, $scan_config ) {
		$repo_key     = 'core';
		$plugin_list  = get_site_transient( 'update_plugins' );
		$q            = $plugin_list->checked;
		$plugin_array = array();
		foreach ( $q as $key => $value ) {
			if ( strpos( $key, '/' ) ) {
				$a = explode( '/', $key );
				array_push( $plugin_array, $a[0] );
			} else {
				array_push( $plugin_array, $key );
			}
		}
		$all_themes  = get_site_transient( 'update_themes' )->checked;
		$theme_array = array();
		foreach ( $all_themes as $key => $value ) {
			array_push( $theme_array, $key );
		}
		$mo2f_malware_db_handler = new MoMmpDB();
		$file_count              = 0;
		$nooffiles               = 0;
		$file_path_array         = array();
		$skip_path_array         = array();
		$folder_skip_array       = array();
		$extensions              = array();
		$files_number            = 0;
		if ( $scan_config['type_scan'] == 'Custom Scan' ) {
			$file_ext = $scan_config['file_extension'];
			if ( empty( $file_ext ) ) {

			} else {
				if ( strpos( $file_ext, ';' ) != false ) {
					$extensions = explode( ';', $file_ext );
				} else {
					array_push( $extensions, $file_ext );
				}
			}
			$folder_skip_array = empty( $scan_config['path_skip'] ) ? array() : explode( ';', $scan_config['path_skip'] );
			$folder_skip_array_size = count( $folder_skip_array );
			for ( $i = 0; $i < $folder_skip_array_size; $i++ ) {
				$path_parts = explode( '/', $folder_skip_array[ $i ] );
				$n         = count( $path_parts ) - 1;
				$folder    = $path_parts[ $n ];
				array_push( $skip_path_array, $folder );
			}
		}
		foreach ( $folder_paths as $key_path => $value ) {
			$file_list = list_files( $value, 100 );
			if ( isset( $folder_paths['base'] ) ) {
				if ( 'base' === $key_path ) {
					$files_number = count( $file_list );
				}
			} else {
				$files_number += count( $file_list );
			}
			foreach ( $file_list as $key => $value1 ) {

				$source_file_path = $value1;

				if ( is_dir( $source_file_path ) ) {
					continue;
				}
				$source_file_path_for_explode = str_replace( '/', '\\', $source_file_path );
				$arr                          = explode( '\\', $source_file_path_for_explode );
				$theme_path                   = get_theme_root();
				if ( $value == $base && ( $scan_config['core_scan'] == 1 ) ) {
					if ( ( 'index.php' === $arr[ count( $arr ) - 1 ] && ( count( $arr ) === 1 || in_array( $arr[ count( $arr ) - 2 ], array( 'wp-content', 'plugins', 'themes' ), true ) ) && ! in_array( 'miniorangescan', $arr, true ) ) || ( ! in_array( 'plugins', $arr, true ) && ! in_array( 'themes', $arr, true ) && ! in_array( 'miniorangescan', $arr, true ) ) ) {
						return;
					} else {
						continue;
					}
				} elseif ( WP_PLUGIN_DIR === $value && 'index.php' === $arr[ count( $arr ) - 1 ] ) {
					continue;
				} elseif ( $value === $theme_path && 'index.php' === $arr[ count( $arr ) - 1 ] ) {
					continue;
				}
				$ext = pathinfo( $source_file_path, PATHINFO_EXTENSION );
				if ( 'Custom Scan' === $scan_config['type_scan'] ) {
					$flag_skip = 0;
					if ( ! empty( $folder_skip_array ) ) {
						$count = count( $skip_path_array );
						for ( $q = 0; $q < $count; $q++ ) {
							if ( strpos( $source_file_path, $skip_path_array[ $q ] ) ) {
								$flag_skip = 1;
								break;
							}
						}
					}
					if ( 1 === $flag_skip ) {
						continue;
					}

					if ( ! empty( $extensions ) ) {
						if ( ! in_array( $ext, $extensions ) ) {
							continue;
						}
					}
				}
				if ( in_array( $ext, array( 'zip', 'log', 'htaccess', 'sitx', '7z', 'rar', 'gz', 'tar.gz', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'tiff', 'raw' ) ) ) {
					continue;
				}
				$file_count++;
				++$nooffiles;

				if ( in_array( 'wp-content', $arr ) && in_array( 'plugins', $arr ) ) {// plugins file
					foreach ( $plugin_array as $arr_index => $key_repo ) {
						if ( in_array( $key_repo, $arr ) ) {
							$repo_key = $key_repo;
							break;
						}
					}
				} elseif ( in_array( 'wp-content', $arr ) && in_array( 'themes', $arr ) ) {// themes file
					foreach ( $theme_array as $arr_index => $key_repo ) {
						if ( in_array( $key_repo, $arr ) ) {
							$repo_key = $key_repo;
							break;
						}
					}
				} else { // core file.
					$repo_key = 'core';
				}

				$file_path_array[ $nooffiles ] = array(
					'file' => $source_file_path,
					'key'  => $repo_key,
				);
				if ( $nooffiles > 0 && 0 === $nooffiles % 100 ) {
					$nooffiles       = 0;
					$file_path_array = array();
				}
			}
			$nooffiles                        = 0;
			$file_path_array                  = array();
			$decoded_scan_status              = json_decode( get_site_option( 'mo_wpns_scan_status' ) );
			$decoded_scan_status->total_files = $file_count;
			$encoded_scan_status              = wp_json_encode( $decoded_scan_status );
			update_site_option( 'mo_wpns_scan_status', $encoded_scan_status );
			$mo2f_files_skipped = $files_number - $file_count;
			update_site_option( 'mo2f_files_skipped', $mo2f_files_skipped );
		}
	}

}
new Mo_Wpns_Scan_Handler_Cron();

