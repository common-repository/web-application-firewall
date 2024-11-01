<?php
	$scan_configuration = json_decode( get_site_option( 'mo_wpns_scan_configuration' ) );
if ( is_null( $scan_configuration ) ) {
	$mo_wpns_scan_files_extensions = '';
	$mo_wpns_skip_folders          = '';
	$mo_wpns_scan_plugins          = 1;
	$mo_wpns_scan_themes           = 1;
	$mo_wpns_core_scan             = 0;
	$mo_wpns_check_vulnerable      = 1;
	$mo_wpns_check_sql             = 1;
	$mo_wpns_check_extl            = 0;
	$mo_wpns_check_repo            = 0;
} else {
	$mo_wpns_scan_files_extensions = $scan_configuration->file_extension;
	$mo_wpns_skip_folders          = $scan_configuration->path_skip;
	$mo_wpns_scan_plugins          = $scan_configuration->plugin_scan;
	$mo_wpns_scan_themes           = $scan_configuration->theme_scan;
	$mo_wpns_core_scan             = $scan_configuration->core_scan;
	$mo_wpns_check_vulnerable      = $scan_configuration->check_vulnerable;
	$mo_wpns_check_sql             = $scan_configuration->check_sql;
	$mo_wpns_check_extl            = $scan_configuration->ext_link_check;
	$mo_wpns_check_repo            = $scan_configuration->check_repo;
}
	$mo_wpns_check_rfi          = 0;
	$mo_wpns_adv_sign           = 0;
	$mo_wpns_check_domain       = 0;
	$mo_wpns_check_trojan       = 0;
	$mo_wpns_check_backdoor     = 0;
	$mo_wpns_skip_folders_array = array();
if ( ! empty( $mo_wpns_skip_folders ) ) {
	$mo_wpns_skip_folders_array = explode( ';', $mo_wpns_skip_folders );
}
	$mo_wpns_white_url        = '';
	$mo_wpns_white_urls_array = array();
if ( ! empty( $mo_wpns_white_url ) ) {
	$mo_wpns_white_urls_array = explode( ';', $mo_wpns_white_url );
}
	$mo_wpns_custom_sign       = '';
	$mo_wpns_custom_sign_array = array();
if ( ! empty( $mo_wpns_custom_sign ) ) {
	$mo_wpns_custom_sign_array = explode( ';', $mo_wpns_custom_sign );
}
?>
<div class="mo_wpns_setting_layout">		
	<div class="mo_wpns_subheading"></div>
	<a style="float:right;" href='<?php echo esc_url( $mo_mmp_premium_docfile['Custom Scan Settings'] ); ?>' target="_blank"><span style="font-size:20px;margin-top:8px" class="dashicons dashicons-external mo_wpns_doc_link" title="More information.."></span></a>
	<br>
	<form id="" method="post" action="">
		<input type="hidden" name="option" value="mo_wpns_scan_configuration">
		<table class="mo_wpns_settings_table">
		<tr>
			<td style="width:30%"><b>Select Folders to Scan : </b></td>
			<td>
			<input type="checkbox" name="mo_wpns_scan_plugins" id="mo_wpns_scan_plugins" value="1" <?php checked( 1 === $mo_wpns_scan_plugins ); ?>> WordPress Plugins folder<br>
			<input type="checkbox" name="mo_wpns_scan_themes" id="mo_wpns_scan_themes" value="1" <?php checked( 1 === $mo_wpns_scan_themes ); ?>> WordPress Themes folder<br>
			<input type="checkbox" name="mo_wpns_scan_wp_files" id="mo_wpns_scan_wp_files" value="1" <?php checked( 1 === $mo_wpns_core_scan ); ?>> WordPress files
			</td>
		</tr>
		<tr><td>&nbsp;</td><td></td></tr>
		<tr>
			<td style="width:30%"><b>Select Type of files to scan : </b></td>
			<td><input class="mo_wpns_table_textbox" type="text" id="mo_wpns_scan_files_extensions" name="mo_wpns_scan_files_extensions" required placeholder="comma separated file extensions e.g. php,inc" value="<?php echo esc_attr( $mo_wpns_scan_files_extensions ); ?>" /></td>
		</tr>
		<tr><td>&nbsp;</td><td></td></tr>
		<tr>
			<td style="width:30%"><b>Select Scan Level : </b></td>
			<td>
			<input type="checkbox" name="mo_wpns_check_vulnerable_code" id="mo_wpns_check_vulnerable_code" value="1" <?php checked( 1 === $mo_wpns_check_vulnerable ); ?>> <b>Check PHP files vulnerable code <span class="mo_green">( Highly Recommeded )</span></b><br>
			Checks if your website has a code which is kept hidden or obfuscated to harm your website.<br><br>
			<input type="checkbox" name="mo_wpns_check_sql_injection" id="mo_wpns_check_sql_injection" value="1" <?php checked( 1 === $mo_wpns_check_sql ); ?>> <b>SQL Injection and injected shell script check <span class="mo_green">( Highly Recommeded )</span></b><br>
			Checks for injected SQL queries which can harm your database and injected shell scripts which can harm your server by executing any commands.<br><br>
			<input type="checkbox" name="mo_wpns_check_external_link" id="mo_wpns_check_external_link" value="1" <?php checked( 1 === $mo_wpns_check_extl ); ?>> <b>External Links Detection</b><br>
			Checks if anyone creating backlinks from your website. Backlinks to blacklisted sites can add your website to spam websites list.<br><br>
			<input type="checkbox" name="mo_wpns_scan_files_with_repo" id="mo_wpns_scan_files_with_repo" value="1" <?php checked( 1 === $mo_wpns_check_repo ); ?>> <b>Check Files with repository</b><br>
			Check the WordPress, plugin and theme files with its repository. It is helpful to determine if extra files added to or missing any of repository files.<br><br>
			</td>
		</tr>
		<tr><td>&nbsp;</td><td></td></tr>
		<tr>
			<td style="width:30%"><b>Skip folders with paths : </b></td>
			<td>
			<table style="width:100%" id="skip_folders">
				<?php for ( $i = 0;$i < count( $mo_wpns_skip_folders_array );$i++ ) { ?>
					<tr><td><input type="text" name="mo_wpns_skip_folders_<?php echo esc_attr( $i ); ?>" id="mo_wpns_skip_scan_folder_<?php echo esc_attr( $i ); ?>" class="mo_wpns_table_textbox mo_wpns_count_box" placeholder="comma separated folders full path" style="width:100%;" value="<?php echo esc_attr( $mo_wpns_skip_folders_array[ $i ] ); ?>" /></td></tr>
					<?php
				}
				if ( 0 === $i ) {
					?>
						<tr><td><input type="text" name="mo_wpns_skip_folders_0" id="mo_wpns_skip_scan_folder_0" class="mo_wpns_table_textbox mo_wpns_count_box" placeholder="comma separated folders full path" style="width:100%;" value="" /></td></tr>
					<?php
				}
				?>
			</table>
			<a style="cursor:pointer" onclick="add_skip_folders();">Add More Folders</a>
			</td>
		</tr>
		<tr><td>&nbsp;</td><td></td></tr>
		<tr>
		<td></td>
		<input type = "hidden" id = "mo_wpns_scan_settings_url" value="<?php echo esc_attr( wp_create_nonce( 'mmp-scan-settings' ) ); ?>" >
		<td><br><input type="button" name="Save_malware_config" id="Save_malware_config" style="width:100px;" value="Save" class="button button-primary button-large"> </td>
		</tr>
		</table>

	</form>
</div>
<script>
	function add_skip_folders(){
		var last_index_name = jQuery('#skip_folders tr:last .mo_wpns_table_textbox').attr('name');
		var splittedArray = last_index_name.split("_");
		var countAttributes = parseInt(splittedArray[splittedArray.length-1])+1;
		jQuery("<tr><td><input type='text' name='mo_wpns_skip_folders_"+countAttributes+"' id='mo_wpns_skip_scan_folder_"+countAttributes+"' class='mo_wpns_table_textbox mo_wpns_count_box' placeholder='comma separated folders full path' style='width:100%;' /></td></tr>").insertAfter(jQuery('#skip_folders tr:last'));
	}

	function add_white_url(){
		var last_index_name = jQuery('#white_url tr:last .mo_wpns_table_textbox').attr('name');
		var splittedArray = last_index_name.split("_");
		var countAttributes = parseInt(splittedArray[splittedArray.length-1])+1;
		jQuery("<tr><td><input type='text' name='mo_wpns_white_url_"+countAttributes+"' class='mo_wpns_table_textbox' placeholder='Enter URLs to be whitelisted' style='width:100%;' disabled/></td></tr>").insertAfter(jQuery('#white_url tr:last'));
	}

	function add_custom_sign(){
		var last_index_name = jQuery('#sign_custom tr:last .mo_wpns_table_textbox').attr('name');
		var splittedArray = last_index_name.split("_");
		var countAttributes = parseInt(splittedArray[splittedArray.length-1])+1;
		jQuery("<tr><td><input type='text' name='mo_wpns_custom_sign_"+countAttributes+"' class='mo_wpns_table_textbox' placeholder='Enter string or code to be added as custom signature' style='width:100%;' disabled/></td></tr>").insertAfter(jQuery('#sign_custom tr:last'));
	}
</script>

<?php
	echo '
	
	<script>
	jQuery(document).ready(function(){
	jQuery("#Save_malware_config").click(function(){
		jQuery("#mo_scan_message").empty();
		jQuery("#mo_scan_message").hide();
		jQuery("#mo_scan_message").show();
		jQuery("#mo_scan_message").removeClass();
		var q= jQuery(".mo_wpns_count_box").length;
		var str="";
		for(var i=0; i<q; i++){
			var content= jQuery("#mo_wpns_skip_scan_folder_"+i).val();
			content = content.trim();
			str= str+content;
			if(i != (q-1)){
				str=str+";";
			}
		}
		var data={
			"action":"mo_wpns_malware_redirect",
			"call_type":"submit_malware_settings_form",
			"scan_plugin":jQuery("input[name= mo_wpns_scan_plugins]:checked").val(),
			"scan_themes": jQuery("input[name= mo_wpns_scan_themes]:checked").val(),
			"scan_core":jQuery("input[name= mo_wpns_scan_wp_files]:checked").val(),
			"file_type":jQuery("#mo_wpns_scan_files_extensions").val(),
			"vulnerable_check":jQuery("input[name= mo_wpns_check_vulnerable_code]:checked").val(),
			"sql_check":jQuery("input[name= mo_wpns_check_sql_injection]:checked").val(),
			"ext_link":jQuery("input[name= mo_wpns_check_external_link]:checked").val(),
			"repo_check":jQuery("input[name= mo_wpns_scan_files_with_repo]:checked").val(),
			"skip_path":str,
			"nonce":jQuery("#mo_wpns_scan_settings_url").val()
		};
		jQuery.post(ajaxurl, data, function(response){
			if (response == "folder_error"){
				jQuery("#mo_scan_message").addClass("notice notice-error is-dismissible");
				jQuery("#mo_scan_message").append("Please select atleast one folder to scan");
				window.scrollTo({ top: 0, behavior: "smooth" });
			}else if (response == "path_error"){
				jQuery("#mo_scan_message").addClass("notice notice-error is-dismissible");
				jQuery("#mo_scan_message").append("The path of folder/folders is/are incorrect");
				window.scrollTo({ top: 0, behavior: "smooth" });
			}
			else if(response == "level_error"){
				jQuery("#mo_scan_message").addClass("notice notice-error is-dismissible");
				jQuery("#mo_scan_message").append("Please select atleast one scan level.");
				window.scrollTo({ top: 0, behavior: "smooth"});

			}
			else{
				jQuery("#mo_scan_message").addClass("notice notice-success is-dismissible");
				jQuery("#mo_scan_message").append("Scan configuration saved successfully");
				window.scrollTo({ top: 0, behavior: "smooth" });
			}
		});

	});
	});
</script>';
?>
