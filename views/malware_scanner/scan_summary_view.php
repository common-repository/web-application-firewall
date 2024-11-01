<?php
global $mo_mo_wpns_utility,$mmp_dir_name;
$setup_dir_name = $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'link_tracers.php';
 require $setup_dir_name;

?>
<?php
add_action( 'admin_footer', 'mo_mmp_start_scan' );
?>
	<link rel="stylesheet" href="">
	
	<div class="mo_wpns_dashboard_layout">
		<div class="malwaresummarydiv">
			<?php mo_mmp_show_summary(); ?>		
		</div>
	</div>
		<div class="mo_wpns_setting_layout" id="scan_status_table">
			<div>
				<p class="hmdiv">Scan Modes <a href='<?php echo esc_url( $mo_mmp_premium_docfile['Scan Modes'] ); ?>' target="_blank"><span class="dashicons dashicons-external mo_wpns_doc_link" title="More information.."></span></a></p>
			</div>
			<div style="float: left;">
				<p id="scanstatus"></p>
			</div>
			<div class="malwaresummarydiv">
				<div class="mo_wpns_sub_scanmode mo_wpns_msdivl">
					<div class="hdiv"><b>Quick Scan</b></div>
					<hr class="line">
					<p class="mo_wpns_scan_desc">Quick Scan checks all Plugins, Themes and Core files for Vulnerable Code and SQL Injections using PHP malware signatures.</p>
					<input type = "hidden" id = "wpns_scan_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mmp-scan-settings' ) ); ?>" >
					<input id="quick_scan_button" type="button" name="quick_scan_button" class="button button-primary button-large" value="Quick Scan">
				</div>
				<div class="mo_wpns_sub_scanmode mo_wpns_msdivr">
					<div class="hdiv"><b>Custom Scan</b></div>
					<hr class="line">
					<p class="mo_wpns_scan_desc">Custom Scan gives you an option to choose which files to scan and what to check for.</p>
					<div style="display:flex;width:100%;justify-content:space-between">
						<input id="custom_scan_button" type="button" name="custom_scan_button" class="button button-primary button-large" value="Custom Scan">
						<input type="button" name="configure_button" class="button button-primary button-large" value="Configure" style="float: right;" onclick="openTabmalware(event, 'settings_scan')" >
					</div>
				</div>
			</div>
		</div>
	</div>
	<div class="mo_wpns_setting_layout" id="mo_progress" style="display: none;">
		<div>
			<div>
				<h3 id="progress_message">Scan progress...</h3>
			</div>
			<div id="mo2f_remaining" class='mo_wpns_scan_data'>
				<div id="mo2f_files_remaining"><span >Files Remaining</span> : <span style='color:green;'>Calculating...</span></div>
				<div id="mo2f_time_remaining"><span >Time Remaining</span> :  <span style='color:green;'>Calculating...</span></div>
			</div>
		</div>
		<div id="mo_mmp_progress" class="mo_mmp_progress">
			<div id="mo_mmp_progress_bar" class="mo_mmp_progress_bar">0%</div>
		</div>
		<div id="mo_stop_button_div" class="mo_stop_button_div">
			<input type="button" name="mo_stop_button" id="mo_stop_button" class="button button-primary " value="Stop Scan">
		</div >
	</div>
	<div id='mo2f_scan_confirm_modal' class="mo_scan_confirm_modal" style="display: none;">
		<div class="mo_wpns_divided_layout" style="margin-left: 13%;">
			<div class="mo_wpns_setting_layout_scan">
				<p style="font-size: large; text-align: center;">The first scan would take time. It is advised to do it when your website is not expecting much traffic. Click continue to proceed with the scan.</p>
				<hr>
				<div style="display:flex">
					<input id="mo2f_scan_continue" type="button" name="mo2f_scan_continue" class="button button-primary button-large" value="Continue" style="margin-left: 20%; margin-right: 8%;">
					<input id="mo2f_scan_cancel" type="button" name="mo2f_scan_cancel" class="button button-secondary button-large" value="Cancel">
				</div>
				<br>
				<div>
				<input type="checkbox" name="popup_hide" id="popup_hide" value="1"><b style="font-size: small;">Do not ask for confirmation again.</b></input>
				</div>
			</div>	
	</div>

<?php
function mo_mmp_start_scan() {
	if ( ( 'admin.php' !== basename( isset( $_SERVER['PHP_SELF'] ) ? sanitize_text_field( wp_unslash( $_SERVER['PHP_SELF'] ) ) : null ) ) || ( isset( $_GET['page'] ) && 'mo_mmp_malwarescan' !== sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) ) {//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification is not required here.
		return;
	}
	$decoded_scan_configuration = json_decode( get_site_option( 'mo_wpns_scan_status' ) );
	if ( ! isset( $decoded_scan_configuration ) ) {
		$status    = false;
		$scan_mode = false;
	} else {
		$status    = $decoded_scan_configuration->scan_progress;
		$scan_mode = $decoded_scan_configuration->scan_mode;
	}
	?>
	<script>
		var progress_bar,scan_progress,stop_scan_progress;
		var disabled="#b0d2cf";
		var active_scan="#2271b1";
		var errorClass="notice notice-error is-dismissible";
		var successClass="notice notice-success is-dismissible";
		var removeClass = "notice-error notice-success";
		var nonceMessage = "Nonce did not match.";
		var scanOngoingMessage="A scan is currently ongoing.";
		var scanCompleteMessage="Malware Scan has started. You can see the results in scan reports tab after it is completed.";
		var quickScanButtionID = "quick_scan_button";
		var customScanButtonID = "custom_scan_button";

		function set_active_button_with_button_value($active_button_id,$disabled_button2_id){
			document.getElementById($active_button_id).style.backgroundColor = active_scan;
			document.getElementById($disabled_button1_id).style.backgroundColor = disabled;
			document.getElementById($disabled_button2_id).style.backgroundColor = disabled;
			document.getElementById($active_button_id).value="Scanning...";
		}
		function set_active_button($active_button_id,$disabled_button1_id){
			document.getElementById($active_button_id).style.backgroundColor = active_scan;
			document.getElementById($disabled_button1_id).style.backgroundColor = disabled;
		}

		function mo_scan_message_rest(){
			jQuery('#mo_scan_message').show();
			jQuery('#mo_scan_message').empty();
			jQuery("#mo_scan_message").removeClass(removeClass);
		}

		function showMessage(addclass,message){
			jQuery("#mo_scan_message").addClass(addclass);
			jQuery("#mo_scan_message").append(message);
		}
		function showMessageWithscroll(addclass,message){
			jQuery("#mo_scan_message").addClass(addclass);
			jQuery("#mo_scan_message").append(message);
			window.scrollTo({ top: 0, behavior: "smooth"});
		}

		jQuery(document).ready(function(){
			var pop_up = "<?php echo esc_js( get_site_option( 'mo_wpns_hide_malware_popup' ) ); ?>";

			var newURL = location.href.split("&")[0];
			window.history.pushState('object', document.title, newURL);
			scan_progress= "<?php echo esc_js( $status ); ?>";
			stop_scan_progress= "<?php echo esc_js( get_site_option( 'mo_stop_scan' ) ); ?>";

			function set_scan(){

				document.getElementById("mo_progress").style.display="block";
				document.getElementById("mo2f_files_remaining").style.display = 'block';
				document.getElementById("mo2f_time_remaining").style.display = 'block';
				document.getElementById("mo2f_remaining").style.display = 'flex';

				document.getElementById("progress_message").innerHTML = "Scan progress...";
				document.getElementById("mo2f_files_remaining").innerHTML = "<span >Files Remaining</span> = <span style='color:green;'>Calculating...</span>";
				document.getElementById("mo2f_time_remaining").innerHTML = "<span >Time Remaining</span> =  <span style='color:green;'>Calculating...</span>";
				jQuery('input[name="mo_stop_button"]').val("Stop Scan");
				document.getElementById('mo_stop_button_div').style.display="block";
				document.getElementById("mo_mmp_progress_bar").style.width= 0 + "%";
				document.getElementById("mo_mmp_progress_bar").innerHTML= 0 + "%";
				progress_bar= setInterval(status_progress, 10000);

				jQuery('input[name="quick_scan_button"]').attr('disabled', true);
				jQuery('input[name="custom_scan_button"]').attr('disabled', true);

			}

		function scan_start_request(scan_type,scanButtonID){
			document.getElementById(scanButtonID).value = "Scanning...";
			var scanOption = new Map();

			if(pop_up == false){
				document.getElementById("mo2f_scan_confirm_modal").style.display="flex";
			}else{
				scanOption.set("action", "mo_wpns_malware_redirect");
				scanOption.set("call_type", "malware_scan_initiate");
				scanOption.set("scan", "scan_start");


				if(scan_type=="quick"){
					scanOption.set("quick_scan_button_backgroundColor", active_scan);
					scanOption.set("custom_scan_button_backgroundColor", disabled);
					scanOption.set("scantype", "quick_scan");
					scanOption.set("nonce_button", "wpns_scan_nonce");
					scanOption.set("scan_button", "quick_scan_button");
					scanOption.set("scan_button_value", "Quick Scan");

				}else if(scan_type=="custom"){
					scanOption.set("quick_scan_button_backgroundColor", disabled);
					scanOption.set("custom_scan_button_backgroundColor", active_scan);
					scanOption.set("scantype", "custom_scan");
					scanOption.set("nonce_button", "wpns_scan_nonce");
					scanOption.set("scan_button", "custom_scan_button");
					scanOption.set("scan_button_value", "Custom Scan");
				}
				scanOption.set("active_scanbutton_backgroundColor",disabled);
				set_scan();
				document.getElementById(quickScanButtionID).style.backgroundColor = scanOption.get("quick_scan_button_backgroundColor");
				document.getElementById(customScanButtonID).style.backgroundColor = scanOption.get("custom_scan_button_backgroundColor");
				var data={
					'action':'mo_wpns_malware_redirect',
					'call_type':'malware_scan_initiate',
					'scan':'scan_start',
					'scantype':scanOption.get("scantype"),
					'nonce':jQuery('#'+scanOption.get("nonce_button")).val()
				};

				jQuery.post(ajaxurl, data, function(response){
					console.log('malware_scan_initiate');
					mo_scan_message_rest();
					if(response == "scanning_already"){
						showMessageWithscroll(errorClass,scanOngoingMessage);
						document.getElementById(scanOption.get("scan_button")).value = scanOption.get("scantype");
						document.getElementById(scanOption.get("scan_button")).style.backgroundColor = disabled;
					}else{
						if(response=="ERROR"){
							showMessageWithscroll(errorClass,nonceMessage);
						}else if(response=="RECONFIGURE"){
							showMessageWithscroll(errorClass,"Please save your custom configuration again");
						}else{
							showMessage(successClass,scanCompleteMessage);

						}
					}

				});

			}
		}
		jQuery('#quick_scan_button').click(function(){
			scan_start_request("quick",quickScanButtionID);
		});
		jQuery('input[name="custom_scan_button"]').click(function(){
			scan_start_request("custom",customScanButtonID);
		});

		jQuery('input[name="mo_stop_button"]').click(function(){
			var button_value = document.getElementById("mo_stop_button").value;
			if(button_value == 'Stop Scan'){
				jQuery('input[name="mo_stop_button"]').attr('disabled', true);

				jQuery('input[name="mo_stop_button"]').val("Stop Scanning...");
				document.getElementById('mo_stop_button').style.backgroundColor = disabled;
				var data={
					'action':'mo_wpns_malware_redirect',
					'call_type':'malware_scan_terminate',
					'nonce': '<?php echo esc_js( wp_create_nonce( 'mmp-scan-settings' ) ); ?>'
				};
				jQuery("#mo_scan_message").removeClass(removeClass);
				jQuery.post(ajaxurl, data, function(response){
					jQuery('#mo_scan_message').show();
					jQuery('#mo_scan_message').empty();
					jQuery('input[name="quick_scan_button"]').attr('disabled', false);
					showMessageWithscroll(successClass,"Scan is stopping...");
					jQuery('input[name="quick_scan_button"]').val('Quick Scan');
					jQuery('input[name="custom_scan_button"]').attr('disabled', false);
					document.getElementById("mo_progress").style.display="none";
				});
			}else{
				document.getElementById("mo_progress").style.display="none";
				jQuery('#mo_scan_message').hide();
				jQuery('#mo_scan_message').empty();
				jQuery("#mo_scan_message").removeClass(removeClass);
			}
		});

		jQuery('input[name="mo2f_scan_continue"]').click(function(){
			var scan_type, nonce;

			document.getElementById("mo2f_scan_confirm_modal").style.display="none";
			set_scan();
			var quick_scan_value = document.getElementById(quickScanButtionID).value;
			var custom_scan_value = document.getElementById(customScanButtonID).value;

			if(quick_scan_value == 'Scanning...'){
				set_active_button(quickScanButtionID,customScanButtonID);
				scan_type = 'quick_scan';
				nonce = jQuery('#wpns_scan_nonce').val();
			}else{
				set_active_button(customScanButtonID,quickScanButtionID);

				scan_type = 'custom_scan';
				nonce = jQuery('#wpns_scan_nonce').val();
			}
			var popup_state = jQuery("input[name= popup_hide]:checked").val();
			var data={
				'action':'mo_wpns_malware_redirect',
				'call_type':'malware_scan_initiate',
				'scan':'scan_start',
				'scantype':scan_type,
				'nonce':nonce,
				'hide_popup':popup_state
			};
			jQuery.post(ajaxurl, data, function(response){
				console.log('malware_scan_initiate');
				mo_scan_message_rest();
				if(response == "scanning_already"){
					showMessageWithscroll(errorClass,scanOngoingMessage);
				}else{
					if(response=="ERROR"){
						showMessageWithscroll(errorClass,nonceMessage);
					}else{
						showMessage(successClass,scanCompleteMessage);
					}
				}

			});

		});

		jQuery('input[name="mo2f_scan_cancel"]').click(function(){
			document.getElementById(quickScanButtionID).value = "Quick Scan";
			document.getElementById(customScanButtonID).value = "Custom Scan";
			document.getElementById("mo2f_scan_confirm_modal").style.display="none";
		});


		var scan_modal_confirm = document.getElementById("mo2f_scan_confirm_modal");
		window.onclick = function(event) {
			if (event.target == scan_modal_confirm) {
				scan_modal_confirm.style.display = "none";
				document.getElementById(quickScanButtionID).value = "Quick Scan";
				document.getElementById(customScanButtonID).value = "Custom Scan";
			}
		}

	function convertSecondsToHHMMSS(secs){
			estimatedTime="<span style='color:green;'>Calculating...</span>";
			if(secs==0){
return estimatedTime;
			}
			var sec_num = parseInt(secs, 10);
			var hours   = Math.floor(sec_num / 3600);
			var minutes = Math.floor(sec_num / 60) % 60;
			var seconds = sec_num % 60;

			estimatedTime= [hours,minutes,seconds].map(v => v < 10 ? "0" + v : v).filter((v,i) => v !== "00" || i > 0).join(":");

			estimatedTime="<span style='color:green;'>"+estimatedTime+"</span><span style='color:green;'>s</span>";
			return estimatedTime;

		}

		function scan_response_status(scanset,serverResponse){
			document.getElementById("progress_message").innerHTML = scanset.get("progress_message");
			var bar= document.getElementById("mo_mmp_progress_bar");
			bar.style.width= 100 + "%";
			bar.innerHTML = 100 + "%";
			jQuery('input[name="quick_scan_button"]').removeAttr('disabled');
			document.getElementById(quickScanButtionID).style.backgroundColor = active_scan;
			document.getElementById(quickScanButtionID).value="Quick Scan";
			jQuery('input[name="custom_scan_button"]').removeAttr('disabled');
			document.getElementById(customScanButtonID).style.backgroundColor = active_scan;
			document.getElementById(customScanButtonID).value="Custom Scan";

			jQuery('#summary_all_scan_text').html(serverResponse['total_files']);
			jQuery('#summary_current_scan_text').html(serverResponse['scan_files']);
			jQuery('#summary_all_infect_text').html(serverResponse['total_mal']);
			jQuery('#summary_current_infect_text').html(serverResponse['mal_files']);
			jQuery('#summary_current_warning_text').html(serverResponse['warnings']);

			jQuery('#mo_scan_message').show();
			jQuery('#mo_scan_message').empty();
			showMessageWithscroll(scanset.get("message_class"),scanset.get("message_value"));

			jQuery('input[name="mo_stop_button"]').val("Dismiss bar");
			document.getElementById('mo_stop_button').style.backgroundColor = active_scan;
			jQuery('input[name="mo_stop_button"]').removeAttr('disabled');
			document.getElementById("mo2f_remaining").style.display = 'none';
			clearInterval(progress_bar);
		}
		function status_progress(){
			var data={
				'action':'mo_wpns_malware_redirect',
				'call_type':'malware_progress_bar',
				'nonce': '<?php echo esc_js( wp_create_nonce( 'mmp-scan-settings' ) ); ?>'   
			};
			jQuery.post(ajaxurl, data, function(response){

				var scanset = new Map();

				jQuery("#mo_scan_message").removeClass(removeClass);
				var bar= document.getElementById("mo_mmp_progress_bar");
				if(response['status']=="COMPLETE"){

					scanset.set("progress_message", "Scan completed");
					scanset.set("message_class", successClass);
					scanset.set("message_value", "Malware Scan is complete. You can see the results in scan reports tab now.");
					scan_response_status(scanset,response);

				}else if(response['status']=="ABORTED"){

					scanset.set("progress_message", "Scan Aborted");
					scanset.set("message_class", errorClass);
					scanset.set("message_value", "Malware Scan is aborted. You can check the results.");
					scan_response_status(scanset,response);

				}else{
					jQuery('#mo_scan_message').hide();
					jQuery('#mo_scan_message').empty();
					if(response['total'] === false || response['total'] == 0 || response['total'] == null){
						var width = 0;
					}else{
						var width= (response['scanned']/response['total'])*100;
						width = Math.round(width);
						var files_remain = response['total']-response['scanned'];
						files_remain = Math.round(files_remain);
						document.getElementById("mo2f_files_remaining").innerHTML="<span>Files Remaining </span>: <span style='color:green;'>"+files_remain+"</span>";

						var averageTimePerFile=response['AverageFileTime'];
						filesAlreadyProcessed = response['total_files_processed'];
						totalFilesToProcess= response['total']*(parseInt(response['extlink_check'])+ parseInt(response['repo_scan']) +1);
						remaining_files_to_process= totalFilesToProcess - filesAlreadyProcessed;
						estimatedTime= (remaining_files_to_process )* averageTimePerFile;
						estimatedTime= Math.ceil(estimatedTime);

						estimatedTime=convertSecondsToHHMMSS(estimatedTime);
						document.getElementById("mo2f_time_remaining").innerHTML="<span >Time Remaining</span>:  " +estimatedTime;

					}
					
					bar.style.width= width + "%";
					if(response['repo_scan']==1 && width==85){
						document.getElementById("progress_message").innerHTML= "Downloading files from WordPress repository...";
						bar.innerHTML = width + "%";
					}else{
						document.getElementById("progress_message").innerHTML= "Scan in progress. It may take some time...";
						bar.innerHTML = width + "%";
						setTimeout(function(){
							document.getElementById("progress_message").innerHTML= "Scan Complete.";
							bar.style.width= "100%";
							bar.innerHTML = "100%";
						},600000);
					}
				}
			});
		}
	});
	</script>
	<?php
}
function mo_mmp_show_summary() {
	$mo_wpns_db_handler = new MoMmpDB();
	$send_id            = 1;
	$report_count       = $mo_wpns_db_handler->count_scans_done();
	add_site_option( 'mo_mmp_scans_done', $report_count );
	if ( is_null( $send_id ) ) {
		$total_scan          = 0;
		$total_malicious     = 0;
		$last_scan           = 0;
		$malicious_last_scan = 0;
		$warning_last_scan   = 0;
	} else {
		$total_scan          = $mo_wpns_db_handler->count_files();
		$total_malicious     = $mo_wpns_db_handler->count_malicious_files();
		$last_scan           = $mo_wpns_db_handler->count_files_last_scan( $send_id );
		$malicious_last_scan = get_site_option( 'mo_mmp_infected_files', 0 );
		$warning_last_scan   = get_site_option( 'mo_mmp_warning_files', 0 );
		if ( $total_scan > 999 ) {
			$total_scan = ( $total_scan / 1000 );
			$total_scan = round( $total_scan, 1 ) . 'k';
		}
		if ( $total_malicious > 999 ) {
			$total_malicious = ( $total_malicious / 1000 );
			$total_malicious = round( $total_malicious, 1 ) . 'k';
		}
		if ( $last_scan > 999 ) {
			$last_scan = ( $last_scan / 1000 );
			$last_scan = round( $last_scan, 1 ) . 'k';
		}
	}
	?>
	<div class="mo_wpns_sub_scansummary mo_wpns_msdivl" id="summary_all_scan">
		<div class="title_hdiv"><b>Total Files Scanned</b></div>
		<hr class="line">
		<p class=" mo_wpns_scan_summary_text" id="summary_all_scan_text"> <?php echo esc_html( $total_scan ); ?> </p>
	</div>
	<div class="mo_wpns_sub_scansummary mo_wpns_msdivr mo_wpns_msdivl" id="summary_all_infect">
		<div class="title_hdiv"><b>Total Infected Files</b></div>
		<hr class="line">
		<p class=" mo_wpns_scan_summary_text" id="summary_all_infect_text"> <?php echo esc_html( $total_malicious ); ?> </p>
	</div>
	<div class="mo_wpns_sub_scansummary mo_wpns_msdivl mo_wpns_msdivr" id="summary_current_scan">
		<div class="title_hdiv"><b>Files scanned in last scan</b></div>
		<hr class="line">
		<p class=" mo_wpns_scan_summary_text" id="summary_current_scan_text"> <?php echo esc_html( $last_scan ); ?> </p>
	</div>
	<div class="mo_wpns_sub_scansummary mo_wpns_msdivl mo_wpns_msdivr" id="summary_current_infect">
		<div class="title_hdiv"><b>Infections in last scan</b></div>
		<hr class="line">
		<p class=" mo_wpns_scan_summary_text" id="summary_current_infect_text"> <?php echo esc_html( $malicious_last_scan ); ?> </p>
	</div>
	<div class="mo_wpns_sub_scansummary mo_wpns_msdivr" id="summary_current_warning">
		<div class="title_hdiv"><b>Warnings in last scan</b></div>
		<hr class="line">
		<p class=" mo_wpns_scan_summary_text" id="summary_current_warning_text"> <?php echo esc_html( $warning_last_scan ); ?> </p>
	</div>

	<?php
}

