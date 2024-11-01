<?php
global $mo_mo_wpns_utility,$mmp_dir_name;
$setup_dir_name = $mmp_dir_name . 'views' . DIRECTORY_SEPARATOR . 'link_tracers.php';
require $setup_dir_name;

?>
<div id="wpns_message" style=" padding-top:8px"></div>
<div class="nav-tab-wrapper">
	<button class="nav-tab tablinks" onclick="waf_function(event, 'settings')" id="settingsTab">Settings</button>
	<button class="nav-tab tablinks" onclick="waf_function(event, 'block_list')" id="BlockWhiteTab" >IP Blacklist</button>
</div>
<br>

<div id="block_list" class="tabcontent">

	<div class="mo_wpns_divided_layout">
		<div class="mo_wpns_setting_layout">
					<h2>Manual IP Blocking <a href='<?php echo esc_url( $mo_mmp_premium_docfile['Manual IP Blocking'] ); ?>' target="_blank"><span class="dashicons dashicons-external mo_wpns_doc_link" title="More information.."></span></a></h2>

					<h4 class="mo_wpns_setting_layout_inside">Manually block an IP address here:&emsp;&emsp;
					<input type="text" name="ManuallyBlockIP" id="ManuallyBlockIP" required placeholder='IP address'pattern="((^|\.)((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]?\d))){4}" style="width: 35%; height: 41px" />&emsp;&emsp;
					<input type="button" name="BlockIP" id="BlockIP" value="Manual Block IP" class="button button-primary button-large" />
					</h4>

					<h3 class="mo_wpns_setting_layout_inside"><b>Blocked IP's</b>
					</h3>
					<h4 class="mo_wpns_setting_layout_inside">&emsp;&emsp;&emsp;

			<div id="blockIPtable">
				<table id="blockedips_table" class="display">
				<thead><tr><th>IP Address&emsp;&emsp;</th><th>Reason&emsp;&emsp;</th><th>Blocked Until&emsp;&emsp;</th><th>Blocked Date&emsp;&emsp;</th><th>Action&emsp;&emsp;</th></tr></thead>
				<tbody>
<?php
			$mo_wpns_handler = new MoMmpHandler();
			$blockedips      = $mo_wpns_handler->get_blocked_ips();
			$whitelisted_ips = $mo_wpns_handler->get_whitelisted_ips();
			$disabled        = '';
			global $mmp_dir_name;
foreach ( $blockedips as $blockedip ) {
	echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $blockedip->ip_address ) . '</td><td>' . esc_html( $blockedip->reason ) . '</td><td>';
	if ( empty( $blockedip->blocked_for_time ) ) {
		echo '<span class=redtext>Permanently</span>';
	} else {
		echo esc_html( gmdate( 'M j, Y, g:i:s a', $blockedip->blocked_for_time ) );
	}
	echo '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', intval( $blockedip->created_timestamp ) ) ) . '</td><td><a ' . esc_attr( $disabled ) . " onclick=unblockip('" . esc_js( $blockedip->id ) . "')>Unblock IP</a></td></tr>";
}
?>
					</tbody>
					</table>
			</div>	
				</h4>
		</div>
		<div class="mo_wpns_setting_layout">
					<h2>IP Whitelisting <a href='<?php echo esc_url( $mo_mmp_premium_docfile['IP Whitelisting'] ); ?>' target="_blank"><span class="dashicons dashicons-external mo_wpns_doc_link" title="More information.."></span></a></h2>
					<h4 class="mo_wpns_setting_layout_inside">Add new IP address to whitelist:&emsp;&emsp;
					<input type="text" name="IPWhitelist" id="IPWhitelist" required placeholder='IP address'pattern="((^|\.)((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]?\d))){4}" style="width: 40%; height: 41px"/>&emsp;&emsp;
					<input type="button" name="WhiteListIP" id="WhiteListIP" value="Whitelist IP" class="button button-primary button-large" />

					</h4>
					<h3 class="mo_wpns_setting_layout_inside">Whitelist IP's
					</h3>
					<h4 class="mo_wpns_setting_layout_inside">&emsp;&emsp;&emsp;

			<div id="WhiteListIPtable">
				<table id="whitelistedips_table" class="display">
				<thead><tr><th>IP Address</th><th>Whitelisted Date</th><th>Remove from Whitelist</th></tr></thead>
				<tbody>
<?php
foreach ( $whitelisted_ips as $whitelisted_ip ) {
	echo "<tr class='mo_wpns_not_bold'><td>" . esc_html( $whitelisted_ip->ip_address ) . '</td><td>' . esc_html( gmdate( 'M j, Y, g:i:s a', $whitelisted_ip->created_timestamp ) ) . '</td><td><a ' . esc_attr( $disabled ) . " onclick=removefromwhitelist('" . esc_js( $whitelisted_ip->id ) . "')>Remove</a></td></tr>";
}

echo '			</tbody>
			</table>';
?>
			</div>
				</h4>
		</div>					
</div>

</div>

<div id="settings" class="tabcontent">


<?php

	$admin_url = admin_url();
	$url       = explode( '/wp-admin/', $admin_url );
	$url       = $url[0] . '/htaccess';

	$nameDownload = 'Backup.htaccess';

?>
<div class="mo_wpns_divided_layout">
	<div class="mo_wpns_setting_layout">
	<table style="width:100%">
		<tr><th align="left">
		<h3>Website firewall on plugin level:<a href='<?php echo esc_url( $mo_mmp_premium_docfile['Plugin level waf'] ); ?>' target="_blank"><span class="	dashicons dashicons-external mo_wpns_doc_link" title="More information.."></span></a>
			<br>
			<p><i class="mo_wpns_not_bold">This will activate WAF after the WordPress load. This will block illegitimate requests after making connection to WordPress. This will check Every Request in plugin itself.</i></p>
		  </th><th align="right">
		  <label class='mo_wpns_switch'>
		 <input type=checkbox id='pluginWAF' name='pluginWAF' />
		 <span class='mo_wpns_slider mo_wpns_round'></span>
		</label>
		</tr></th>
		 </h3>
		 </table>
<?php
		$WAFactivate = get_option( 'WAFEnabled' );
		$WAFactivate = $WAFactivate == 1 ? '' : 'disabled';
echo "<a href='" . esc_url( $url ) . "' download='" . esc_attr( $nameDownload ) . "'>";
?>
	</div>	

	</div>	


	</div>



<script type="text/javascript">
	jQuery(document).ready(function(){
		jQuery('#resultsIPLookup').empty();
		var WAF 			= "<?php echo esc_js( get_option( 'WAF' ) ); ?>";
		var wafE 			= "<?php echo esc_js( get_option( 'WAFEnabled' ) ); ?>";

		if(wafE=='1')
		{	
	
			if(WAF == 'PluginLevel')
			{
				jQuery('#pluginWAF').prop("checked",true);
			}
		}

		jQuery('#pluginWAF').click(function(){

			var pluginWAF = jQuery("input[name='pluginWAF']:checked").val();
			var nonce = '<?php echo esc_js( wp_create_nonce( 'loginsecuritynonce' ) ); ?>';

			if(pluginWAF != '')
			{

				var data = {
				'action'					: 'wpns_login_security',
				'wpns_loginsecurity_ajax' 	: 'wpns_waf_settings_form',
				'optionValue' 				: 'WAF',
				'pluginWAF'					:  pluginWAF,
				'nonce'						:  nonce
				};
				jQuery.post(ajaxurl, data, function(response) {
						var response = response.replace(/\s+/g,' ').trim();
						if(response == "PWAFenabled")
						{
							jQuery("#mo_waf_notice").hide();
							jQuery('#wpns_message').empty();
							jQuery('#wpns_message').append("<div class= 'notice notice-success is-dismissible' style='mmm  ' >&nbsp; &nbsp; WAF  is enabled on Plugin level</div>");
							window.scrollTo({ top: 0, behavior: 'smooth'});
							window.onload = nav_popup();

						}
						else if(response == 'PWAFdisabled')
						{
							jQuery("#mo_waf_notice").hide();

							jQuery('#wpns_message').empty();
							jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; WAF is disabled on plugin level.</div>");
							window.scrollTo({ top: 0, behavior: 'smooth'});
							window.onload = nav_popup();
						}
						else if(response == 'NotWritable')
						{
							jQuery('#wpns_message').empty();
							jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; File permission denied for wp-content/uploads folder. </div>");
							window.scrollTo({ top: 0, behavior: 'smooth'});
							window.onload = nav_popup();
						}
						else
						{
							jQuery('#wpns_message').empty();
							jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; An unknown Error has occured </div>");
							window.scrollTo({ top: 0, behavior: 'smooth'});
							window.onload = nav_popup();
						}
				});

			}
		});

jQuery('#SettingPage').click(function(){
	document.getElementById("settingsTab").click();
	window.scrollTo({ top: 0, behavior: 'smooth' });
});
jQuery('#IPBlockingWhitelistPage').click(function(){
	document.getElementById("BlockWhiteTab").click();
	window.scrollTo({ top: 0, behavior: 'smooth' });
});

var tab = localStorage.getItem("lastTab");
if(tab == "settings")
{
	document.getElementById("settingsTab").click();	
}

else if(tab == "block_list")
{
	document.getElementById("BlockWhiteTab").click();	
}
else 
{
	document.getElementById("settingsTab").click();	
}

jQuery('#BlockIP').click(function(){
	var ip 	= jQuery('#ManuallyBlockIP').val();

	var nonce = '<?php echo esc_js( wp_create_nonce( 'loginsecuritynonce' ) ); ?>';
	if(ip != '')
	{
		var data = {
		'action'					: 'wpns_login_security',
		'wpns_loginsecurity_ajax' 	: 'wpns_ManualIPBlock_form', 
		'IP'						:  ip,
		'nonce'						:  nonce,
		'option'					: 'mo_wpns_manual_block_ip'
		};
		jQuery.post(ajaxurl, data, function(response) {
				var response = response.replace(/\s+/g,' ').trim();
				if(response == 'empty IP')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP can not be blank.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
				}
				else if(response == 'already blocked')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP is already blocked.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
				}
				else if(response == "INVALID_IP_FORMAT")
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP does not match required format.</div>");
						window.scrollTo({ top: 0, behavior: 'smooth'});
						window.onload = nav_popup();

				}
				else if(response == "IP_IN_WHITELISTED")
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP is whitelisted can not be blocked.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();

				}
				else
				{
					jQuery('#wpns_message').empty();
					refreshblocktable(response);
					jQuery('#wpns_message').append("<div class= 'notice notice-success is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP Blocked Sucessfully.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
				}

		});
	}

});
jQuery('#WhiteListIP').click(function(){

	var ip 	= jQuery('#IPWhitelist').val();

	var nonce = '<?php echo esc_js( wp_create_nonce( 'loginsecuritynonce' ) ); ?>';
	if(ip != '')
	{
		var data = {
		'action'					: 'wpns_login_security',
		'wpns_loginsecurity_ajax' 	: 'wpns_WhitelistIP_form', 
		'IP'						:  ip,
		'nonce'						:  nonce,
		'option'					: 'mo_wpns_whitelist_ip'
		};
		jQuery.post(ajaxurl, data, function(response) {
				
				var response = response.replace(/\s+/g,' ').trim();
				if(response == 'EMPTY IP')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP can not be empty.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();

				}
				else if(response == 'INVALID_IP')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP does not match required format.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
	
				}
				else if(response == 'IP_ALREADY_WHITELISTED')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP is already whitelisted.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
	
				}
				else
				{	
					jQuery('#wpns_message').empty();
					refreshWhiteListTable(response);	
					jQuery('#wpns_message').append("<div class= 'notice notice-success is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP whitelisted Sucessfully.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
			
				}
		});
					
	}

});

jQuery("#blockedips_table").DataTable({
				"order": [[ 3, "desc" ]]
			});
jQuery("#whitelistedips_table").DataTable({
				"order": [[ 1, "desc" ]]
			});

});
function unblockip(id) {
  var nonce = '<?php echo esc_js( wp_create_nonce( 'loginsecuritynonce' ) ); ?>';
	if(id != '')
	{
		var data = {
		'action'					: 'wpns_login_security',
		'wpns_loginsecurity_ajax' 	: 'wpns_ManualIPBlock_form', 
		'id'						:  id,
		'nonce'						:  nonce,
		'option'					: 'mo_wpns_unblock_ip'
		};
		jQuery.post(ajaxurl, data, function(response) {
			var response = response.replace(/\s+/g,' ').trim();
			if(response=="UNKNOWN_ERROR")
			{	
				jQuery('#wpns_message').empty();
				jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; Unknow Error occured while unblocking IP.</div>");
				window.scrollTo({ top: 0, behavior: 'smooth'});
				window.onload = nav_popup();
			}
			else
			{
				jQuery('#wpns_message').empty();
				refreshblocktable(response);
				jQuery('#wpns_message').append("<div class= 'notice notice-success is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP UnBlocked Sucessfully.</div>");
				window.scrollTo({ top: 0, behavior: 'smooth'});
				window.onload = nav_popup();
			}
		});
					
	}
}
function removefromwhitelist(id)
{
	var nonce = '<?php echo esc_js( wp_create_nonce( 'loginsecuritynonce' ) ); ?>';
	if(id != '')
	{
		var data = {
		'action'					: 'wpns_login_security',
		'wpns_loginsecurity_ajax' 	: 'wpns_WhitelistIP_form', 
		'id'						:  id,
		'nonce'						:  nonce,
		'option'					: 'mo_wpns_remove_whitelist'
		};
		jQuery.post(ajaxurl, data, function(response) {
				var response = response.replace(/\s+/g,' ').trim();
				if(response == 'UNKNOWN_ERROR')
				{
					jQuery('#wpns_message').empty();
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; Unknow Error occured while removing IP from Whitelist.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();
				}
				else
				{
					jQuery('#wpns_message').empty();
					refreshWhiteListTable(response);	
					jQuery('#wpns_message').append("<div class= 'notice notice-error is-dismissible' style='mmm  ' >&nbsp; &nbsp; IP removed from Whitelist.</div>");
					window.scrollTo({ top: 0, behavior: 'smooth'});
					window.onload = nav_popup();		
				}
		});
					
	}
}
function waf_function(evt, cityName) {
	var i, tabcontent, tablinks;
	tabcontent = document.getElementsByClassName("tabcontent");
	for (i = 0; i < tabcontent.length; i++) {
		tabcontent[i].style.display = "none";
	}
	tablinks = document.getElementsByClassName("tablinks");
	for (i = 0; i < tablinks.length; i++) {
		tablinks[i].className = tablinks[i].className.replace(" nav-tab-active", "");
	}
	document.getElementById(cityName).style.display = "block";

	localStorage.setItem("lastTab",cityName);
	evt.currentTarget.className += " nav-tab-active";
}
function refreshblocktable(html)
{
	 jQuery('#blockIPtable').html(html);
}

function refreshWhiteListTable(html)
{
	 
	 jQuery('#WhiteListIPtable').html(html);	
}

function nav_popup() {
//   document.getElementById("notice_div").style.width = "40%";
  setTimeout(function(){ $('#notice_div').fadeOut('slow'); }, 3000);
}
</script>

	

