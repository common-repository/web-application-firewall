<?php

class MoMmpMessages {

	const INVALID_IP             = 'Please enter a valid IP address.';
	const IP_ALREADY_WHITELISTED = 'IP Address is already Whitelisted.';
	const IP_IN_WHITELISTED      = 'IP Address is Whitelisted. Please remove it from the whitelisted list.';

	const NOTIFY_ON_IP_BLOCKED             = 'Email notification is enabled for Admin.';
	const DONOT_NOTIFY_ON_IP_BLOCKED       = 'Email notification is disabled for Admin.';
	const NOTIFY_ON_UNUSUAL_ACTIVITY       = 'Email notification is enabled for user for unusual activities.';
	const DONOT_NOTIFY_ON_UNUSUAL_ACTIVITY = 'Email notification is disabled for user for unusual activities.';

	const INVALID_IP_FORMAT = 'Please enter Valid IP Range.';

	const UNKNOWN_ERROR  = 'Error processing your request. Please try again.';
	const FEEDBACK       = "<div class='custom-notice notice notice-warning feedback-notice'><p><p class='notice-message'>Looking for a feature? Help us make the plugin better. Send us your feedback using the Support Form below.</p><button class='feedback notice-button'><i>Dismiss</i></button></p></div>";
	const WHITELIST_SELF = "<div class='custom-notice notice notice-warning whitelistself-notice'><p><p class='notice-message'>It looks like you have not whitelisted your IP. Whitelist your IP as you can get blocked from your site.</p><button class='whitelist_self notice-button'><i>WhiteList</i></button></p></div>";

	const NEW_PLUGIN_THEME_CHECK = "<div class='custom-notice notice notice-warning new_plugin_theme-notice' style='background:#ff6666;'><p class='notice-message' style='font-weight:700;font-size:20px;height:20%;'>The miniOrange Web Application Firewall plugin will be removed from WordPress soon as it is no longer maintained by miniOrange.</p></div>";

	public static function showMessage( $message, $data = array() ) {
		$message = constant( 'self::' . $message );
		foreach ( $data as $key => $value ) {
			$message = str_replace( '{{' . $key . '}}', $value, $message );
		}
		return $message;
	}

}


