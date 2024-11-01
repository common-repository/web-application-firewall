<?php

class MoMmpUtility {

	public static function check_empty_or_null( $value ) {
		if ( ! isset( $value ) || empty( $value ) ) {
			return true;
		}
		return false;
	}

	public static function get_client_ip() {
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( $_SERVER['REMOTE_ADDR'] );
		}

		return '';
	}

	function sendIpBlockedNotification( $ip_address, $reason ) {
		$subject     = 'User with IP address ' . $ip_address . ' is blocked | ' . get_bloginfo();
		$toEmail     = get_option( 'admin_email_address' );
			$content = '';
		if ( get_option( 'custom_admin_template' ) ) {
			$content = get_option( 'custom_admin_template' );
			$content = str_replace( '##ipaddress##', $ip_address, $content );
		} else {
			$content = $this->getMessageContent( $reason, $ip_address );
		}
		if ( isset( $content ) ) {
			return $this->wp_mail_send_notification( $toEmail, $subject, $content );
		}

	}

	function wp_mail_send_notification( $toEmail, $subject, $content ) {
		$headers = array( 'Content-Type: text/html; charset=UTF-8' );
		wp_mail( $toEmail, $subject, $content, $headers );

	}

	// Check if null what will be the message
	function getMessageContent( $reason, $ip_address, $username = null, $fromEmail = null ) {
		switch ( $reason ) {
			case MoMmpConstants::LOGIN_ATTEMPTS_EXCEEDED:
				$content = 'Hello,<br><br>The user with IP Address <b>' . $ip_address . '</b> has exceeded allowed failed login attempts on your website <b>' . get_bloginfo() . '</b> and we have blocked his IP address for further access to website.<br><br>You can login to your WordPress dashaboard to check more details.<br><br>Thanks,<br>miniOrange';
				return $content;
			case MoMmpConstants::IP_RANGE_BLOCKING:
				$content = "Hello,<br><br>The user's IP Address <b>" . $ip_address . '</b> was found in IP Range specified by you in Advanced IP Blocking and we have blocked his IP address for further access to your website <b>' . get_bloginfo() . '</b>.<br><br>You can login to your WordPress dashaboard to check more details.<br><br>Thanks,<br>miniOrange';
				return $content;
			case MoMmpConstants::LOGGED_IN_FROM_NEW_IP:
				$content = 'Hello ' . $username . ',<br><br>Your account was logged in from new IP Address <b>' . $ip_address . '</b> on website <b>' . get_bloginfo() . "</b>. Please <a href='mailto:" . $fromEmail . "'>contact us</a> if you don't recognise this activity.<br><br>Thanks,<br>" . get_bloginfo();
				return $content;
			case MoMmpConstants::FAILED_LOGIN_ATTEMPTS_FROM_NEW_IP:
				$subject = 'Someone trying to access you account | ' . get_bloginfo();
				$content = 'Hello ' . $username . ',<br><br>Someone tried to login to your account from new IP Address <b>' . $ip_address . '</b> on website <b>' . get_bloginfo() . "</b> with failed login attempts. Please <a href='mailto:" . $fromEmail . "'>contact us</a> if you don't recognise this activity.<br><br>Thanks,<br>" . get_bloginfo();
				return $content;
			default:
				if ( is_null( $username ) ) {
					$content = 'Hello,<br><br>The user with IP Address <b>' . $ip_address . '</b> has exceeded allowed trasaction limit on your website <b>' . get_bloginfo() . '</b> and we have blocked his IP address for further access to website.<br><br>You can login to your WordPress dashaboard to check more details.<br><br>Thanks,<br>miniOrange';
				} else {
					$content = 'Hello ' . $username . ',<br><br>Your account was logged in from new IP Address <b>' . $ip_address . '</b> on website <b>' . get_bloginfo() . "</b>. Please <a href='mailto:" . $fromEmail . "'>contact us</a> if you don't recognise this activity.<br><br>Thanks,<br>" . get_bloginfo();
				}
				return $content;
		}
	}
}
