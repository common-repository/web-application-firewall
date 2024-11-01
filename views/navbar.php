<?php

	echo '<div class="wrap">
			<div><img  style="float:left;margin-top:5px;" src="' . esc_url( $logo_url ) . '"></div>
			<h1>
				miniOrange Firewall &nbsp;
			</h1></div>';?>
	<br>
	<div class="nav-tab-wrapper">
		<?php
		echo '<a id="mo_2fa_waf" class="nav-tab ' . ( 'mo_mmp_dashboard' === $active_tab ? 'nav-tab-active' : '' ) . '" href="' . esc_url( $dashboard_url ) . '"><span class="dashicons dashicons-dashboard"></span>Dashboard</a>';
		echo '<a id="mo_2fa_waf" class="nav-tab ' . ( 'mo_mmp_waf' === $active_tab ? 'nav-tab-active' : '' ) . '" href="' . esc_url( $waf ) . '"><span class="dashicons dashicons-shield"></span>Firewall</a>';
		echo '<a id="malware_tab" class="nav-tab ' . ( 'mo_mmp_malwarescan' === $active_tab ? 'nav-tab-active' : '' ) . '" href="' . esc_url( $scan_url ) . '"><span class="dashicons dashicons-search"></span>Malware Scan</a>';
		?>
	</div>
