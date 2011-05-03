<?php
	include_once("config.php");
	function generate_password()
	{
		global $password_len;
		$password = "";

		$pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$psz = strlen($pool);
		for ($i = 0; $i < $password_len; ++$i)
			$password .= substr($pool, mt_rand(0, $psz - 1), 1);
		return $password;
	}
?>
