<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
<title>Create account -- Gateway6 HTTP Server</title>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
</head>

<body>
<?php
	session_name('numimg');
	session_start();
	$rndval = rand(0, 9999);
	$rndstr = sprintf("%04d", $rndval);
	$_SESSION['rndstr'] = $rndstr;
?>
	<center>
	<form action="confirm.php" method="post">
	<table>
	<tr>
		<td align="right"><strong>Login-ID:</strong></td>
		<td align="left"><input type="text" name="loginid" size="10">(3 to 32 charactors of alpha or number)</td>
	</tr> 
	<tr>
		<td align="right"><strong>E-Mail:</strong></td>
		<td align="left"><input type="text" name="email" size="40"></td>
	</tr> 
	<tr>
		<td align="right"><img src="numimg.php"></td>
		<td align="left"><input type="text" name="numval" size="10"></td>
	</tr> 
	<tr>
		<td align="center" colspan="2"><input type="submit" value="Submit"></td>
	</tr>
	</table>
	</center>
</body>
</html>
