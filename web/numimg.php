<?php

session_name('numimg');
session_start();

$im = imagecreate(80, 20);

$string = 'PHP';

$bg = imagecolorallocate($im, 0, 0, 0);
for ($i = 0; $i < 4; ++$i) {
	$filename = sprintf("number/%s.png", substr($_SESSION['rndstr'], $i, 1));
	$digitimg = imagecreatefrompng($filename);
	imagetruecolortopalette($digitimg, false, 2);
	$coloridx = imagecolorclosest($digitimg, 255, 255, 255);
	$r = rand(90, 255);
	$g = rand(90, 255);
	$b = rand(90, 255);
	imagecolorset($digitimg, $coloridx, $r, $g, $b);
	imagecopymerge($im, $digitimg, $i * 20, 0, 0, 0, 13, 20, 70);
}

for ($i = 0; $i < 8; ++$i) {
	$color = false;
	while (!$color) {
		$r = rand(0, 128);
		$g = rand(0, 128);
		$b = rand(0, 128);
		$color = imagecolorallocate($im, $r, $g, $b);
	}

	$ax = rand(0, 80);
	$ay = rand(0, 20);
	$bx = rand(0, 80);
	$by = rand(0, 20);
	imageline($im, $ax, $ay, $bx, $by, $color);
}

header('Content-type: image/png');
imagepng($im);

?>
