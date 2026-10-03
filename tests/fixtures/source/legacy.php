<?php
$ct = openssl_encrypt($data, 'des-ede3-cbc', $key, OPENSSL_RAW_DATA, $iv);
