<?PHP // © THD@GGD 2017-2020

/**
  * Photosec app API
  *
  * @author Thijs Houtenbos
  * @version 0.2.0
  * @package Photosec
  * @subpackage API
  */


  // Include required files
  require_once '../.server/config.inc.local.php';
  require_once 'classes/classes.inc.php';


  // Set cache headers
  $date = gmdate("D, d M Y H:i:s") . " GMT";
  header("Expires: $date");
  header("Last-Modified: $date");
  header("Pragma: no-cache");
  header("Cache-Control: no-cache, must-revalidate");


  // If system is offline show message
  if (config::offline) { new response_redirect('/offline.html'); }


  // Handle an API call
  $call = isset($_GET['call']) ? $_GET['call'] : '';
  $method = $_SERVER['REQUEST_METHOD'];
  photosec::log($call, security::ip(), $method, v::read_all($method));
  switch ($call) {


    // qr            GET           Generate JWT QR code
    case 'qr':
      if ($method !== 'GET') { new response_method_not_allowed(); }
      $app  = v::read_valid('app', v::VAR_LABEL, v::GET);
      if (!isset(config::$apps[$app])) { new response_bad_request("Invalid app specified"); }
      $code       = v::read_valid('code', v::VAR_CODE, v::GET);
      $user       = v::read_valid('user', v::VAR_USER, v::GET);
      $time       = v::read_valid('time', v::VAR_INTEGER, v::GET);
      $inactivity = isset($_GET['inactivity']) ? v::read_valid('inactivity', v::VAR_INTEGER, v::GET) : 14400; // Optional
      if ($time < 600) { new response_bad_request("Time too short (less than 10 minutes)"); }
      if ($time > 31536000) { new response_bad_request("Time too long (over 1 year)"); }
      if ($inactivity < 600) { new response_bad_request("Inactivity too short (less than 10 minutes)"); }
      if ($inactivity > 31536000) { new response_bad_request("Inactivity too long (over 1 year)"); }
      $jwt = photosec::jwt_encode(array(
        'iat'       => time(), // Issued at time
        'exp'       => time() + $time, // Expites at time
        // 'iss'       => 'Photosec', // Issuer
        'app'       => $app, // App issued for
        'url'       => config::security_domain, // This API URL
        'jti'       => $code, // Case sensitive unique identifier of the token even among different issuers.
        'sub'       => $user, // Subject = user
        'types'     => array(
          // 'png',
          'jpg',
          'jpeg',
        ),
        'active'    => false,
        'nr'        => 0,
        'inactivity'=> $inactivity
      ));
      photosec::qr_encode($jwt);
      break;


    // scan          POST          Scan JTW QR code + activate
    case 'scan':
      if ($method !== 'POST') { new response_method_not_allowed(); }
      $jwt = v::read_valid('jwt', v::VAR_JWS, v::POST);
      try {
        $data = photosec::jwt_decode($jwt);
      } catch (Exception $e) {
        new response_invalid_jwt();
      }

      // Check shorter time frame
      // @todo

      // Check for double activation
      // @todo

      // Activate JWT and return
      $data['active'] = true;
      echo photosec::jwt_encode($data);
      break;


    // send          POST          Send file to app
    case 'send':
      if ($method !== 'POST') { new response_method_not_allowed(); }
      $jwt = v::read_valid('jwt', v::VAR_JWS, v::POST);
      $file = v::read_valid('file', v::VAR_FILE, v::POST);
      try {
        $data = photosec::jwt_decode($jwt);
      } catch (Exception $e) {
        new response_invalid_jwt();
      }

      // Check file upload content
      // @todo

      // Handle file upload
      $result = photosec::send_file($file, $data);
      if (!$result) {
        // DEBUG log
        photosec::log('FAILED SENDING FILE TO APPLICATION', '0.0.0.0', 'POST');
        new response_failed_sending_file();
      }

      // Count JWT nr and return
      $data['nr']++;
      echo photosec::jwt_encode($data);
      break;


    // Default response
    default:
      new response_forbidden();
      break;


  }


?>