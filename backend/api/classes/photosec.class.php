<?PHP // © THD@GGD 2017-2019

/**
  * Photosec
  *
  * @author Thijs Houtenbos
  * @version 0.1.1
  * @package Photosec
  * @subpackage API
  */


  use \Firebase\JWT\JWT;


/**
  * Photosec Class
  *
  * All functions that are called in the IC app are executed here.
  *
  * @package Photosec
  * @subpackage API
  */
  class photosec {


  /**
    * Encode array of data to JWT
    *
    * Data is returned as encoded valid JWT.
    *
    * JWT encoding is handled by PHP-JWT {@link https://github.com/firebase/php-jwt}
    *
    * @param array|string $data The data to be encoded as JWT
    * @return string JWT data
    */
    public static function jwt_encode($data = array()) {
      return JWT::encode($data, config::security_jwt_key, config::security_jwt_alg);
    }


  /**
    * Decode JWT data
    *
    * JWT encoding is handled by PHP-JWT {@link https://github.com/firebase/php-jwt}
    *
    * @param string $jwt JWT encoded data
    * @return array the data
    */
    public static function jwt_decode($jwt) {
      return (array) JWT::decode($jwt, config::security_jwt_key, array(config::security_jwt_alg));
    }


  /**
    * QR encode data
    *
    * Output a PNG with the encoded data.
    *
    * QR encoding is handled by PHP-QR-code {@link https://github.com/ziplr/php-qr-code}
    *
    * Developers note: QR_ECLEVEL_H gives most redundancy, QR_ECLEVEL_L the least
    *
    * @param string data
    * @return void
    */
    public static function qr_encode($data) {
      QRcode::png($data, false, QR_ECLEVEL_L, config::security_qr_size, 0);
    }


  /**
    * Send a file
    *
    * For now the file is assumed to be a photo
    *
    * @param string $file
    * @param array[string]string $data
    * @return boolean success
    */
    public static function send_file($file, $data) {
      $url = config::$apps[$data['app']]['url'];
      $post = config::$apps[$data['app']]['post'];

      // @todo add filetype doublecheck

      // File matches format: '/^(data:)([a-z]+\/[a-z]+);base64,.*$/'
      $file_components = explode(',', $file);
      $file = base64_decode($file_components[1]);

      // HTTP POST SETTING
      $multipart_boundary = '-----' . microtime(true) . '-----';
      $user = $data['sub'];
      $code = $data['jti'];
      $filename = 'foto.jpg';
      $type = 'jpg';

      // Assemble POST content
      $content =  "--$multipart_boundary\r\n";
      foreach ($post as $name => $value) {
        if ($value=='$file') {
          // Upload the file
          $content .= "Content-Disposition: form-data; name=\"$name\"; filename=\"" . basename($filename) . "\"\r\n";
          $content .= "Content-Type: image/jpeg\r\n\r\n";
          $content .= "$file\r\n";
        } else {
          // Add normal variable
          if ($value=='$user') { $value = $user; }
          if ($value=='$code') { $value = $code; }
          if ($value=='$type') { $value = $type; }
          $content .= "Content-Disposition: form-data; name=\"$name\"\r\n\r\n";
          $content .= "$value\r\n";
        }
        // Add boundary
        $content .= "--$multipart_boundary\r\n";
      }

      // POST file to app
      try {
        $response = @file_get_contents($url, false, stream_context_create(array(
          'http' => array(
            'header'  => "Content-Type: multipart/form-data; boundary=$multipart_boundary\r\n",
            'method'  => 'POST',
            'content' => $content
          ),
        )));
        self::log($url, security::ip(), 'POST', "SUCCESS POSTing photo.");
      } catch (Exception $e) {
        self::log($url, security::ip(), 'POST', "ERROR POSTing photo: " . $e);
        return false;
      }
      // return (trim($response) == 'OK');
      return true;
    }



  /**
    * Log a request
    *
    * All HTTP requests to the API are logged in this way (there is no highly secure data that needs filtering)
    *
    * @param string $request the HTTP request
    * @param string $method (GET/POST/local)
    * @param string|array[string]string $variables the URL encoded variables
    */
    public static function log($request, $ip, $method = 'GET', $variables = '') {
      if (!config::security_enable_log) { return; }
      if (is_array($variables)) {
        $variables = http_build_query($variables);
      }
      $log = date('c') . " $request $ip $method $variables\n";
      file_put_contents(config::path(config::security_log_path) . config::security_log_file, $log, FILE_APPEND);
    }





  }


?>