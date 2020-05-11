<?PHP // © THD @ GGD 2020

/**
  * Photosec Configuration
  *
  * This file contains the server config for Photosec.
  * These constants have been tweaked to the specific requirements of the server.
  *
  * DO NOT CHANGE ANYTING IN THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING!!!
  *
  * @author Thijs Houtenbos
  * @version 0.2.0
  * @package Photosec IC
  * @subpackage Configuration
  */

  if (!defined('PHOTOSEC_CONFIG_LOADED')) {
    define('PHOTOSEC_CONFIG_LOADED', 1);


    // Show all errors
    error_reporting(E_ALL ^ E_DEPRECATED);
    ini_set('display_errors', 1);

    // Show no errors
    // error_reporting(0);
    // ini_set('display_errors', 0);


  /**
    * Config class
    *
    * The config class contains all the constants that specify certain server configurations.
    *
    * @package Photosec IC
    */
    class config {


    /**#@+
      * Take the system offline for maintenance
      *
      * Set this value to true to show a warning that the system is offline temporarily before allowing login.
      */
      const offline                       = false;
    /**#@-*/


    /**#@+
      * Configured allowed app URLS and POSTs
      *
      * When adding a new app add the URL and POST data here
      * 
      * There are 4 variables that will be substituted:
      * - $user - The user name or ID
      * - $code - The token code
      * - $file - The file uploaded MIME base64 encoded
      * - $type - The file type (only 'jpg')
      */
      public static $apps = array(
        'test' => array(
          'url'  => 'https://a-photosec.itforcare.nl/.test/send/',
          'post' => array(
            'user'      => '$user',
            'code'      => '$code',
            'file'      => '$file',
            'type'      => '$type',
          ),
        ),
        'formatus' => array(
          'url'  => 'https://a-formatus.itforcare.nl/MagicScripts/MGrqispi.dll',
          'post' => array(
            'APPNAME'   => 'Formatus',
            'PRGNAME'   => 'FotosecInvoer',
            'user'      => '$user',
            'code'      => '$code',
            'file'      => '$file',
            'type'      => '$type',
            'ARGUMENTS' => 'user,code,type,file',
          ),
        ),
        'photosecdemo' => array(
          'url'  => 'https://photosecdemo.herokuapp.com/photoupload/', // photoupload/<int:user>/<str:token>
          'post' => array(
            'user'      => '$user',
            'token'     => '$code',
            'file'      => '$file',
            'type'      => '$type',
            'title'     => 'foto.jpg',
          ),
        ),
      );
    /**#@-*/


    /**#@+
      * Security settings
      *
      * These settings are used for security and authentication purposes {@link security.class.php}.
      */
      const security_domain               = 'photosec.local';                     // The domain used by the cookies
      const security_https                = false;                                // Use HTTPS
      const security_jwt_type             = 'JWT';                                // JWT type
      const security_jwt_alg              = 'HS256';                              // JWT algorihm
      // const security_jwt_key              = 'e01661831421d4a320a1a1472023c7e049ae041283383d3fdf10ab1027d6b007'; // JWT key (256 bit)
      const security_jwt_key              = 'test'; // JWT key (256 bit)
      const security_enable_log           = true;                                 // Log
      const security_log_path             = 'api\log';                            // Log path
      const security_log_file             = 'request.log';                        // Log file
      const security_qr_size              = 5;                                    // Size of QR code pixel
      const security_qr_valid_time        = 300;                                  // QR code is valid for this long
    /**#@-*/


    /**
      * Get the current path
      *
      * Beside providing the root path of the system you can specify an optional subpath.
      * When you pass a subpath the full path to this folder inside the root is returned.
      *
      * @param string Subpath in the tree structure
      * @param string Slash at the end of the pathname
      * @return string Full path of the system
      */
      public static function path($subpath = '', $slash = '\\') {
        return dirname(__FILE__) . '\\..\\' . $subpath . $slash;
      }


      // End of class config
    }


  } else {
    // Show the developer something went wrong.
    if (function_exists('error')) { error('Config loaded twice', 'This should never happen, when you see this error please contact the developers...'); }
  }


?>