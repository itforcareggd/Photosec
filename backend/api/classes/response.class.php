<?PHP // © THD@GGD 2017

/**
  * API response
  *
  * @author Thijs Houtenbos
  * @version 0.1.0
  * @package Photosec
  * @subpackage API
  */


/**
  * API Response generic
  *
  * Use this class to create API responses.
  *
  * @package Photosec
  * @subpackage API
  */
  class response {


    /** Error code constants */
    const ERROR_NONE                      = 0;
    const ERROR_BAD_REQUEST               = 400;
    const ERROR_LOGIN_FAILED              = 401;
    const ERROR_UNAUTHORIZED              = 401;
    const ERROR_CSRF_FAILED               = 403;
    const ERROR_LOGOUT_FAILED             = 409;
    const ERROR_FORBIDDEN                 = 403;
    const ERROR_METHOD_NOT_ALLOWED        = 405;
    const ERROR_SESSION_TIMEOUT           = 440;
    const ERROR_GATEWAY_TIMEOUT           = 503;


    /** Message constants */
    const MESSAGE_OK                      = 'OK';
    const MESSAGE_RESUME                  = 'Resume';
    const MESSAGE_LOGIN_OK                = 'Login success';
    const MESSAGE_LOGIN_FAILED            = 'Er is een fout opgetreden in de communicatie met DigiD. Probeert u het later nogmaals. Indien deze fout blijft aanhouden, kijk dan op de website https://www.digid.nl voor de laatste informatie.';
    const MESSAGE_UNAUTHORIZED            = 'Unauthorized. You are required to re-authenticate.';
    const MESSAGE_LOGOUT_OK               = 'Logout success';
    const MESSAGE_LOGOUT_FAILED           = 'Failed to logout. Perhaps you were no longer logged in.';
    const MESSAGE_CONSENT_OK              = 'Consent success';
    const MESSAGE_CONSENT_FAILED          = 'Failed to give consent. You might not be allowed to perform this action.';
    const MESSAGE_BAD_REQUEST             = 'Bad Request. Missing/malformed parameters.';
    const MESSAGE_INVALID_VARIABLE        = 'Bad Request. Malformed parameter: \'%s\'.';
    const MESSAGE_MISSING_VARIABLE        = 'Bad Request. Missing parameter: \'%s\'.';
    const MESSAGE_FORBIDDEN               = 'Forbidden. You can not do that.';
    const MESSAGE_METHOD_NOT_ALLOWED      = 'Method not allowed';
    const MESSAGE_SESSION_TIMEOUT         = 'Session Expired/invalid';
    const MESSAGE_INVALID_JWT             = 'Invalid/expired JWT';
    const MESSAGE_CSRF_FAILED             = 'No valid CSRF token';
    const MESSAGE_ERROR_SENDING_FILE      = 'Error sending file to application backend';


    /** @var integer error code */
    public $error = 0;

    /** @var string message response */
    public $message = '';

    /** @var array[]mixed result */
    public $result = array();

  /**
    * Construct message with optional error code and message
    *
    * @param array[mixed]mixed|string $result the result to encode
    * @param integer $error the error code to return (default is 0, no error)
    * @param string $message the message to return (default is OK)
    * @param boolean $output output the message right away (default is OK)
    */
    public function __construct($result = array(), $error = self::ERROR_NONE, $message = self::MESSAGE_OK, $output = true) {
      $this->result       = $result;
      $this->error        = $error;
      $this->message      = $message;
      if ($output) { $this->output(); }
    }


  /**
    * Send response
    *
    * @param boolean @exit default true, set to false to continue parsing PHP after outputting
    */
    public function output($exit = true) {
      header('Content-Type: application/json');
      echo json::encode($this);
      if ($exit) { exit(); }
    }

  }


/**
  * API Response with CSRF
  *
  * Adds the CSRF token
  *
  * @package Photosec
  * @subpackage API
  */
  class response_csrf extends response {
    /** @var string CSRF token */
    public $csrf_token = '';

    public function __construct($result = array(), $error = self::ERROR_NONE, $message = self::MESSAGE_OK, $output = true) {
      // Only send token when consumed or no error occured
      if (security::csrf_token_consumed() || !$error) {
        // Set CSRF token and send
        $this->csrf_token   = security::csrf_token();
        parent::__construct($result, $error, $message, $output);
      } else {
        // Create generic response without CSRF token
        return new response($result, $error, $message, $output);
      }
    }
  }


/**
  * API Response: generic
  *
  * Returns a generic message only
  *
  * @package Photosec
  * @subpackage API
  */
  class response_generic extends response_csrf {
    public function __construct($data = '') {
      parent::__construct($data, self::ERROR_NONE, self::MESSAGE_OK);
    }
  }


/**
  * API Response: redirect
  *
  * @package Photosec
  * @subpackage API
  */
  class response_redirect extends response_csrf {
    public function __construct($url) {
      header("Location: $url");
      exit();
    }
  }


/**
  * API Response: login
  *
  * @package Photosec
  * @subpackage API
  */
  class response_login_success extends response_redirect {
    public function __construct($result = array()) {
      parent::__construct('/api/resume');
    }
  }


/**
  * API Response: login failed
  *
  * @package Photosec
  * @subpackage API
  */
  class response_login_failed extends response_csrf {
    public function __construct($result = array()) {
      parent::__construct($result, self::ERROR_LOGIN_FAILED, self::MESSAGE_LOGIN_FAILED);
    }
  }


/**
  * API Response: logout
  *
  * @package Photosec
  * @subpackage API
  */
  class response_logout_success extends response_csrf {
    public function __construct($result = array()) {
      parent::__construct($result, self::ERROR_NONE, self::MESSAGE_LOGOUT_OK);
    }
  }


/**
  * API Response: login failed
  *
  * @package Photosec
  * @subpackage API
  */
  class response_logout_failed extends response_csrf {
    public function __construct($result = array()) {
      parent::__construct($result, self::ERROR_LOGOUT_FAILED, self::MESSAGE_LOGOUT_FAILED);
    }
  }


/**
  * API Response: resume
  *
  * Returns a resume message
  *
  * @package Photosec
  * @subpackage API
  */
  class response_resume extends response_csrf {
    public function __construct($result = array()) {
      $result['cookies'] = array(
        security::COOKIE_SESSION_KEY    => v::read(security::COOKIE_SESSION_KEY, v::ACTION_COOKIE),
        'SimpleSAML'                    => v::read('SimpleSAML', v::ACTION_COOKIE),
        'SimpleSAMLAuthToken'           => v::read('SimpleSAMLAuthToken', v::ACTION_COOKIE),
      );
      parent::__construct($result, self::ERROR_NONE, self::MESSAGE_RESUME);
    }


  /**
    * Send response
    *
    * @param boolean @exit default true, set to false to continue parsing PHP after outputting
    */
    public function output($exit = true) {
      echo "<html><body>" . json::encode($this) . "</body></html>";
      if ($exit) { exit(); }
    }
  }


/**
  * API Response: consent
  *
  * @package Photosec
  * @subpackage API
  */
  class response_consent_success extends response_csrf {
    public function __construct($data = '') {
      parent::__construct($data, self::ERROR_NONE, self::MESSAGE_CONSENT_OK);
    }
  }


/**
  * API Response: consent failed
  *
  * @package Photosec
  * @subpackage API
  */
  class response_consent_failed extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 401 Unauthorized ');
      parent::__construct($result, self::ERROR_LOGIN_FAILED, self::MESSAGE_CONSENT_FAILED);
    }
  }



/**
  * API Response: Bad Request
  *
  * @package Photosec
  * @subpackage API
  */
  class response_bad_request extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 400 Bad Request');
      parent::__construct($result, self::ERROR_UNAUTHORIZED, self::MESSAGE_BAD_REQUEST);
    }
  }


/**
  * API Response: Invalid Variable
  *
  * This is a specific version of: Bad Request
  *
  * @package Photosec
  * @subpackage API
  */
  class response_invalid_variable extends response_csrf {
    public function __construct($variable, $result = array()) {
      header('HTTP/1.0 400 Bad Request');
      parent::__construct($result, self::ERROR_UNAUTHORIZED, sprintf(self::MESSAGE_INVALID_VARIABLE, $variable));
    }
  }

/**
  * API Response: Missing Variable
  *
  * This is a specific version of: Bad Request
  *
  * @package Photosec
  * @subpackage API
  */
  class response_missing_variable extends response_csrf {
    public function __construct($variable, $result = array()) {
      header('HTTP/1.0 400 Bad Request');
      parent::__construct($result, self::ERROR_UNAUTHORIZED, sprintf(self::MESSAGE_MISSING_VARIABLE, $variable));
    }
  }


/**
  * API Response: not allowed
  *
  * @package Photosec
  * @subpackage API
  */
  class response_forbidden extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 403 Forbidden');
      parent::__construct($result, self::ERROR_FORBIDDEN, self::MESSAGE_FORBIDDEN);
    }
  }


/**
  * API Response: method not allowed
  *
  * @package Photosec
  * @subpackage API
  */
  class response_method_not_allowed extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 405 Method not allowed');
      parent::__construct($result, self::ERROR_METHOD_NOT_ALLOWED, self::MESSAGE_METHOD_NOT_ALLOWED);
    }
  }


/**
  * API Response: session timeout
  *
  * @package Photosec
  * @subpackage API
  */
  class response_session_expired extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 440 Login Time-out');
      parent::__construct($result, self::ERROR_SESSION_TIMEOUT, self::MESSAGE_SESSION_TIMEOUT);
    }
  }


/**
  * API Response: invalid JWT
  *
  * @package Photosec
  * @subpackage API
  */
  class response_invalid_jwt extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 440 Login Time-out');
      parent::__construct($result, self::ERROR_SESSION_TIMEOUT, self::MESSAGE_INVALID_JWT);
    }
  }


/**
  * API Response: CSRF error
  *
  * @package Photosec
  * @subpackage API
  */
  class response_csrf_error extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 403 Forbidden');
      parent::__construct($result, self::ERROR_CSRF_FAILED, self::MESSAGE_CSRF_FAILED);
    }
  }


/**
  * API Response: session low security
  *
  * @package Photosec
  * @subpackage API
  */
  class response_session_low_security extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 401 Unauthorized ');
      parent::__construct($result, self::ERROR_UNAUTHORIZED, self::MESSAGE_UNAUTHORIZED);
    }
  }


/**
  * API Response: failed sending file
  *
  * @package Photosec
  * @subpackage API
  */
  class response_failed_sending_file extends response_csrf {
    public function __construct($result = array()) {
      header('HTTP/1.0 503 Gateway timeout');
      parent::__construct($result, self::ERROR_GATEWAY_TIMEOUT, self::MESSAGE_ERROR_SENDING_FILE);
    }
  }

?>