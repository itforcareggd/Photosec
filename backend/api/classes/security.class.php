<?PHP // © THD @ GGD 2012-2018

/**
  * Security
  *
  * @author Thijs Houtenbos
  * @version 0.2.1
  * @package Photosec
  * @subpackage Classes
  *
  **/

/**
  * Security class
  *
  * This class handles:
  * - login (validate user data)
  * - logout (destroy session)
  * - sessions (validate the user session)
  * - userinfo (the current user)
  *
  * This class interfaces with DIGID to validate login.
  *
  * There are 3 levels of session security:
  * - has_session() = New session, unknown user
  * - low_secure()  = Old session, known user but no secure actions allowed
  * - high_secure() = Secure session, user recently logged in again with DIGID
  *
  * THIS CLASS IS ABOUT KEEPING THIS SYSTEM SAFE. DO NOT MESS WITH THIS!
  *
  * @package Photosec
  * @subpackage Classes
  */
  class security {

    /** Constants */
    const COOKIE_SESSION_KEY    = 'session'; // cookie session key name
    const USER_INPUT_REGEX      = '/^((?!session)[a-z0-9_]+)$/i';

    /** Crypto used in sessions */
    const CRYPTO_METHOD         = 'aes-256-cbc';
    const SECRET_SIZE_BYTES     = 32;
    const CSRF_SIZE_BYTES       = 16;

    /** @var object Singleton instance */
    private static $instance;

    /** @var boolean is de user ever logged in (meaning low secure session, user is known but not authenticated to do any changes) */
    private static $logged_in = false;

    /** @var string Profile object, the user profile. */
    private static $profile = array();

    /** @var string Session object, this info can not directly be modified by the user. */
    private static $session = array();

    /** @var array[string]mixed session data, this info may possibly be modified by the user */
    private static $session_data = array();

    /** @var string hash */
    private static $hash = '';

    /** @var string secret */
    private static $secret = '';

    /** @var boolean cookie sent */
    private static $cookie_sent = false;

    /** @var array[]string allowed session types */
    private static $allowed_session_types = array('web', 'android', 'ios');

    /** @var string default session types */
    private static $default_session_type = 'web';

    /** @var boolean csrf token consumed */
    private static $csrf_token_consumed = false;

  /** Construction of security object is not nessecary (init handles this), but it is allowed */
    private function __construct() {
      // Do nothing
    }


  /** De-construction of security object is not nessecary, but it is allowed */
    private function __deconstruct() {
      // Do nothing
    }


  /** Cloning the security object is not allowed because the object is a singleton */
    public function __clone() {
      trigger_error("Clone is not allowed for singletons!", E_USER_ERROR);
    }


  /**
    * Init the security object
    *
    * Handles login information and returns a singleton security object.
    *
    * @todo check session datum
    *
    * @return security singleton
    */
    public static function init() {
      // Create singleton when needed
      if (self::$instance === null) {
        self::$instance = new security();
        self::$logged_in = false;

        // Laad session, data en gebruiker
        self::$hash = v::read(self::COOKIE_SESSION_KEY, v::ACTION_COOKIE);
        if (self::$hash != '') {
          // Get session and session data
          self::$session = db::get_one('session', array('hash' => self::$hash));
          if (!isset(self::$session['session_id'])) { self::start_session(); }
          self::$session_data = db::key(db::get('session_data', array('session_id' => self::$session['session_id'])), 'label', 'value');
          self::$logged_in = isset(self::$session['profile_id']) && self::$session['profile_id'] > 0;
          if (self::$logged_in) {
            // Only get profile when session is low or high security
            self::$profile = db::get_one('profile', array('profile_id' => self::$session['profile_id']));
          }

          // Update session timestamp
          self::$session['last_seen'] = self::timestamp();
          self::$session['valid_until'] = self::timestamp(self::session_timeout());
          db::update('session', array(
            'last_seen'     => self::$session['last_seen'],
            'valid_until'   => self::$session['valid_until'],
          ), array(
            'session_id' => self::$session['session_id'],
          ));

          // Update cookie
          self::session_cookie();
        }
      }

      // Return instance
      return self::$instance;
    }


  /**
    * Start session
    *
    * Starts a new session
    *
    * @return boolean success
    */
    public static function start_session($type = '') {
      // Create session
      self::$hash = bin2hex(openssl_random_pseudo_bytes(self::SECRET_SIZE_BYTES));
      self::$secret = bin2hex(openssl_random_pseudo_bytes(self::SECRET_SIZE_BYTES));
      self::$session = array(
        'hash'        => self::$hash,
        'secret'      => self::$secret,
        'created'     => self::timestamp(),
        'last_seen'   => self::timestamp(),
        'valid_until' => self::timestamp(self::session_timeout()),
        'ip'          => self::ip(),
      );
      db::insert('session', self::$session);
      self::$session['session_id'] = db::last_insert_id();

      // Check for the X-type header
      if (isset($_SERVER['HTTP_X_TYPE'])) {
        if (in_array($_SERVER['HTTP_X_TYPE'], self::$allowed_session_types)) {
          $type = $_SERVER['HTTP_X_TYPE'];
        }
      }
      if (!$type) {
        $type = self::$default_session_type;
      }
      sarphati::audit('new_session_started', $type);
      self::set_session_data('type', $type);

      // Send session cookie
      security::session_cookie();
    }


  /**
    * End session
    *
    * Terminate session
    */
    public static function end_session() {
      if (isset(self::$session['session_id'])) {
        db::delete('session', array(
          'session_id' => self::$session['session_id'],
        ));
      }
      v::delete_cookie(self::COOKIE_SESSION_KEY);
    }


  /**
    * Get the session type
    *
    * Return either the header sent right now or the stored session type
    */
    public static function session_type() {
      if (isset($_SERVER['HTTP_X_TYPE']) && in_array($_SERVER['HTTP_X_TYPE'], self::$allowed_session_types)) {
        return $_SERVER['HTTP_X_TYPE'];
      }
      $session_type = self::get_session_data('type');
      return in_array($session_type, self::$allowed_session_types) ? $session_type : self::$default_session_type;
    }


  /**
    * Session cookie
    *
    * Set the session cookie (again)
    *
    * @return void
    */
    public static function session_cookie() {
      if (!self::$cookie_sent) {
        self::$cookie_sent = true;
        v::set_cookie(self::COOKIE_SESSION_KEY, self::$hash, time() + self::session_timeout());
      }
    }


  /**
    * Login
    *
    * Performs the login and simply returns true on success and false on failure.
    *
    * This function performs the following tasks:
    * - Checks there is an active session
    * - Check the login was performed
    * - Links a session to a profile
    *
    * @return boolean login status
    */
    public static function login() {
      security::init();
      if (!digid::login()) { return false; }

      // Link profile to session
      $bsn = digid::bsn();
      $hash = hash_hmac('sha256', $bsn, config::security_server_salt);

      // Look up profile
      if ($profile = db::get_one('profile', array('hash' => $hash))) {
        self::$profile = $profile;
        self::$session['profile_id'] = self::$profile['profile_id'];

        // Audit message
        sarphati::audit('login_success_profile_exists', $profile_id);
      } else {
        // Create profile the first time
        db::insert('profile', array(
          'hash'      => $hash,
          'name'      => '',
          'email'     => null,
          'phone'     => null,
        ));
        $profile_id = db::last_insert_id();

        // DEBUG
        // echo "LAST INSERT ID: " . $profile_id;

        // Store profile_id
        self::$session['profile_id'] = $profile_id;

        // Audit message
        sarphati::audit('login_success_profile_created', $profile_id);
      }

      // Update session with the profile
      db::update('session', array(
        'profile_id' => self::$session['profile_id'],
      ), array(
        'session_id' => self::$session['session_id'],
      ));

      // Save the encrypted BSN in the session
      self::set_session_data('bsn', self::encrypt($bsn));

      // Set logged in status
      self::$logged_in = isset(self::$session['profile_id']) && (self::$session['profile_id'] > 0);

      // Return login status
      return self::$logged_in;
    }


  /**
    * Is there an session?
    *
    * Check if there is a session
    *
    * @return boolean user has a session (this does not imply any security!)
    */
    public static function has_session() {
      security::init();
      return isset(self::$session['session_id']) && (self::$session['session_id'] > 0);
    }


  /**
    * Is the system low secure?
    *
    * Check if user is known but not logged in with DigiD.
    *
    * @return boolean user has an older active session
    */
    public static function low_secure() {
      security::init();
      return self::$logged_in;
    }


  /**
    * Is the system high secure?
    *
    * Check if the user is currently logged in with DigiD
    *
    * @return boolean user is logged in with digid
    */
    public static function high_secure() {
      security::init();
      return self::$logged_in && digid::authenticated();
    }


  /**
    * Session
    *
    * This function is provided for easy scripting, this data is also available from {@link security::$session}.
    *
    * Get session object (with hash) or return null when no gebruiker is logged in.
    *
    * @return string session hash or null
    */
    public static function session() {
      return self::$session;
    }


  /**
    * Profile ID
    *
    * Get currewnt user profile_id
    *
    * @return integeror null
    */
    public static function profile_id() {
      return isset(self::$session['profile_id']) ? self::$session['profile_id'] : null;
    }


  /**
    * Session data
    *
    * This function is provided for easy scripting, this data is also available from {@link security::$session_data}.
    *
    * Get session hash or return null when no gebruiker is logged in.
    * @return array[string]mixed session data
    */
    public static function session_data() {
      return self::$session_data;
    }


  /**
    * Get session data
    *
    * Return a single item of session data.
    *
    * @param string $label the item to get
    * @return mixed the session data or null
    */
    public static function get_session_data($label) {
      return isset(self::$session_data[$label]) ? self::$session_data[$label] : null;
    }


  /**
    * Set session data
    *
    * Sets a single item of session data.
    *
    * @todo save session data
    *
    * @param string $label the item to set
    * @param mixed $value the value to set
    * @return mixed result of DB call
    */
    public static function set_session_data($label, $value = '') {
      // Check if session is active
      if (!isset(self::$session['session_id'])) {
        error("Session data opgeslagen zonder actieve session");
        return false;
      }

      // Skip storing the same value
      if (isset(self::$session_data[$label]) && self::$session_data[$label] == $value) { return; }

      // Do not store null values
      $value = $value ?: '';

      // Update when a value was present
      if (isset(self::$session_data[$label])) {
        db::update('session_data', array(
          'value'       => $value,
        ), array(
          'session_id'  => self::$session['session_id'],
          'label'       => $label,
        ));
      } else {
        db::insert('session_data', array(
          'session_id'  => self::$session['session_id'],
          'label'       => $label,
          'value'       => $value,
        ));
      }

      // Store the value in the current session
      self::$session_data[$label] = $value;
    }


  /**
    * Calculate the hash from a password
    *
    * This function creates a hash from the password in the method described in the config.
    * It is recommended to at least use SHA512 as the hash cypher, SHA1 is not recommende and MD5 is just plain stupid! :)
    * For security purposes some salt is also added to the hash, so hashes differ betweeen installations.
    *
    * @param string $login the gebruiker login
    * @param string $password the gebruiker password (plain)
    * @param string $salt (optional) the salt used to calculate the hash, by default the configured salt is used
    * @return string secure hash
    */
    public static function hash_password($login, $password, $salt = config::security_server_salt) {
      return hash(config::db_login_cypher, $login . $salt . $password);
    }


  /**
    * Validate session
    *
    * Validates the current session (stored in cookie) and return the user_id.
    * This function can also be used to check any running session and return that user's ID.
    *
    * @param string $session (optional) session key to validate or null to read current sessions key
    * @return integer user_id or null on failure
    */
    public static function validate($session = null) {
      // Get the session from the cookie or use give session instead
      // self::$session = ($session===null) ? v::read(security::COOKIE_SESSION_KEY, v::ACTION_COOKIE) : $session;

      // Init security
      self::init();

      // FAIL
      return null;
    }


  /**
    * Perform logout
    *
    * Logs the current user out by performing the following steps:
    * - Validate the user is logged in
    * - Destroy the session
    * - Delete the session cookie
    * - Redirect to insecure pages
    *
    * DEVELOPERS NOTE: the DigiD logout initiates a redirect! So always return true also when no session is set!
    *
    * @return true on success and false on failure
    */
    public static function logout() {
      security::init();
      // Logout from DigiD, delete cookie, and return
      if (security::low_secure()) {
        security::end_session();
      }
      if (digid::authenticated()) {
        digid::logout();
      }
      sarphati::audit('user_logged_out');
      return true;
    }


  /**
    * Get the users IP address
    *
    * This function will attempt to return the IP of the actual client, but when it fails it will return the default remote IP (the terminal server when connecting from thin client).
    *
    * @return The IP address of the client
    */
    public static function ip() {
      // Try all possible IP variables
      // DEVELOPERS NOTE: HTTP_X_FORWARDED_FOR is the proper variable set by the Netscaler at the GGD
      if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
      } else if(isset($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
      } else if(isset($_SERVER['HTTP_X_FORWARDED'])) {
        return $_SERVER['HTTP_X_FORWARDED'];
      } else if(isset($_SERVER['HTTP_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_FORWARDED_FOR'];
      } else if(isset($_SERVER['HTTP_FORWARDED'])) {
        return $_SERVER['HTTP_FORWARDED'];
      } else if(isset($_SERVER['REMOTE_ADDR'])) {
        return $_SERVER['REMOTE_ADDR'];
      } else {
        return '0.0.0.0';
      }
    }


  /**
    * Is app
    *
    * Session is initiated trough the app
    *
    * @todo implement this
    *
    * @return boolean is app
    */
    public static function is_app() {
      return true;
    }


  /**
    * Session timeout
    *
    * Get the session timeout in seconds
    *
    * @return int session timeout
    */
    public static function session_timeout() {
      return self::is_app() ? config::security_session_duration_app : config::security_session_duration;
    }


  /**
    * Encrypt data
    *
    * Encrypt with key specific to server, and IV specific to session.
    *
    * @param string data
    * @return string encrypted data
    */
    public static function encrypt($data) {
      if (!isset(self::$session['secret'])) { return false; }
      $key  = hex2bin(config::security_client_salt);
      $iv   = substr(hex2bin(self::$session['secret']), 0, openssl_cipher_iv_length(self::CRYPTO_METHOD));
      return base64_encode(openssl_encrypt($data, self::CRYPTO_METHOD, $key, OPENSSL_RAW_DATA, $iv));
    }


  /**
    * Decrypt data
    *
    * Decrypt with key specific to server, and IV specific to session.
    *
    * @param string encrypted data
    * @return string data
    */
    public static function decrypt($encrypted) {
      if (!isset(self::$session['secret'])) { return false; }
      $key  = hex2bin(config::security_client_salt);
      $iv   = substr(hex2bin(self::$session['secret']), 0, openssl_cipher_iv_length(self::CRYPTO_METHOD));
      return openssl_decrypt(base64_decode($encrypted), self::CRYPTO_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    }


  /**
    * Timestamp
    *
    * Return a timestamp object with added seconds from now
    *
    * @param int (optional) $seconds from now
    * @param boolean (optional) $return_object when set to true, default is ISO string
    * @return string|DateTime object
    */
    public static function timestamp($seconds = 0, $return_object = false) {
      $timestamp = new DateTime("+$seconds seconds");
      return $return_object ? $timestamp : $timestamp->format('c');
    }


  /**
    * CSRF token
    *
    * Get a valid CSRF token
    *
    * @param refresh (always generates a new one)
    * @return string token
    */
    public static function csrf_token($refresh = false) {
      if (self::has_session()) {
        if ($refresh || !self::get_session_data('csrf_token')) {
          $csrf_token = bin2hex(openssl_random_pseudo_bytes(self::CSRF_SIZE_BYTES));
          self::set_session_data('csrf_token', $csrf_token);
          self::$csrf_token_consumed = true;
          return $csrf_token;
        } else {
          return self::get_session_data('csrf_token');
        }
      }
      // No token because no sesion
      return '';
    }


  /**
    * Validate CSRF token
    *
    * Checks the CSRF token. And on success generates a new token.
    *
    * @todo actually fail when token does not match
    *
    * @param string token (optional) when not passed the X-CSRF-Token header will be used
    * @return boolean success
    */
    public static function validate_csrf_token($token = '') {
      // Get the CSRF token
      $token = $token ? $token : (isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '');

      // Check if the token matches
      if (self::get_session_data('csrf_token') == $token) {
        // Refresh the token (this will also be sent in the response)
        self::csrf_token(true);
        return true;
      }

      // Not valid!
      sarphati::audit('csrf_token_validation_failed');
      return false;
    }


  /**
    * CSRF token consumed?
    *
    * @return boolean yes
    */
    public static function csrf_token_consumed() {
      return self::$csrf_token_consumed;
    }


  }


?>