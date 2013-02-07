<?php defined('SYSPATH') OR die('No direct script access.');

/**
 * Authlite library v2.1.0
 *
 * Based on Kohana's Auth library.
 *
 * @author		Fred Wu <fred@wuit.com>
 * @author		Daniel Macedo <admacedo@gmail.com>
 * @copyright	Wuit
 * @license		http://www.opensource.org/licenses/mit-license.php
 */
class Authlite_Core
{
	/**
	 * Authlite instances
	 *
	 * @var array
	 */
	protected static $instances;

	/**
	 * Controller methods that bypass the login
	 *
	 * @var array
	 */
	protected $ignored_methods = array();

	/**
	 * Kohana session object
	 *
	 * @var object
	 */
	protected $session;

	/**
	 * Configuration instance name
	 *
	 * @var string
	 */
	protected $config_name;

	/**
	 * Kohana config object
	 *
	 * @var object
	 */
	protected $config;

	/**
	 * Configured user model
	 *
	 * @var string
	 */
	protected $user_model;

	/**
	 * Username column
	 *
	 * @var string
	 */
	protected $username_column;

	/**
	 * Password column
	 *
	 * @var string
	 */
	protected $password_column;

	/**
	 * Configured logins model
	 *
	 * @var string
	 */
	protected $login_model;

	/**
	 * Tokens column
	 *
	 * @var string
	 */
	protected $token_column;

	/**
	 * Autologin cookie name
	 *
	 * @var string
	 */
	protected $cookie;

	/**
	 * Create an instance of Authlite.
	 *
	 * @param string $config config file name
	 * @return object
	 */
	public static function factory($config_name = 'authlite')
	{
		return new Authlite($config_name);
	}

	/**
	 * Return a static instance of Authlite.
	 *
	 * @return object
	 */
	public static function instance($config_name = 'authlite')
	{
		// Load the Authlite instance
		empty(Authlite::$instances[$config_name]) and Authlite::$instances[$config_name] = new Authlite($config_name);

		return Authlite::$instances[$config_name];
	}

	public function __construct($config_name = 'authlite')
	{
		$this->session			= Session::instance();
		$this->config			= Kohana::$config->load($config_name);
		$this->config_name		= $config_name;
		$this->user_model		= $this->config['user_model'];
		$this->username_column	= $this->config['username'];
		$this->password_column	= $this->config['password'];
		$this->login_model		= $this->config['login_model'];
		$this->token_column		= $this->config['token'];
		$this->cookie			= $this->config['cookie'];
		$this->ignored_methods	= $this->session->get('authlite_ignored_methods');
	}

	/**
	 * Adds the method to the ignore list
	 *
	 * @param string|array $method
	 * @return void
	 */
	public function add_to_ignore($method)
	{
		$this->ignored_methods[$this->config_name] =
			isset($this->ignored_methods[$this->config_name])
				? $this->ignored_methods[$this->config_name]
				: array();

		$method = is_string($method) ? array($method) : $method;
		$method = array_combine(array_keys(array_flip($method)), $method);

		$this->ignored_methods[$this->config_name] = array_merge($this->ignored_methods[$this->config_name], $method);

		$this->session->set('authlite_ignored_methods', $this->ignored_methods);
	}

	/**
	 * Removes the method from the ignore list
	 *
	 * @param string|array $method
	 * @return void
	 */
	public function remove_from_ignore($method)
	{
		$method = is_string($method) ? array($method) : $method;

		$this->ignored_methods[$this->config_name] = array_diff($this->ignored_methods[$this->config_name], $method);

		$this->session->set('authlite_ignored_methods', $this->ignored_methods);
	}

	/**
	 * Check if there is an active session or active cookie.
	 *
	 * @return object|FALSE|NULL
	 */
	public function logged_in()
	{
		if (isset($this->ignored_methods[$this->config_name]) AND in_array(Request::instance()->action, $this->ignored_methods[$this->config_name]))
		{
			return TRUE;
		}

		// Get the user from the session
		$user = $this->session->get($this->config['session_key']);

		$status = is_object($user) ? TRUE : FALSE;

		// Get the user from the cookie
		if ($status == FALSE)
		{
			$token = Cookie::get($this->cookie);

			if (is_string($token))
			{
				$logins = ORM::factory($this->login_model)->find(array($this->token_column => $token));
				$user = ORM::factory($this->user_model)->find(array($this->username_column => $logins->{$this->username_column}));

				if (is_object($user))
				{
					$status = TRUE;

					$user = ORM::factory($this->user_model)
						->where($this->username_column, '=', $logins->{$this->username_column})
						->find()
						->values(array(
							'ip' => Request::$client_ip,
							'last_login' => DB::expr('UTC_TIMESTAMP()')
						))->save();

					$this->session->set($this->config['session_key'], $user);

					// Extends cookie lifetime
					Cookie::set($this->cookie, $token, $this->config['lifetime']);
				}
			}
		}

		if ($status == TRUE)
		{
			return $user;
		}

		return FALSE;
	}

	/**
	 * Returns the currently logged in user, or FALSE.
	 *
	 * @see self::logged_in()
	 * @return object|FALSE
	 */
	public function get_user()
	{
		return $this->logged_in();
	}

	/**
	 * Attempts to log in a user
	 *
	 * @param string username to log in
	 * @param string password to check against
	 * @param boolean enable auto-login
	 * @return object|FALSE
	 */
	public function login($username, $password, $remember = FALSE)
	{
		if (empty($password))
		{
			return FALSE;
		}

		$login_table = ORM::factory($this->login_model)->table_name();

		// Delete all expired tokens
		$result = DB::delete($login_table)->where('date', '<=', DB::expr('(NOW() - INTERVAL ' . $this->config['lifetime'] . ' SECOND)'))->execute();

		$user = ORM::factory($this->user_model)
			->where($this->username_column, '=', $username)
			->where($this->password_column, '=', $this->hash($password))
			->find();

		if ($user->loaded())
		{
			// Regenerate session_id
			$this->session->regenerate();

			$user->values(array(
					'ip' => Request::$client_ip,
					'last_login' => DB::expr('UTC_TIMESTAMP()')
				))->save();

			$this->session->set($this->config['session_key'], $user);

			if ((bool) $remember === TRUE)
			{
				// Can you request a second login at the same time()?... Just add a bit of extra rand()
				$token = hash_hmac($this->config['hash_method'], time() . rand(), $this->config['hash_key']);

				$logins = ORM::factory($this->login_model)->values(array(
						$this->token_column => $token,
						$this->username_column => $username,
					))->save();

				Cookie::set($this->cookie, $token, $this->config['lifetime']);
			}

			return $user;
		}
		else
		{
			return FALSE;
		}
	}

	/**
	 * Forces a user to be logged in without a password
	 *
	 * @param string|object $username
	 * @return object|FALSE
	 */
	public function force_login($username)
	{
		if (!is_object($username))
		{
			$user = ORM::factory($this->user_model)->where($this->username_column, $username)->find();
		}

		if ($user->loaded)
		{
			$this->session->regenerate();
			$this->session->set($this->config['session_key'], $user);
			return $user;
		}

		return FALSE;
	}

	/**
	 * Logs out a user by removing the related session variables.
	 *
	 * @param boolean $destroy completely destroy the session
	 * @return boolean
	 */
	public function logout($destroy = FALSE)
	{
		if ($token = Cookie::get($this->cookie))
		{
			Cookie::delete($this->cookie);

			// Delete entry from login model
			$db_token = ORM::factory($this->login_model)->where($this->token_column, '=', $token)->find();

			if ($db_token->loaded())
			{
				$db_token->delete();
			}
		}

		if ($destroy === TRUE)
		{
			// Destroy the session completely
			$this->session->destroy();
		}
		else
		{
			// Remove the user from the session
			$this->session->delete($this->config['session_key']);

			// Regenerate session_id
			$this->session->regenerate();
		}

		return !$this->logged_in();
	}

	/**
	 * Hashes a string using the configured hash method
	 *
	 * @param string $str
	 * @return string
	 */
	public function hash($str)
	{
		return hash_hmac($this->config['hash_method'], $str, $this->config['hash_key']);
	}
} // End Authlite
