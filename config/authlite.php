<?php defined('SYSPATH') or die('No direct access allowed.');

return array
(
	/**
	 * User model
	 */
	'user_model' => 'users',

	/**
	 * Username column
	 */
	'username' => 'username',

	/**
	 * Password column
	 */
	'password' => 'password',

	/**
	* Logins model
	*/
	'login_model' => 'logins',

	/**
	 * Tokens column
	 */
	'token' => 'token',

	/**
	 * Type of hash to use for passwords. Any algorithm supported by the hash function
	 * can be used here.
	 * @see http://php.net/hash
	 * @see http://php.net/hash_algos
	 */
	'hash_method' => 'sha256',

	/**
	 * Secret key used for generating the HMAC variant of the password
	 * @see http://php.net/hash_hmac
	 */
	'hash_key' => '',

	/**
	 * Set the auto-login (remember me) cookie lifetime, in seconds. The default
	 * lifetime is two weeks.
	 */
	'lifetime' => 1209600,

	/**
	 * Set the session key that will be used to store the current user.
	 */
	'session_key' => 'user',

	/**
	* Cookie name
	*/
	'cookie' => 'u',
);
