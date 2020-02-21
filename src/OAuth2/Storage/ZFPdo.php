<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use InvalidArgumentException;

/**
 * Simple PDO storage for all storage types
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class ZFPdo implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface
{
    /**
     * @var \PDO
     */
    protected $db;

    /**
     * @var array
     */
    protected $config;

    /**
     * @param mixed $connection
     * @param array $config
     *
     * @throws InvalidArgumentException
     */
	/*********************************************/
	public function __construct($connection, $config = array())
	{
		$this->db = $connection;
        $this->config = array_merge(array(
            'client_table'			=> 'itop_clients',
            'access_token_table'	=> 'itop_access_tokens',
            'refresh_token_table'	=> 'itop_refresh_tokens',
            'code_table'			=> 'itop_authorization_codes',
            'user_table'			=> 'itop_users',
            'jwt_table'				=> 'itop_jwt',
            'jti_table'				=> 'itop_jti',
            'scope_table'			=> 'itop_scopes',
            'public_key_table'		=> 'itop_public_key',
        ), $config);
	}

    /**
     * @param string $client_id
     * @param null|string $client_secret
     * @return bool
     */
	/*********************************************/
	public function checkClientCredentials($client_id, $client_secret = null)
	{
		$sql = sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']);
		$result = $this->db->fetchRow($sql, $client_id);
		
/*		
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);
*/

        // make this extensible
        return $result && $result['client_secret'] == $client_secret;
	}

    /**
     * @param string $client_id
     * @return bool
     */
	public function isPublicClient($client_id)
	{
		$sql = sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']);		
		
/*
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));
*/

		if (!$result = $this->db->fetchRow($sql, $client_id)) {
			return false;
		}

		return empty($result['client_secret']);
	}

    /**
     * @param string $client_id
     * @return array|mixed
     */
	/*********************************************/
	public function getClientDetails($client_id)
    {
		$sql = sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']);
		
/*		
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));

        return $stmt->fetch(\PDO::FETCH_ASSOC);
*/		
		return $this->db->fetchRow($sql, $client_id);
	}

    /**
     * @param string $client_id
     * @param null|string $client_secret
     * @param null|string $redirect_uri
     * @param null|array  $grant_types
     * @param null|string $scope
     * @param null|string $user_id
     * @return bool
     */
	/*********************************************/
	public function setClientDetails($client_id, $client_secret = NULL, $redirect_uri = NULL, $grant_types = NULL, $scope = NULL, $user_id = NULL)
	{
		$data = array(
			'client_secret'		=> $client_secret
			, 'redirect_uri'	=> $redirect_uri
			, 'grant_types'		=> $grant_types
			, 'scope'			=> $scope
			, 'user_id'			=> $user_id
		);
		$where[] = "client_id = '$client_id'";
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
			$result = $this->db->update($this->config['client_table'], $data, $where);
		} else {
			$data = array_merge(array( 'client_id' => $client_id ), $data);
			$result = $this->db->insert($this->config['client_table'], $data);
		}
/*		
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_secret=:client_secret, redirect_uri=:redirect_uri, grant_types=:grant_types, scope=:scope, user_id=:user_id where client_id=:client_id', $this->config['client_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (:client_id, :client_secret, :redirect_uri, :grant_types, :scope, :user_id)', $this->config['client_table']));
        }

        return $stmt->execute(compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'));
*/		
		return $result;
	}

    /**
     * @param $client_id
     * @param $grant_type
     * @return bool
     */
	/*********************************************/
	public function checkRestrictedGrantType($client_id, $grant_type)
	{
		$details = $this->getClientDetails($client_id);
		if (isset($details['grant_types'])) {
			$grant_types = explode(' ', $details['grant_types']);

			return in_array($grant_type, (array) $grant_types);
		}

		// if grant_types are not defined, then none are restricted
		return true;
	}

    /**
     * @param string $access_token
     * @return array|bool|mixed|null
     */
	/*********************************************/
	public function getAccessToken($access_token)
	{
		$sql = sprintf('SELECT * from %s where access_token = ?', $this->config['access_token_table']);
		if ($token = $this->db->fetchRow($sql, $access_token)) {
			$token['expires'] = strtotime($token['expires']);
//			$token['expires'] = DateTime::createFromFormat(DTF, $token['expires']);
		}

/*		
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where access_token = :access_token', $this->config['access_token_table']));

        $token = $stmt->execute(compact('access_token'));
        if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }
*/

		return $token;
	}

    /**
     * @param string $access_token
     * @param mixed  $client_id
     * @param mixed  $user_id
     * @param int    $expires
     * @param string $scope
     * @return bool
     */
	/*********************************************/
	public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
	{
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
		$data = array(
			'client_id'		=> $client_id
			, 'expires'		=> $expires
			, 'user_id'		=> $user_id
			, 'scope'		=> $scope
		);
		$where[] = "access_token = '$access_token'";
		// if it exists, update it.
		if ($this->getAccessToken($access_token)) {		
			$result = $this->db->update($this->config['access_token_table'], $data, $where);
		} else {
			$data = array_merge(array( 'access_token' => $access_token ), $data);
			$result = $this->db->insert($this->config['access_token_table'], $data);
		}		
//!d($data);
/*		
        // convert expires to datestring
//        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = $this->db->prepare(sprintf('UPDATE %s SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope where access_token=:access_token', $this->config['access_token_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (access_token, client_id, expires, user_id, scope) VALUES (:access_token, :client_id, :expires, :user_id, :scope)', $this->config['access_token_table']));
        }

        return $stmt->execute(compact('access_token', 'client_id', 'user_id', 'expires', 'scope'));
*/		
		
		return $result;
	}

    /**
     * @param $access_token
     * @return bool
     */
	/*********************************************/
	public function unsetAccessToken($access_token)
	{
		$where[] = "access_token = '$access_token'";
		$result = $this->db->delete($this->config['access_token_table'], $where);

/*		
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE access_token = :access_token', $this->config['access_token_table']));

        $stmt->execute(compact('access_token'));

        return $stmt->rowCount() > 0;
*/		
		
		return $result > 0;
	}

    /* OAuth2\Storage\AuthorizationCodeInterface */
    /**
     * @param string $code
     * @return mixed
     */
	/*********************************************/
	public function getAuthorizationCode($code)
	{
		$sql = sprintf('SELECT * from %s where authorization_code = ?', $this->config['code_table']);
		if ($code = $this->db->fetchRow($sql, $code)) {
			$code['expires'] = strtotime($code['expires']);		
		}
		
/*		
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where authorization_code = :code', $this->config['code_table']));
        $stmt->execute(compact('code'));

        if ($code = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }
*/

		return $code;
	}

    /**
     * @param string $code
     * @param mixed  $client_id
     * @param mixed  $user_id
     * @param string $redirect_uri
     * @param int    $expires
     * @param string $scope
     * @param string $id_token
     * @return bool|mixed
     */
	/*********************************************/
	public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
	{
//!d($code, $client_id, $user_id, $redirect_uri, $expires, $scope, $id_token);
		if (func_num_args() > 6) {
			// we are calling with an id token
			return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
		}		
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
		$data = array(
			'client_id'			=> $client_id
			, 'user_id'			=> $user_id
			, 'redirect_uri'	=> $redirect_uri
			, 'expires'			=> $expires
			, 'scope'			=> $scope
		);
		$where[] = "authorization_code = '$code'";
		// if it exists, update it.
		if ($this->getAuthorizationCode($code)) {		
			$result = $this->db->update($this->config['code_table'], $data, $where);
		} else {
			$data = array_merge(array( 'authorization_code' => $code ), $data);
			$result = $this->db->insert($this->config['code_table'], $data);
		}	
		
/*		
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }


        // convert expires to datestring
//        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope where authorization_code=:code', $this->config['code_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)', $this->config['code_table']));
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope'));
*/
		return $result;
	}

    /**
     * @param string $code
     * @param mixed  $client_id
     * @param mixed  $user_id
     * @param string $redirect_uri
     * @param string $expires
     * @param string $scope
     * @param string $id_token
     * @return bool
     */
	/*********************************************/
	private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
	{
        // convert expires to datestring
		$expires = date('Y-m-d H:i:s', $expires);
		$data = array(
			'client_id'			=> $client_id
			, 'user_id'			=> $user_id
			, 'redirect_uri'	=> $redirect_uri
			, 'expires'			=> $expires
			, 'scope'			=> $scope
			, 'id_token'		=> $id_token
		);
		$where[] = "authorization_code = '$code'";
        // if it exists, update it.
		if ($this->getAuthorizationCode($access_token)) {		
			$result = $this->db->update($this->config['code_table'], $data, $where);
		} else {
			$data = array_merge(array( 'authorization_code' => $code ), $data);
			$result = $this->db->insert($this->config['code_table'], $data);
		}			
		
/*		
        // convert expires to datestring
//        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope, id_token =:id_token where authorization_code=:code', $this->config['code_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, id_token) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope, :id_token)', $this->config['code_table']));
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'));
*/	
		return $result;
	}

    /**
     * @param string $code
     * @return bool
     */
	/*********************************************/
	public function expireAuthorizationCode($code)
	{
		$where[] = "authorization_code = '$code'";
		$result = $this->db->delete($this->config['code_table'], $where);
		
		
/*		
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE authorization_code = :code', $this->config['code_table']));

        return $stmt->execute(compact('code'));
*/
		return $result;
	}

    /**
     * @param string $username
     * @param string $password
     * @return bool
     */
	/*********************************************/
	public function checkUserCredentials($username, $password)
	{
		if ($user = $this->getUser($username)) {
			return $this->checkPassword($user, $password);
		}

		return false;
	}

    /**
     * @param string $username
     * @return array|bool
     */
	/*********************************************/
	public function getUserDetails($username)
	{
		return $this->getUser($username);
	}

    /**
     * @param mixed  $user_id
     * @param string $claims
     * @return array|bool
     */
	/*********************************************/
	public function getUserClaims($user_id, $claims)
	{
		if (!$userDetails = $this->getUserDetails($user_id)) {
			return false;
		}

		$claims = explode(' ', trim($claims));
		$userClaims = array();

		// for each requested claim, if the user has the claim, set it in the response
		$validClaims = explode(' ', self::VALID_CLAIMS);
		foreach ($validClaims as $validClaim) {
			if (in_array($validClaim, $claims)) {
				if ($validClaim == 'address') {
					// address is an object with subfields
					$userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
				} else {
					$userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
				}
			}
		}

		return $userClaims;
	}

    /**
     * @param string $claim
     * @param array  $userDetails
     * @return array
     */
	/*********************************************/
	protected function getUserClaim($claim, $userDetails)
	{
		$userClaims = array();
		$claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
		$claimValues = explode(' ', $claimValuesString);

		foreach ($claimValues as $value) {
			$userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
		}

		return $userClaims;
	}

    /**
     * @param string $refresh_token
     * @return bool|mixed
     */
	/*********************************************/
	public function getRefreshToken($refresh_token)
	{
		$sql = sprintf('SELECT * FROM %s WHERE refresh_token = ?', $this->config['refresh_token_table']);
		if ($token = $this->db->fetchRow($sql, $refresh_token)) {
			$token['expires'] = strtotime($token['expires']);		
		}
/*		
		$stmt = $this->db->prepare(sprintf('SELECT * FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

		$token = $stmt->execute(compact('refresh_token'));
		if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
			// convert expires to epoch time
			$token['expires'] = strtotime($token['expires']);
		}
*/
		
		return $token;
	}

    /**
     * @param string $refresh_token
     * @param mixed  $client_id
     * @param mixed  $user_id
     * @param string $expires
     * @param string $scope
     * @return bool
     */
	/*********************************************/
	public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
	{
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
		$data = array(
			'refresh_token'	=> $refresh_token
			, 'client_id'	=> $client_id
			, 'user_id'		=> $user_id
			, 'expires'		=> $expires
			, 'scope'		=> $scope
		);
		// if it exists, update it.
		$result = $this->db->insert($this->config['refresh_token_table'], $data);
	
/*		
		// convert expires to datestring
//		$expires = date('Y-m-d H:i:s', $expires);

		$stmt = $this->db->prepare(sprintf('INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (:refresh_token, :client_id, :user_id, :expires, :scope)', $this->config['refresh_token_table']));

		return $stmt->execute(compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'));
*/
		
		return $result;
	}

    /**
     * @param string $refresh_token
     * @return bool
     */
	/*********************************************/
	public function unsetRefreshToken($refresh_token)
	{
		$where[] = "refresh_token = '$refresh_token'";
		$result = $this->db->delete($this->config['refresh_token_table'], $where);		

/*		
		$stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

		$stmt->execute(compact('refresh_token'));

		return $stmt->rowCount() > 0;
*/
		
		return $result > 0;		
	}

    /**
     * plaintext passwords are bad!  Override this for your application
     *
     * @param array $user
     * @param string $password
     * @return bool
     */
	/*********************************************/
	protected function checkPassword($user, $password)
	{
//		return $user['password'] == $this->hashPassword($password);
		return password_verify($password, $user['password']);
	}

    // use a secure hashing algorithm when storing passwords. Override this for your application
	/*********************************************/
	protected function hashPassword($password)
	{
//		return sha1($password);
		$options = array('cost' => 12);
		return password_hash($password, PASSWORD_BCRYPT, $options);
	}

    /**
     * @param string $username
     * @return array|bool
     */
	/*********************************************/
	public function getUser($username)
	{
		$sql = sprintf('SELECT * from %s where username = ?', $this->config['user_table']);	
		if (!$userInfo = $this->db->fetchRow($sql, $username)) {
			return false;
		}
		if (!$userInfo['username']) {
			return false;
		}		
		// the default behavior is to use "username" as the user_id
		return array_merge(array(
			'user_id' => $userInfo['username']
		), $userInfo);
	
/*		
		$stmt = $this->db->prepare($sql = sprintf('SELECT * from %s where username=:username', $this->config['user_table']));
		$stmt->execute(array('username' => $username));

		if (!$userInfo = $stmt->fetch(\PDO::FETCH_ASSOC)) {
			return false;
		}

		// the default behavior is to use "username" as the user_id
		return array_merge(array(
			'user_id' => $username
		), $userInfo);
*/
	}

    /**
     * plaintext passwords are bad!  Override this for your application
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function setUser($username, $password, $scope = null)
    {
        // do not store in plaintext
        $password = $this->hashPassword($password);

		$where[] = "username = '$username'";
		
		$data = array(
			'username'			=> $username,
			'password'			=> $password,
			'email'				=> $username,
			'scope'				=> $scope,
		);
        // if it exists, update it.
        if ($this->getUser($username)) {
			unset($data['username']);
!d('UPD', $data, $where);		
			$result = $this->db->update($this->config['user_table'], $data, $where);
		} else {
!d('INS', $data);		
			$result = $this->db->insert($this->config['user_table'], $data);
		}	
		return $result;
    }	

    /**
     * @param string $scope
     * @return bool
     */
	/*********************************************/
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
		$sql = sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn);
		if ($result = $this->db->fetchRow($sql, $scope)) {
            return $result['count'] == count($scope);
		};		
			
/*		
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $stmt = $this->db->prepare(sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn));
        $stmt->execute($scope);

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['count'] == count($scope);
        }

        return false;
*/
		
        return false;		
    }

    /**
     * @param mixed $client_id
     * @return null|string
     */
	/*********************************************/
	public function getDefaultScope($client_id = null)
	{
		$sql = sprintf('SELECT scope FROM %s WHERE is_default = ?', $this->config['scope_table']);
		if ($result = $this->db->fetchAll($sql, true)) {
			$defaultScope = array_map(function ($row) {
				return $row['scope'];
			}, $result);

			return implode(' ', $defaultScope);
		};			
		
/*		
		$stmt = $this->db->prepare(sprintf('SELECT scope FROM %s WHERE is_default=:is_default', $this->config['scope_table']));
		$stmt->execute(array('is_default' => true));

		if ($result = $stmt->fetchAll(\PDO::FETCH_ASSOC)) {
			$defaultScope = array_map(function ($row) {
				return $row['scope'];
			}, $result);

			return implode(' ', $defaultScope);
		}
*/
		return null;
	}

    /**
     * @param mixed $client_id
     * @param $subject
     * @return string
     */
	/*********************************************/
	public function getClientKey($client_id, $subject)
	{
		$sql = sprintf('SELECT public_key from %s where client_id = ? AND subject=?', $this->config['jwt_table']);
		return $result = $this->db->fetchCol($sql, array($client_id, $subject));

/*		
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key from %s where client_id=:client_id AND subject=:subject', $this->config['jwt_table']));

        $stmt->execute(array('client_id' => $client_id, 'subject' => $subject));

        return $stmt->fetchColumn();
*/

	}

    /**
     * @param mixed $client_id
     * @return bool|null
     */
	/*********************************************/
    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    /**
     * @param mixed $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     * @return array|null
     */
	/*********************************************/
    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {
		$sql = sprintf('SELECT * FROM %s WHERE issuer = ? AND subject = ? AND audience = ? AND expires = ? AND jti = ?', $this->config['jti_table']);
        if ($this->db->fetchRow($sql, array($client_id, $subject, $audience, $expires, $jti))) {
            return array(
                'issuer' 	=> $result['issuer'],
                'subject' 	=> $result['subject'],
                'audience' 	=> $result['audience'],
                'expires' 	=> $result['expires'],
                'jti' 		=> $result['jti'],
            );
        }		

/*		
        $stmt = $this->db->prepare($sql = sprintf('SELECT * FROM %s WHERE issuer=:client_id AND subject=:subject AND audience=:audience AND expires=:expires AND jti=:jti', $this->config['jti_table']));

        $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return array(
                'issuer' => $result['issuer'],
                'subject' => $result['subject'],
                'audience' => $result['audience'],
                'expires' => $result['expires'],
                'jti' => $result['jti'],
            );
        }
*/
        return null;
    }

    /**
     * @param mixed $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     * @return bool
     */
	/*********************************************/
    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
		$data = array(
			'issuer'	=> $client_id,
			'subject'	=> $subject,
			'audience'	=> $audience,
			'expires'	=> $expires,
			'jti'		=> $jti,
		);

/*		
        $stmt = $this->db->prepare(sprintf('INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (:client_id, :subject, :audience, :expires, :jti)', $this->config['jti_table']));

        return $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));
*/		
		
		return $result = $this->db->insert($this->config['jti_table'], $data);
    }

    /**
     * @param mixed $client_id
     * @return mixed
     */
	/*********************************************/
    public function getPublicKey($client_id = null)
    {
		$sql = sprintf('SELECT public_key FROM %s WHERE client_id = ? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']);
		
/*		
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['public_key'];
        }
*/		
		
        if ($result = $this->db->fetchRow($sql, $client_id)) {
            return $result['public_key'];
        }			
    }

    /**
     * @param mixed $client_id
     * @return mixed
     */
	/*********************************************/
    public function getPrivateKey($client_id = null)
    {
		$sql = sprintf('SELECT private_key FROM %s WHERE client_id = ? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']);		
		
		
/*		
        $stmt = $this->db->prepare($sql = sprintf('SELECT private_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['private_key'];
        }
*/		
		
        if ($result = $this->db->fetchRow($sql, $client_id)) {
            return $result['private_key'];
        }		
    }

    /**
     * @param mixed $client_id
     * @return string
     */
	/*********************************************/
    public function getEncryptionAlgorithm($client_id = null)
    {
		$sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id = ? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']);	

/*
		$stmt = $this->db->prepare($sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['encryption_algorithm'];
        }
        return 'RS256';
*/		
		
        if ($result = $this->db->fetchRow($sql, $client_id)) {
            return $result['encryption_algorithm'];
        }
        return 'RS256';
    }

    /**
     * DDL to create OAuth2 database and tables for PDO storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     *
     * @param string $dbName
     * @return string
     */
	/*********************************************/
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
		CREATE TABLE {$this->config['client_table']} (
			client_id				VARCHAR(80)   NOT NULL,
			client_secret			VARCHAR(80),
			redirect_uri			VARCHAR(2000),
			grant_types				VARCHAR(80),
			scope					VARCHAR(4000),
			user_id					VARCHAR(40),
			PRIMARY KEY (client_id)
		);

		CREATE TABLE {$this->config['access_token_table']} (
			access_token			VARCHAR(40)    NOT NULL,
			client_id				VARCHAR(80)    NOT NULL,
			user_id					VARCHAR(40),
			expires					TIMESTAMP      NOT NULL,
			scope					VARCHAR(4000),
			PRIMARY KEY (access_token)
		);

		CREATE TABLE {$this->config['code_table']} (
			authorization_code		VARCHAR(40)    NOT NULL,
			client_id				VARCHAR(80)    NOT NULL,
			user_id					VARCHAR(40),
			redirect_uri			VARCHAR(2000),
			expires					TIMESTAMP      NOT NULL,
			scope					VARCHAR(4000),
			id_token				VARCHAR(1000),
			PRIMARY KEY (authorization_code)
		);

		CREATE TABLE {$this->config['refresh_token_table']} (
			refresh_token			VARCHAR(40)    NOT NULL,
			client_id				VARCHAR(80)    NOT NULL,
			user_id					VARCHAR(40),
			expires					TIMESTAMP      NOT NULL,
			scope					VARCHAR(4000),
			PRIMARY KEY (refresh_token)
		);

		CREATE TABLE {$this->config['user_table']} (
			username				VARCHAR(40),
			password				VARCHAR(80),
			email					VARCHAR(80),
			email_verified			BOOLEAN,
			scope					VARCHAR(4000)
			PRIMARY KEY (username)
		);

		CREATE TABLE {$this->config['scope_table']} (
			scope					VARCHAR(80)  NOT NULL,
			is_default				BOOLEAN,
			PRIMARY KEY (scope)
		);

		CREATE TABLE {$this->config['jwt_table']} (
			client_id				VARCHAR(80)   NOT NULL,
			subject					VARCHAR(80),
			public_key				VARCHAR(2000) NOT NULL
		);

		CREATE TABLE {$this->config['jti_table']} (
			issuer					VARCHAR(80)   NOT NULL,
			subject					VARCHAR(80),
			audiance				VARCHAR(80),
			expires					TIMESTAMP     NOT NULL,
			jti						VARCHAR(2000) NOT NULL
		);

		CREATE TABLE {$this->config['public_key_table']} (
			client_id				VARCHAR(80),
			public_key				VARCHAR(2000),
			private_key				VARCHAR(2000),
			encryption_algorithm	VARCHAR(100) DEFAULT 'RS256'
		);
			
		CREATE TABLE {$this->config['verified_token_table']} (
			verified_token			VARCHAR(80)    NOT NULL,
			user_id					VARCHAR(40),
			expires					TIMESTAMP      NOT NULL,
			scope					VARCHAR(4000),
			PRIMARY KEY (verified_token)
		)		
        ";

        return $sql;
    }

    /**
     * @param string $email
     * @return bool
     */
	/*********************************************/
	public function checkEmailVerified($email)
	{

		$sql = sprintf('SELECT * from %s where email = ?', $this->config['user_table']);
		$result = $this->db->fetchAll($sql, $email);
		return intval($result[0]['email_verified']) > 0;
	}

    /**
     *
     * @param string $email
     * @return bool
     */
    public function setEmailVerified($email)
    {
		$where[] = "email = '$email'";
		
		$data = array(
			'email_verified'	=> true
		);
		$result = $this->db->update($this->config['user_table'], $data, $where);
		return $result;
    }	
	
    /**
     * @param string $token
     * @param mixed  $user_id
     * @param string $expires
     * @param string $scope
     * @return string|bool
     */
	/*********************************************/
	public function setUserVerifiedToken($user_id, $expires)
	{
		$data = array(
			'verified_token'	=> md5($user_id.time()),
			'user_id'			=> $user_id,
			'expires'			=> $expires,
		);
		$where[] = "user_id = '$user_id'";
        // if it exists, update it.
		if ($this->getUserVerifiedToken($user_id)) {
			unset($data['user_id']);
			$result = (($this->db->update($this->config['verified_token_table'], $data, $where)) ? $data['verified_token'] : false);
		} else {
			$result = (($this->db->insert($this->config['verified_token_table'], $data)) ? $data['verified_token'] : false);
		}			
		return $result;
	}	
	
    /**
     * @param string $verified_token
     * @return array|bool|mixed|null
     */
	/*********************************************/
	public function checkVerifiedToken($verified_token)
	{
		$sql = sprintf('SELECT * from %s where verified_token = ?', $this->config['verified_token_table']);
		$result = $this->db->fetchRow($sql, $verified_token);
		if (!$result || !$result['expires']) {
			return false;
		} else {
			$dc = strtotime($result['expires']);
			$dn = strtotime('now');
			if ($dn >= $dc) {
				$this->unsetVerifiedToken($verified_token);
			}
		}
		return ($dn < $dc);
	}	

    /**
     * @param string $verified_token
     * @return array|bool|mixed|null
     */
	/*********************************************/
	public function getVerifiedToken($verified_token)
	{
		$sql = sprintf('SELECT * from %s where verified_token = ?', $this->config['verified_token_table']);
		$result = $this->db->fetchRow($sql, $verified_token);
		return $result;
	}
	
    /**
     * @param string $user_id
     * @return array|bool|mixed|null
     */
	/*********************************************/
	public function getUserVerifiedToken($user_id)
	{
		$sql = sprintf('SELECT * from %s where user_id = ?', $this->config['verified_token_table']);
		$result = $this->db->fetchRow($sql, $user_id);
		return $result;
	}	


    /**
     * @param string $verified_token
     * @return bool
     */
	/*********************************************/
	public function unsetVerifiedToken($verified_token)
	{
		$where[] = "verified_token = '$verified_token'";
		$result = $this->db->delete($this->config['verified_token_table'], $where);
		return $result > 0;		
	}
	
    /**
     * @param string $user_id
     * @return bool
     */
	/*********************************************/
	public function unsetUserVerifiedTokens($user_id)
	{
		$where[] = "user_id = '$user_id'";
		$result = $this->db->delete($this->config['verified_token_table'], $where);
		return $result > 0;		
	}
	
    /**
     *
     * @param string $username
     * @return bool
     */
	/*********************************************/
    public function setUserScope($username, $scope)
    {
		$where[] = "username = '$username'";
		
		$data = array(
			'scope'	=> $scope,
		);
		return $this->db->update($this->config['user_table'], $data, $where);
    }

    /**
     * @param mixed  $client_id
     * @param string $public_key
     * @param string $private_key
     * @param string $encryption_algorithm
     * @return bool
     */
	/*********************************************/
	public function setClientKeys($client_id, $public_key, $private_key, $encryption_algorithm='RS256')
	{
!d('setClientKeys');		
        // convert expires to datestring
		$data = array(
//			'client_id'				=> $client_id,
			'public_key'			=> $public_key,
			'private_key'			=> $private_key,
			'encryption_algorithm'	=> $encryption_algorithm,
		);
		$where[] = "client_id = '$client_id'";
		// if it exists, update it.
		if ($this->getPublicKey($client_id)) {	
!d('update');		
			$result = $this->db->update($this->config['public_key_table'], $data, $where);
		} else {
!d('insert');		
			$data = array_merge(array( 'client_id' => $client_id ), $data);
			$result = $this->db->insert($this->config['public_key_table'], $data);
		}		

		return $result;
	}	
	
}
