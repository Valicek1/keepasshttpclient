<?php
/**
 * Created by PhpStorm.
 * User: vasek
 * Date: 31.10.16
 * Time: 12:23
 */

namespace Valicek1\KeePassLib;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Client;


class KeePassHTTPClient
{


	const
		CIPHER = "AES-256-CBC",
		RequestType = "RequestType",
		TriggerUnlock = "TriggerUnlock",
		Nonce = "Nonce",
		Verifier = "Verifier",
		Id = "Id",
		Key = "Key",
		Url = "Url",
		SubmitUrl = "SubmitUrl",
		SortSelection = "SortSelection";

	/** @var  string */
	private $key;

	/** @var  string */
	private $label;

	/** @var  string */
	private $address;

	/** @var port */
	private $port;

	/** @var  Client */
	private $client;

	/** @var bool */
	private $associated = FALSE;

	/** @var string */
	private $nonce;


	/**
	 * KeePassHTTPClient constructor.
	 * @param string $key Encryption key, 256 bits
	 * @param string $label Label (product of association)
	 * @param string $address KeepassHTTP listening address
	 * @param int    $port KeepassHTTP listening port
	 */
	public function __construct($key, $label = "", $address = "localhost", $port = 19455)
	{

		if (strlen($key) <> 32) {
			throw new \InvalidArgumentException("Key length must be 32 bytes (256 bit)");
		}
		$this->key = $key;

		$this->label = $label;
		$this->address = $address;
		$this->port = $port;


		$this->client = new Client([
			'base_uri' => "http://{$this->address}:{$this->port}/",
			'debug'    => TRUE,
			'timeout'  => 60,
		]);

	}


	/**
	 * Get servers address
	 * @return string
	 */
	public function getAddress()
	{

		return $this->address;

	}


	/**
	 * Get servers port
	 * @return int port
	 */
	public function getPort()
	{

		return $this->port;
	}


	/**
	 * Get "Label" of key assigned in KeePassHTTP
	 * @return string
	 */
	public function getLabel()
	{

		return $this->label;
	}


	/**
	 * Is key associated? (returns last testAssociate status
	 * @return bool
	 */
	public function isAssociated()
	{

		return $this->associated;
	}


	/**
	 * Is address:port opened?
	 * @return bool
	 */
	public function isServerListening()
	{

		$opened = @fsockopen($this->address, $this->port);

		if (!$opened) {
			return FALSE;
		}

		return TRUE;

	}


	/**
	 * Get Guzzle HTTP Client
	 * @return Client
	 */
	public function getClient()
	{

		return $this->client;
	}


	/**
	 * @param $json
	 * @return mixed
	 * @throws KeePassHTTPException Server logic exception
	 * @throws KeePassTimeoutException Timeout Exception
	 * @throws KeePassValidationException
	 */
	public function sendRequest($json)
	{

		try {
			$response = $this->client->request('POST', "/", ['json' => $json]);
		} catch (ConnectException $e) {
			if ($e->getHandlerContext()['errno'] == 28) {
				throw  new KeePassTimeoutException("Request TimeOut");
			} else {
				throw $e;
			}
		}
		if ($response->getStatusCode() == 200) {
			$json = json_decode($response->getBody());
			if ($json->Success) {
				$this->checkVerifier($json);
			}
			return $json;
		} else {
			throw  new KeePassHTTPException("Server returned Error");
		}
	}


	/**
	 * Encrypts stuff by OpenSSL lib
	 * @param $string Text to encrypt
	 * @return string
	 */
	private function encode($string)
	{

		$iv = base64_decode($this->nonce);
		return openssl_encrypt($string, self::CIPHER, $this->key, 0, $iv);

	}


	/**
	 * Tries to decrypt data encrypted by $this->encrypt
	 * @param $encoded Data to decrypt
	 * @return string|bool
	 */
	private function decode($encoded)
	{

		$iv = base64_decode($this->nonce);
		return openssl_decrypt($encoded, self::CIPHER, $this->key, 0, $iv);
	}


	/**
	 * Generate new nonce, iv and return verifier array
	 * @return array
	 */
	private function getVerifier()
	{

		$nonce = base64_encode(openssl_random_pseudo_bytes(16));
		$this->nonce = $nonce;
		$verifier = $this->encode($nonce);

		return [
			self::Nonce    => $nonce,
			self::Verifier => $verifier,
		];

	}


	/**
	 * Check response verifier
	 * @param $response
	 * @throws KeePassValidationException
	 */
	private function checkVerifier($response)
	{

		$this->nonce = $response->Nonce;
		$verifier = $response->Verifier;

		if ($this->nonce <> $this->decode($verifier)) {
			throw new KeePassValidationException();
		}


	}


	/**
	 * Checks, whenever is key associated in KeepassHTTP
	 * @param bool $empty (Try to validate or just send some request to server to test it out?)
	 * @return bool
	 */
	public function testAssociated($empty = FALSE)
	{

		$req = $this->getVerifier();

		$req += [
			self::RequestType   => 'test-associate',
			self::TriggerUnlock => FALSE,
		];

		if (!$empty) {
			$req += [self::Id => $this->label];
		}

		$resp = $this->sendRequest($req);

		$this->associated = $resp->Success;
		return $this->associated;

	}


	/**
	 * Try to authorize new key, grab a label of it
	 * @return string Label
	 * @throws KeePassHTTPException
	 */
	public function authorizeKey()
	{

		$req = $this->getVerifier();
		$req += [
			self::RequestType => "associate",
			self::Key         => base64_encode($this->key),
		];

		$response = $this->client->request('POST', "/", [
			'json'    => $req,
			'timeout' => 120,
		]);

		if ($response->getStatusCode() == 200) {
			$json = json_decode($response->getBody());
			if ($json->Success) {
				// Security check
				$this->checkVerifier($json);
				$this->label = $json->Id;
			}
		} else {
			throw  new KeePassHTTPException("Authorization Error");
		}

		return $this->label;
	}


	/**
	 * Get logins from KeePass DB
	 * @param $url
	 * @param $redirectUrl
	 * @return array
	 */
	public function getLogins($url, $redirectUrl)
	{

		$req = $this->getVerifier();
		$req += [
			self::Id            => $this->label,
			self::RequestType   => 'get-logins',
			self::Url           => $this->encode($url),
			self::SubmitUrl     => $this->encode($redirectUrl),
			self::SortSelection => TRUE,
		];

		$resp = $this->sendRequest($req);

		$return = [];

		foreach ($resp->Entries as $entry) {
			$name = $this->decode($entry->Name);
			$login = $this->decode($entry->Login);
			$pass = $this->decode($entry->Password);
			$uuid = $this->decode($entry->Uuid);

			$return[] = [
				'name'  => $name,
				'login' => $login,
				'pass'  => $pass,
				'uuid'  => $uuid,
			];
		}
		return $return;
	}


	/**
	 * Get logins from KeePass DB
	 * @param $url
	 * @param $redirectUrl
	 * @return array
	 */
	public function getLoginsCount($url, $redirectUrl)
	{

		$req = $this->getVerifier();
		$req += [
			self::Id            => $this->label,
			self::RequestType   => 'get-logins-count',
			self::Url           => $this->encode($url),
			self::SubmitUrl     => $this->encode($redirectUrl),
			self::SortSelection => TRUE,
		];

		$resp = $this->sendRequest($req);

		return $resp->Count;
	}

}


class KeePassHTTPException extends \Exception
{

}


class KeePassTimeoutException extends \Exception
{

}


class KeePassValidationException extends \Exception
{

}