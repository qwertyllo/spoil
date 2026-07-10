<?php
/**
 * This file is part of the SPOIL library.
 *
 * @author     Quetzy Garcia <quetzyg@impensavel.com>
 * @copyright  2014-2016
 *
 * For the full copyright and license information,
 * please view the LICENSE.md file that was distributed
 * with this source code.
 */

namespace Impensavel\Spoil;

use Exception;
use Serializable;

use Carbon\Carbon;
use Firebase\JWT\JWT;

use Impensavel\Spoil\Exception\SPBadMethodCallException;
use Impensavel\Spoil\Exception\SPRuntimeException;
use Impensavel\Spoil\Exception\SPInvalidArgumentException;

class SPAccessToken extends SPObject implements Serializable
{
    /**
     * Access token
     *
     * @var  string
     */
    protected $value;

    /**
     * Expiration date
     *
     * @var  \Carbon\Carbon
     */
    protected $expiration;

    /**
     * {@inheritdoc}
     */
    protected function hydrate($data, $exceptions = true)
    {
        $expires = $data['expires_on'] ?? $data['expires_in'] ?? null;
        if ($expires) {
            $data['expires_on'] = Carbon::now()->addSeconds((int)$expires);
        }

        return parent::hydrate($data, $exceptions);
    }

    /**
     * SharePoint Access Token constructor
     *
     * @param   array $payload OData response payload
     * @param   array $extra   Extra payload values to map
     * @throws  SPBadMethodCallException
     */
    public function __construct(array $payload, array $extra = [])
    {
        $this->mapper = array_merge([
            'value'      => 'access_token',
            'expiration' => 'expires_on',
        ], $extra);

        $this->hydrate($payload);
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        return [
            'value'      => $this->value,
            'expiration' => $this->expiration,
            'extra'      => $this->extra,
        ];
    }

    /**
     * Serialize SharePoint Access Token
     *
     * @return  array
     */
    public function __serialize(): array
    {
        return [
            $this->value,
            $this->expiration->getTimestamp(),
            $this->expiration->getTimezone()->getName(),
        ];
    }

    /**
     * Serialize SharePoint Access Token (PHP <= 7.3 compatibility)
     *
     * @return  string
     */
    public function serialize(): string
    {
        return serialize($this->__serialize());
    }

    /**
     * Recreate SharePoint Access Token
     *
     * @param   array $data
     * @return  void
     */
    public function __unserialize(array $data): void
    {
        list($this->value, $timestamp, $timezone) = $data;

        $this->expiration = Carbon::createFromTimeStamp($timestamp, $timezone);
    }

    /**
     * Recreate SharePoint Access Token (PHP <= 7.3 compatibility)
     *
     * @param   string $serialized
     * @return  void
     */
    public function unserialize(string $serialized): void
    {
        $data = unserialize($serialized);
        $this->__unserialize($data);
    }

    /**
     * SharePoint Access Token string value
     *
     * @return  string
     */
    public function __toString()
    {
        return $this->value;
    }

    /**
     * Create a SharePoint Access Token (User-only Policy)
     *
     * @param   SPSite $site         SharePoint Site
     * @param   string $contextToken Context Token
     * @param   array  $extra        Extra payload values to map
     * @throws  SPBadMethodCallException|SPRuntimeException
     * @return  SPAccessToken
     */
    public static function createUserOnlyPolicy(SPSite $site, $contextToken, array $extra = [])
    {
        $config = $site->getConfig();

        if (empty($config['secret'])) {
            throw new SPBadMethodCallException('The Secret is empty/not set');
        }

        try {
            $jwt = JWT::decode($contextToken, $config['secret'], [
                'HS256',
            ]);
        } catch (Exception $e) {
            throw new SPRuntimeException('Unable to decode the Context Token', 0, $e);
        }

        // Get URL hostname
        $hostname = parse_url($site->getUrl(), PHP_URL_HOST);

        // Build resource
        $resource = str_replace('@', '/'.$hostname.'@', $jwt->appctxsender);

        // Decode application context
        $oauth2 = json_decode($jwt->appctx);

        $json = $site->request($oauth2->SecurityTokenServiceUri, [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],

            // The POST body must be passed as a query string
            'body'    => http_build_query([
                'grant_type'    => 'refresh_token',
                'client_id'     => $jwt->aud,
                'client_secret' => $config['secret'],
                'refresh_token' => $jwt->refreshtoken,
                'resource'      => $resource,
            ])
        ], 'POST');

        return new static($json, $extra);
    }

    /**
     * Create a SharePoint Access Token (App-only Policy)
     *
     * @param   SPSite $site  SharePoint Site
     * @param   array  $extra Extra payload values to map
     * @throws  SPBadMethodCallException|SPInvalidArgumentException
     * @return  SPAccessToken
     */
    public static function createAppOnlyPolicy(SPSite $site, array $extra = [])
    {
        $config = $site->getConfig();
        $useCertificate = !empty($config['certificate_path']);

        if (!$useCertificate && empty($config['secret'])) {
            throw new SPBadMethodCallException('The Secret/Certificate is empty/not set');
        }

        if (empty($config['acs'])) {
            throw new SPBadMethodCallException('The Azure Access Control Service URL is empty/not set');
        }

        if (! filter_var($config['acs'], FILTER_VALIDATE_URL)) {
            throw new SPInvalidArgumentException('The Azure Access Control Service URL is invalid');
        }

        if (empty($config['client_id'])) {
            throw new SPBadMethodCallException('The Client ID is empty/not set');
        }

        if (!$useCertificate && empty($config['resource'])) {
            throw new SPBadMethodCallException('The Resource is empty/not set');
        }
                
        // Get vars from config
        $tenantId = $config['tenant_id'];
        $clientId = $config['client_id'];
        $pfxPath = storage_path($config['certificate_path']);
        $pfxPassword = $config['certificate_password'];
        $scope = 'https://' . $config['host'] . '/.default';
        $tokenEndpoint = sprintf('https://login.microsoftonline.com/%s/oauth2/v2.0/token', $tenantId);

        // Get client assertion using certificate
        list($privateKey, $certificate) = self::getCertificate($pfxPath, $pfxPassword);
        $clientAssertion = self::getClientAssertion($clientId, $tokenEndpoint, $certificate, $privateKey);

        // Build HTTP payload
        $payload = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
        ];

        if ($useCertificate) {
            $payload += [
                'scope' => $scope,
                'client_assertion_type' =>
                    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion' => $clientAssertion,
            ];
        }
        else {
            $payload += [
                'client_secret' => $config['secret'],
                'resource'      => $config['resource'],
            ];
        }

        // Send HTTP request
        $json = $site->request($tokenEndpoint, [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => http_build_query($payload),
        ], 'POST');

        return new static($json, $extra);
    }

    /**
     * Returns certificate parts as array (privateKey, certificate)
     *
     * @param   string $pfxPath  Pfx certificate file path
     * @param   string  $pfxPassword Pfx certificate password
     * @throws  Exception
     * @return  array
     */
    private static function getCertificate($pfxPath, $pfxPassword) {
        $pkcs12 = file_get_contents($pfxPath);
        if (!openssl_pkcs12_read($pkcs12, $certs, $pfxPassword)) {
            throw new \Exception('Unable to read PFX certificate.');
        }

        $privateKey = $certs['pkey'];
        $certificate = $certs['cert'];
        return [$privateKey, $certificate];
    }

    /**
     * Returns client assertion.
     *
     * @param   string $clientId  SharePoint client's ID
     * @param   string  $tokenEndpoint Token's endpoint URL
     * @param  string  $certificate Public part of certificate
     * @param  string  $privateKey Private part of certificate
     * @return  string
     */
    private static function getClientAssertion($clientId, $tokenEndpoint, $certificate, $privateKey) {
        $now = time();
        $payload = [
            'aud' => $tokenEndpoint,
            'iss' => $clientId,
            'sub' => $clientId,
            'jti' => (string) \Str::uuid(),
            'nbf' => $now,
            'iat' => $now,
            'exp' => $now + 600,
        ];
        $headers = [
            'typ' => 'JWT',
            'alg' => 'RS256',
            'x5t' => self::getThumbprint($certificate),
        ];
        return JWT::encode(
            $payload,
            $privateKey,
            'RS256',
            null,
            $headers
        );
    }

    /**
     * Returns thumbprint given public part of certificate.
     *
     * @param  string  $certificate Public part of certificate
     * @return  string
     */
    private static function getThumbprint($certificate) {
        $parsed = openssl_x509_read($certificate);
        openssl_x509_export($parsed, $pem);
        $cleanPem = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/', '', $pem);
        $sha1 = sha1(base64_decode($cleanPem), TRUE);
        return rtrim(strtr(base64_encode($sha1), '+/', '-_'), '=');
    }

    /**
     * Check if the SharePoint Access Token has expired
     *
     * @return  bool
     */
    public function hasExpired()
    {
        return $this->expiration->isPast();
    }

    /**
     * Get the SharePoint Access Token expiration
     *
     * @return  Carbon
     */
    public function expiration()
    {
        return $this->expiration;
    }
}
