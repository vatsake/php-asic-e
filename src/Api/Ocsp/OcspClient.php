<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Ocsp;

use Vatsake\AsicE\Api\HttpClient;

class OcspClient
{
    private const OCSP_HEADERS = [
        'Content-Type' => 'application/ocsp-request',
        'Accept' => 'application/ocsp-response',
    ];

    private HttpClient $httpClient;

    public function __construct()
    {
        $this->httpClient = new HttpClient();
    }

    public function sendRequest(OcspRequest $request): OcspResponse
    {
        $response = $this->httpClient->post($request->getUrl(), $request->getBody(), self::OCSP_HEADERS);
        return new OcspResponse($response);
    }
}
