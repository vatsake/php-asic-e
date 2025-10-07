<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api\Tsa;

use Vatsake\AsicE\Api\HttpClient;

class TsaClient
{
    private array $headers = [
        'Content-Type' => 'application/timestamp-query',
        'Accept' => 'application/timestamp-reply'
    ];

    private HttpClient $httpClient;

    public function __construct()
    {
        $this->httpClient = new HttpClient();
    }

    public function sendRequest(TsaRequest $request): TsaResponse
    {
        $response = $this->httpClient->post($request->getUrl(), $request->getBody(), $this->headers);
        return new TsaResponse($response, $request->getNonce());
    }
}
