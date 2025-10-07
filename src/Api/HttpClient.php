<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Api;

use Vatsake\AsicE\Exceptions\HttpException;

class HttpClient
{
    public function post(string $url, string $data, array $headers = []): string
    {
        $ch = curl_init($url);

        $curlHeaders = [];
        foreach ($headers as $key => $value) {
            $curlHeaders[] = $key . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $curlHeaders,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HEADER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_SSL_OPTIONS => CURLSSLOPT_NATIVE_CA
        ]);


        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        if ($response === false) {
            $curlErrorMsg = curl_error($ch);
            throw new HttpException($url, 'POST', $httpCode, $curlErrorMsg);
        }

        $body = substr($response, $headerSize);

        if ($httpCode !== 200) {
            $curlErrorMsg = curl_error($ch);
            $message = $body != '' ? $body : $curlErrorMsg;
            throw new HttpException($url, 'POST', $httpCode, $message);
        }

        return $body;
    }

    public function get(string $url, array $headers = []): string
    {
        $ch = curl_init($url);

        $curlHeaders = [];
        foreach ($headers as $key => $value) {
            $curlHeaders[] = $key . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => $curlHeaders,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HEADER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_SSL_OPTIONS => CURLSSLOPT_NATIVE_CA
        ]);


        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        if ($response === false) {
            $curlErrorMsg = curl_error($ch);
            throw new HttpException($url, 'GET', $httpCode, $curlErrorMsg);
        }

        $body = substr($response, $headerSize);

        if ($httpCode !== 200) {
            $curlErrorMsg = curl_error($ch);
            $message = $body != '' ? $body : $curlErrorMsg;
            throw new HttpException($url, 'GET', $httpCode, $message);
        }

        return $body;
    }
}
