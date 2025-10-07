<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Validation\Tsa;

use Vatsake\AsicE\Api\Tsa\TimestampToken;
use Vatsake\AsicE\Validation\ValidationResult;
use Vatsake\AsicE\Validation\Validator;
use Vatsake\AsicE\Container\Signature\SignatureXml;

/**
 * Validates the timestamp token's message imprint against the SignatureValue element.
 */
class MessageSignatureValidator implements Validator
{
    public function __construct(private TimestampToken $token, private SignatureXml $xml)
    {
    }

    public function validate(): ValidationResult
    {
        $tstInfo = $this->token->getTimestampInfo();
        $hashAlgorithm = $tstInfo->getHashedAlgorithm();
        $hashInTst = base64_encode($tstInfo->getHashedMessage());

        $signatureXml = $this->xml->getSignatureValueCanonicalized();
        $calculatedHash = base64_encode(hash($hashAlgorithm->value, $signatureXml, true));

        if ($hashInTst !== $calculatedHash) {
            return new ValidationResult(
                false,
                'Timestamp token hash does not match the canonical SignatureValue hash.',
                [
                    'expected' => $hashInTst,
                    'calculated' => $calculatedHash,
                    'algorithm' => $hashAlgorithm->value,
                ]
            );
        }

        return new ValidationResult(true);
    }
}
