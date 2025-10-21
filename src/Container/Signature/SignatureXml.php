<?php

declare(strict_types=1);

namespace Vatsake\AsicE\Container\Signature;

use DateTime;
use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMNode;
use Vatsake\AsicE\Common\Utils;
use Vatsake\AsicE\Crypto\CanonicalizationMethod;
use Vatsake\AsicE\Crypto\DigestAlg;
use Vatsake\AsicE\Crypto\SignAlg;
use Vatsake\AsicE\Exceptions\InvalidCertificateException;
use Vatsake\AsicE\Exceptions\InvalidSignatureXml;

final class SignatureXml
{
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    private const NS_ASIC = 'http://uri.etsi.org/02918/v1.2.1#';
    private const SIGNED_PROPS = 'http://uri.etsi.org/01903#SignedProperties';

    private string $id;

    private ?DOMDocument $doc = null;

    public function __construct(null|string $xml = null)
    {
        if (!$xml) {
            $this->id = 'id-' . bin2hex(random_bytes(14));
            $this->createBase();
        } else {
            $this->doc = new DOMDocument('1.0', 'UTF-8');
            $this->doc->preserveWhiteSpace = true;
            $this->doc->formatOutput = false;

            if (!$this->doc->loadXML($xml)) {
                throw new InvalidSignatureXml('Invalid XML provided');
            }

            foreach ($this->doc->getElementsByTagName('*') as $el) {
                if ($el->hasAttribute('Id')) {
                    $el->setIdAttribute('Id', true);
                }
            }

            $sig = $this->doc->getElementsByTagName('Signature')->item(0);
            $this->id = $sig->getAttribute('Id');
        }
    }

    public function getOcspToken(): string
    {
        $els = $this->doc->getElementsByTagName('EncapsulatedOCSPValue');
        if ($els->count() === 0) {
            throw new InvalidSignatureXml('No OCSP response found in signature');
        }
        return Utils::stripBr($els->item(0)->textContent);
    }

    public function getTimestampToken(): string
    {
        $els = $this->doc->getElementsByTagName('EncapsulatedTimeStamp');
        if ($els->count() === 0) {
            throw new InvalidSignatureXml('No timestamp found in signature');
        }
        return Utils::stripBr($els->item(0)->textContent);
    }

    public function getSignerCertificate(): string
    {
        return Utils::stripBr($this->doc->getElementsByTagName('X509Certificate')->item(0)->textContent);
    }

    public function getSignedPropSignerDigestAlg(): DigestAlg
    {
        $digestUrl = $this->doc->getElementsByTagName('SigningCertificate')->item(0)->getElementsByTagName('DigestMethod')->item(0)->getAttribute('Algorithm');
        $digestAlg = DigestAlg::fromUrl($digestUrl);
        if (!$digestAlg) {
            throw new InvalidSignatureXml("Unknown signature digest method: $digestUrl");
        }
        return $digestAlg;
    }

    public function getSignedPropSignerDigest(): string
    {
        return Utils::stripBr($this->doc->getElementsByTagName('SigningCertificate')->item(0)->getElementsByTagName('DigestValue')->item(0)->textContent);
    }

    public function getSignerSerialNumber(): string
    {
        return Utils::stripBr($this->doc->getElementsByTagName('SigningCertificate')->item(0)->getElementsByTagName('X509SerialNumber')->item(0)->textContent);
    }


    public function getSigningTime(): DateTimeImmutable
    {
        $timeStr = $this->doc->getElementsByTagName('SignedSignatureProperties')->item(0)->getElementsByTagName('SigningTime')->item(0)->textContent;
        return DateTimeImmutable::createFromFormat(DateTimeImmutable::RFC3339, $timeStr);
    }

    /**
     * Used by TSA
     */
    public function getSignatureValueCanonicalized(): string
    {
        $method = $this->getSignatureValueCanonicalizationMethod();
        return $this->doc->getElementsByTagName('SignatureValue')->item(0)->C14N(
            $method->exclusive(),
            $method->withComments()
        );
    }

    public function getSignatureValue(): string
    {
        return Utils::stripBr($this->doc->getElementsByTagName('SignatureValue')->item(0)->textContent);
    }

    private function getSignatureValueCanonicalizationMethod(): CanonicalizationMethod
    {
        $ts = $this->doc->getElementsByTagName('SignatureTimeStamp')->item(0);
        $methodUrl = $ts?->getElementsByTagName('CanonicalizationMethod')->item(0)?->getAttribute('Algorithm');

        if ($methodUrl) {
            return CanonicalizationMethod::tryFromUrl($methodUrl);
        }
        return CanonicalizationMethod::INCLUSIVE_1_0;
    }

    private function getSignedInfoCanonicalizationMethod(): CanonicalizationMethod
    {
        $signedInfo = $this->doc->getElementsByTagName('SignedInfo')->item(0);
        $methodUrl = $signedInfo->getElementsByTagName('CanonicalizationMethod')->item(0)?->getAttribute('Algorithm');

        if ($methodUrl) {
            return CanonicalizationMethod::tryFromUrl($methodUrl);
        }
        return CanonicalizationMethod::INCLUSIVE_1_0;
    }

    public function getSignedInfoCanonicalized(bool $stripWhitespace = true): string
    {
        $method = $this->getSignedInfoCanonicalizationMethod();
        $si = $this->getClonedDoc()->getElementsByTagName('SignedInfo')->item(0);

        if ($stripWhitespace) {
            $this->stripWhitespaceNodes($si);
        }

        return $si->C14N(
            $method->exclusive(),
            $method->withComments(),
        );
    }

    public function getSignedInfoSignMethod(): SignAlg
    {
        $signedInfo = $this->doc->getElementsByTagName('SignedInfo')->item(0);
        $signUrl = $signedInfo->getElementsByTagName('SignatureMethod')->item(0)->getAttribute('Algorithm');

        $method = SignAlg::tryFrom($signUrl);
        if (!$method) {
            throw new InvalidSignatureXml("Unknown signature method: $signUrl");
        }
        return $method;
    }

    public function getSignedPropertiesCanonicalized(bool $stripWhitespace = true): string
    {
        $method = $this->getSignedPropertiesCanonicalizationMethod();
        $sp = $this->getClonedDoc()->getElementsByTagName('SignedProperties')->item(0);

        if ($stripWhitespace) {
            $this->stripWhitespaceNodes($sp);
        }

        return $sp->C14N(
            $method?->exclusive(),
            $method?->withComments(),
        );
    }

    public function getSignedPropertiesDigest(): string
    {
        $ref = $this->getSignedPropertiesRef();
        return Utils::stripBr($ref->getElementsByTagName('DigestValue')->item(0)->textContent);
    }

    public function getSignedPropertiesDigestMethod(): DigestAlg
    {
        $ref = $this->getSignedPropertiesRef();
        $digestUrl = $ref->getElementsByTagName('DigestMethod')->item(0)->getAttribute('Algorithm');

        $digest = DigestAlg::fromUrl($digestUrl);
        if (!$digest) {
            throw new InvalidSignatureXml("Unknown digest method: $digestUrl");
        }
        return $digest;
    }

    /**
     * @return array base64 encoded certificates
     */
    public function getEncapsulatedCertificates(): array
    {
        $encapsulatedCerts = $this->doc->getElementsByTagName('EncapsulatedX509Certificate');
        $certificates = [];
        foreach ($encapsulatedCerts->getIterator() as $encapCert) {
            $certificates[] = Utils::stripBr($encapCert->textContent);
        }
        return $certificates;
    }

    private function getSignedPropertiesCanonicalizationMethod(): CanonicalizationMethod
    {
        $ref = $this->getSignedPropertiesRef();
        $url = $ref->getElementsByTagName('Transform')->item(0)?->getAttribute('Algorithm');

        if ($url) {
            return CanonicalizationMethod::tryFromUrl($url);
        }
        return CanonicalizationMethod::INCLUSIVE_1_0;
    }

    private function getSignedPropertiesRef(): DOMElement|null
    {
        $references = $this->doc->getElementsByTagName('Reference');
        foreach ($references->getIterator() as $ref) {
            if (str_contains($ref->getAttribute('Type'), 'SignedProperties')) {
                return $ref;
            }
        }
        return null;
    }

    private function getClonedDoc()
    {
        return $this->doc->cloneNode(true);
    }

    /**
     * @return array<string, array{0: DigestAlg, 1: string}>
     */
    public function getFileDigestMethods(): array
    {
        $references = ($this->doc->getElementsByTagName('Reference'));
        $fileList = [];
        foreach ($references->getIterator() as $ref) {
            if (str_contains($ref->getAttribute('Type'), 'SignedProperties')) {
                continue;
            }
            $digestMethodUrl = $ref->getElementsByTagName('DigestMethod')->item(0)->getAttribute('Algorithm');
            $digest = Utils::stripBr($ref->getElementsByTagName('DigestValue')->item(0)->textContent);
            $digestAlg = DigestAlg::fromUrl($digestMethodUrl);

            $fileName = urldecode($ref->getAttribute('URI'));
            $fileList[$fileName] = [$digestAlg, $digest];
        }

        return $fileList;
    }

    public function toXml(): string
    {
        return $this->doc->saveXML();
    }

    private function createBase()
    {
        $this->doc = new DOMDocument('1.0', 'UTF-8');
        $this->doc->preserveWhiteSpace = true;
        $this->doc->formatOutput = false;

        $root = $this->doc->createElementNS(self::NS_ASIC, 'asic:XAdESSignatures');
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', self::NS_DS);
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xades', self::NS_XADES);
        $this->doc->appendChild($root);

        $signature = $this->doc->createElementNS(self::NS_DS, 'ds:Signature');
        $signature->setAttribute('Id', $this->id);
        $signature->setIdAttribute('Id', true);
        $root->appendChild($signature);
    }

    /**
     *
     * @param string $signerCertificate base64 encoded
     * @param string $numOfFiles number of datafiles in container
     * @param array{City: string|null, StateOrProvince: string|null, PostalCode: int|string|null, CountryName: string|null} $productionPlace
     * @param array<int, string> $signerRoles
     */
    public function createSignedProperties(string $signerCertificate, int $numOfFiles, array $productionPlace = [], array $signerRoles = []): DOMElement
    {
        if ($this->doc->getElementsByTagName('Object')->count() > 0) {
            throw new \RuntimeException('Signed properties already created');
        }

        $signingTime = new DateTime();
        $signerCert = openssl_x509_parse($signerCertificate);
        if ($signerCert === false) {
            throw new InvalidCertificateException('Invalid certificate, is it in base64 format?', $signerCertificate);
        }

        $obj = $this->doc->createElementNS(self::NS_DS, 'ds:Object');
        $this->doc->firstChild->firstChild->appendChild($obj);

        $qp = $this->doc->createElementNS(self::NS_XADES, 'xades:QualifyingProperties');
        $qp->setAttribute('Target', '#' . $this->id);
        $obj->appendChild($qp);

        $sp = $this->doc->createElementNS(self::NS_XADES, 'xades:SignedProperties');
        $sp->setAttribute('Id', $this->id . '-SignedProperties');
        $sp->setIdAttribute('Id', true);
        $qp->appendChild($sp);

        $ssp = $this->doc->createElementNS(self::NS_XADES, 'xades:SignedSignatureProperties');
        $sp->appendChild($ssp);

        $ssp->appendChild($this->doc->createElementNS(self::NS_XADES, 'xades:SigningTime', $signingTime->format('Y-m-d\TH:i:s\Z')));

        $sc = $this->doc->createElementNS(self::NS_XADES, 'xades:SigningCertificate');
        $ssp->appendChild($sc);

        $cert = $this->doc->createElementNS(self::NS_XADES, 'xades:Cert');
        $sc->appendChild($cert);

        $certDigest = $this->doc->createElementNS(self::NS_XADES, 'xades:CertDigest');
        $cert->appendChild($certDigest);

        $certDm = $this->doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $certDm->setAttribute('Algorithm', DigestAlg::SHA256->getUrl());
        $certDigest->appendChild($certDm);

        $der = base64_decode(Utils::stripPemHeaders($signerCertificate));
        $hash = base64_encode(hash(DigestAlg::SHA256->value, $der, true));
        $certDigest->appendChild($this->doc->createElementNS(self::NS_DS, 'ds:DigestValue', $hash));

        $issuerDN = $this->reverseIssuerDn($signerCert['issuer']);
        $issSerial = $this->doc->createElementNS(self::NS_XADES, 'xades:IssuerSerial');
        $cert->appendChild($issSerial);

        $issuerName = $this->doc->createElementNS(self::NS_DS, 'ds:X509IssuerName', $issuerDN);
        $issSerial->appendChild($issuerName);

        $serialNum = $this->doc->createElementNS(self::NS_DS, 'ds:X509SerialNumber', Utils::serialToNumber($signerCert['serialNumber']));
        $issSerial->appendChild($serialNum);

        $spp = $this->doc->createElementNS(self::NS_XADES, 'xades:SignatureProductionPlace');

        $isAnySet = false;
        foreach ($productionPlace as $key => $value) {
            if ($value !== null) {
                $element = $this->doc->createElementNS(self::NS_XADES, 'xades:' . $key, (string) $value);
                $spp->appendChild($element);
                $isAnySet = true;
            }
        }
        if ($isAnySet) {
            $ssp->appendChild($spp);
        }

        if (sizeof($signerRoles) > 0) {
            $sr = $this->doc->createElementNS(self::NS_XADES, 'xades:SignerRoleV2');
            $ssp->appendChild($sr);

            $csr = $this->doc->createElementNS(self::NS_XADES, 'xades:ClaimedRoles');
            $sr->appendChild($csr);

            foreach ($signerRoles as $role) {
                $roleEl = $this->doc->createElementNS(self::NS_XADES, 'xades:ClaimedRole', $role);
                $csr->appendChild($roleEl);
            }
        }

        $sdop = $this->doc->createElementNS(self::NS_XADES, 'xades:SignedDataObjectProperties');
        $sp->appendChild($sdop);

        for ($i = 0; $i < $numOfFiles; $i++) {
            $dof = $this->doc->createElementNS(self::NS_XADES, 'xades:DataObjectFormat');
            $dof->setAttribute('ObjectReference', '#' . $this->id . '-RefId' . $i);
            $sdop->appendChild($dof);

            $mime = $this->doc->createElementNS(self::NS_XADES, 'xades:MimeType', 'application/octet-stream');
            $dof->appendChild($mime);
        }
        return $sp;
    }

    /**
     * @param array<string, array{0: DigestAlg, 1: string}> $fileDigests
     */
    public function createSignedInfo(array $fileDigests, SignAlg $signAlg, DigestAlg $signedPropertiesDigestAlg)
    {
        if ($this->doc->getElementsByTagName('SignedInfo')->count() > 0) {
            throw new \RuntimeException('Signed info already created');
        }

        /** @var \DOMElement */
        $signature = $this->doc->firstChild->firstChild;
        $sp = $this->doc->getElementById($this->id . '-SignedProperties');

        $si = $this->doc->createElementNS(self::NS_DS, 'ds:SignedInfo');
        $signature->prepend($si);

        $cm = $this->doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $cm->setAttribute('Algorithm', CanonicalizationMethod::EXCLUSIVE_1_0->value);
        $si->append($cm);

        $sm = $this->doc->createElementNS(self::NS_DS, 'ds:SignatureMethod');
        $sm->setAttribute('Algorithm', $signAlg->value);
        $si->append($sm);

        $i = 0;
        foreach ($fileDigests as $name => $digest) {
            $ref = $this->doc->createElementNS(self::NS_DS, 'ds:Reference');
            $ref->setAttribute('Id', $this->id . '-RefId' . $i);
            $ref->setIdAttribute('Id', true);
            $ref->setAttribute('URI', rawurlencode($name));
            $si->append($ref);

            $dm = $this->doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
            $dm->setAttribute('Algorithm', $digest[0]->getUrl());
            $ref->append($dm);

            $dv = $this->doc->createElementNS(self::NS_DS, 'ds:DigestValue', $digest[1]);
            $ref->append($dv);
            $i++;
        }

        // Signed props ref
        $ref = $this->doc->createElementNS(self::NS_DS, 'ds:Reference');
        $ref->setAttribute('Id', $this->id . '-RefId' . $i);
        $ref->setIdAttribute('Id', true);
        $ref->setAttribute('Type', self::SIGNED_PROPS);
        $ref->setAttribute('URI', '#' . $this->id . '-SignedProperties');
        $si->append($ref);

        $transforms = $this->doc->createElementNS(self::NS_DS, 'ds:Transforms');
        $ref->append($transforms);

        $transform = $this->doc->createElementNS(self::NS_DS, 'ds:Transform');
        $transform->setAttribute('Algorithm', CanonicalizationMethod::EXCLUSIVE_1_0->value);
        $transforms->append($transform);

        $dm = $this->doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dm->setAttribute('Algorithm', $signedPropertiesDigestAlg->getUrl());
        $ref->append($dm);

        $signedPropDigestValue = base64_encode(hash($signedPropertiesDigestAlg->value, $sp->C14N(true), true));
        $dv = $this->doc->createElementNS(self::NS_DS, 'ds:DigestValue', $signedPropDigestValue);
        $ref->append($dv);

        return $si;
    }

    public function createSignatureAndSignerValues(string $signatureValue, string $signerCertificate)
    {
        $obj = $this->doc->getElementsByTagName('Object')->item(0);

        $sv = $this->doc->createElementNS(self::NS_DS, 'ds:SignatureValue', $signatureValue);
        $sv->setAttribute('Id', $this->id . '-SIG');
        $sv->setIdAttribute('Id', true);
        $obj->parentNode->insertBefore($sv, $obj);

        $keyInfo = $this->doc->createElementNS(self::NS_DS, 'ds:KeyInfo');
        $obj->parentNode->insertBefore($keyInfo, $obj);

        $x509Data = $this->doc->createElementNS(self::NS_DS, 'ds:X509Data');
        $keyInfo->appendChild($x509Data);

        $cert = $this->doc->createElementNS(self::NS_DS, 'ds:X509Certificate', Utils::stripPemHeaders($signerCertificate));
        $x509Data->appendChild($cert);
    }

    public function createUnsignedProperties(string $issuerCertificate, string $timestampToken, string $ocspToken)
    {
        $qp = $this->doc->getElementsByTagName('QualifyingProperties')->item(0);

        $up = $this->doc->createElementNS(self::NS_XADES, 'xades:UnsignedProperties');
        $qp->appendChild($up);

        $usp = $this->doc->createElementNS(self::NS_XADES, 'xades:UnsignedSignatureProperties');
        $up->appendChild($usp);

        $st = $this->doc->createElementNS(self::NS_XADES, 'xades:SignatureTimeStamp');
        $st->setAttribute('Id', $this->id . '-T0');
        $st->setIdAttribute('Id', true);
        $usp->appendChild($st);

        $cm = $this->doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $cm->setAttribute('Algorithm', CanonicalizationMethod::INCLUSIVE_1_0->value);
        $st->appendChild($cm);

        $ets = $this->doc->createElementNS(self::NS_XADES, 'xades:EncapsulatedTimeStamp', $timestampToken);
        $st->appendChild($ets);

        $cv = $this->doc->createElementNS(self::NS_XADES, 'xades:CertificateValues');
        $usp->appendChild($cv);

        $cc = $this->doc->createElementNS(self::NS_XADES, 'xades:EncapsulatedX509Certificate', $issuerCertificate);
        $cc->setAttribute('Id', $this->id . '-CA-CERT');
        $cc->setIdAttribute('Id', true);
        $cv->appendChild($cc);

        $rv = $this->doc->createElementNS(self::NS_XADES, 'xades:RevocationValues');
        $usp->appendChild($rv);

        $ocspv = $this->doc->createElementNS(self::NS_XADES, 'xades:OCSPValues');
        $rv->appendChild($ocspv);

        $eocspv = $this->doc->createElementNS(self::NS_XADES, 'xades:EncapsulatedOCSPValue', $ocspToken);
        $ocspv->appendChild($eocspv);
    }

    /**
     * @param array $issuer
     */
    private function reverseIssuerDn($issuer): string
    {
        $dn = [];
        foreach ($issuer as $key => $value) {
            $dn[] = $key . '=' . $value;
        }
        return implode(',', array_reverse($dn));
    }

    private function stripWhitespaceNodes(DOMNode $node)
    {
        if ($node->hasChildNodes()) {
            for ($i = $node->childNodes->length - 1; $i >= 0; $i--) {
                $child = $node->childNodes->item($i);
                if ($child->nodeType === XML_TEXT_NODE && trim($child->nodeValue) === '') {
                    $node->removeChild($child);
                } else {
                    $this->stripWhitespaceNodes($child);
                }
            }
        }
    }
}
