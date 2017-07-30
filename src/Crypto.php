<?php

namespace fpoirotte\Cryptal\Plugins\PhpCrypto;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Crypto implements CryptoInterface, PluginInterface
{
    protected $method;
    protected $padding;
    protected $aead;
    protected $cipher;
    protected $cipherObj;
    private $key;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers["$cipher"], static::$supportedModes["$mode"])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $method             = static::$supportedCiphers["$cipher"] . '-' . static::$supportedModes["$mode"];
        $this->padding      = $padding;
        $this->cipher       = $cipher;
        $this->key          = $key;
        $this->cipherObj    = new \Crypto\Cipher($method);

        $aeadModes  = array(
            \Crypto\Cipher::MODE_CCM,
            \Crypto\Cipher::MODE_GCM,
        );
        $this->aead = in_array($this->cipherObj->getMode(), $aeadModes);
        if ($this->aead) {
            $this->cipherObj->setTagLength($tagLength);
        }
    }

    protected static function checkSupport()
    {
        $modes          = array();
        $ciphers        = array();
        $map            = array(
            'modes'     => array(
                'cbc' => (string) ModeEnum::MODE_CBC(),
                'ccm' => (string) ModeEnum::MODE_CCM(),
                'cfb' => (string) ModeEnum::MODE_CFB(),
                'ctr' => (string) ModeEnum::MODE_CTR(),
                'ecb' => (string) ModeEnum::MODE_ECB(),
                'gcm' => (string) ModeEnum::MODE_GCM(),
                'ofb' => (string) ModeEnum::MODE_OFB(),
            ),
            'ciphers'   => array(
                'des-ede3'      => (string) CipherEnum::CIPHER_3DES(),
                'aes-128'       => (string) CipherEnum::CIPHER_AES_128(),
                'aes-192'       => (string) CipherEnum::CIPHER_AES_192(),
                'aes-256'       => (string) CipherEnum::CIPHER_AES_256(),
                'bf'            => (string) CipherEnum::CIPHER_BLOWFISH(),
                'camelia-128'   => (string) CipherEnum::CIPHER_CAMELIA_128(),
                'camelia-192'   => (string) CipherEnum::CIPHER_CAMELIA_192(),
                'camelia-256'   => (string) CipherEnum::CIPHER_CAMELIA_256(),
                'cast5'         => (string) CipherEnum::CIPHER_CAST5(),
                'des'           => (string) CipherEnum::CIPHER_DES(),
                'rc2'           => (string) CipherEnum::CIPHER_RC2(),
                'rc4'           => (string) CipherEnum::CIPHER_RC4(),
                'seed'          => (string) CipherEnum::CIPHER_SEED(),
            ),
        );

        foreach (\Crypto\Cipher::getAlgorithms(false) as $method) {
            $mode   = substr(strrchr($method, '-'), 1);
            $cipher = substr($method, 0, -(strlen($mode) + 1));

            $modes[$mode]       = 1;
            $ciphers[$cipher]   = 1;
        }

        static::$supportedModes     = array_flip(array_intersect_key($map['modes'], $modes));
        static::$supportedCiphers   = array_flip(array_intersect_key($map['ciphers'], $ciphers));
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $paddedData = $data . $this->padding->getPaddingData($blockSize, $missing);

        if ($this->aead) {
            $this->cipherObj->setAAD($aad);
            $res = $this->cipherObj->encrypt($paddedData, $this->key, $iv);
            $tag = $this->cipherObj->getTag();
            return $res;
        }
        $res = $this->cipherObj->encrypt($paddedData, $this->key, $iv);
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {

        if ($this->aead) {
            $this->cipherObj->setAAD($aad);
            $this->cipherObj->setTag($tag);
        }
        $res        = $this->cipherObj->decrypt($data, $this->key, $iv);
        $blockSize  = $this->getBlockSize();
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        return $this->cipherObj->getIVLength();
    }

    public function getBlockSize()
    {
        $res = $this->cipherObj->getBlockSize();
        return ($res <= 0) ? 1 : $res;
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedModes as $mode => $modeConst) {
            foreach (static::$supportedCiphers as $cipher => $cipherConst) {
                $registry->addCipher(
                    __CLASS__,
                    CipherEnum::$cipher(),
                    ModeEnum::$mode(),
                    ImplementationTypeEnum::TYPE_COMPILED()
                );
            }
        }
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
