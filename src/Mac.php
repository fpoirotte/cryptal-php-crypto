<?php

namespace fpoirotte\Cryptal\Plugins\PhpCrypto;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\AbstractMac;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

class Mac extends AbstractMac implements PluginInterface
{
    protected $context;
    protected static $supportedAlgos = null;

    public function __construct(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $nonce = ''
    ) {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedAlgos['mac']["$macAlgorithm"])) {
            throw new \InvalidArgumentException('Unsupported MAC algorithm');
        }

        if ($innerAlgorithm instanceof CipherEnum) {
            if (!isset(static::$supportedAlgos['crypto']["$innerAlgorithm"])) {
                throw new \InvalidArgumentException('Unsupported cipher algorithm');
            }
            $innerAlgo = static::$supportedAlgos['crypto']["$innerAlgorithm"];
        } elseif ($innerAlgorithm instanceof HashEnum) {
            if (!isset(static::$supportedAlgos['hash']["$innerAlgorithm"])) {
                throw new \InvalidArgumentException('Unsupported hashing algorithm');
            }
            $innerAlgo = static::$supportedAlgos['hash']["$innerAlgorithm"];
        } else {
            throw new \InvalidArgumentException('Unsupported inner algorithm');
        }

        $cls = static::$supportedAlgos['mac']["$macAlgorithm"];
        $this->context = new $cls($key, $innerAlgo);
    }

    protected static function checkSupport()
    {
        static::$supportedAlgos = array();

        // Supported cipher algorithms
        $ciphers        = array();
        $map            = array(
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
        );

        foreach (\Crypto\Cipher::getAlgorithms(false) as $method) {
            $cipher             = substr($method, 0, strrpos($method, '-'));
            $ciphers[$cipher]   = 1;
        }
        static::$supportedAlgos['crypto'] = array_flip(array_intersect_key($map, $ciphers));

        // Supported hash algorithms
        $supported = array(
            (string) HashEnum::HASH_MD2()       => 'md2',
            (string) HashEnum::HASH_MD4()       => 'md4',
            (string) HashEnum::HASH_MD5()       => 'md5',
            (string) HashEnum::HASH_RIPEMD160() => 'ripemd160',
            (string) HashEnum::HASH_SHA1()      => 'sha1',
            (string) HashEnum::HASH_SHA2_224()  => 'sha224',
            (string) HashEnum::HASH_SHA2_256()  => 'sha256',
            (string) HashEnum::HASH_SHA2_384()  => 'sha384',
            (string) HashEnum::HASH_SHA2_512()  => 'sha512',
        );
        static::$supportedAlgos['hash'] = array_intersect($supported, \Crypto\Hash::getAlgorithms(false));

        // Supported MAC algorithms
        // PHP-Crypto only supports HMAC & CMAC.
        // We map each algorithm directly to its class.
        static::$supportedAlgos['mac'] = array(
            (string) MacEnum::MAC_CMAC()    => '\\Crypto\\CMAC',
            (string) MacEnum::MAC_HMAC()    => '\\Crypto\\HMAC',
        );
    }

    protected function internalUpdate($data)
    {
        $this->context->update($data);
    }

    protected function internalFinalize()
    {
        return $this->context->digest();
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedAlgos['mac'] as $algo => $algoConst) {
            $registry->addMac(
                __CLASS__,
                MacEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
