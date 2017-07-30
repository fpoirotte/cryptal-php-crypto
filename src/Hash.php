<?php

namespace fpoirotte\Cryptal\Plugins\PhpCrypto;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\AbstractHash;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Hash extends AbstractHash implements PluginInterface
{
    protected $context;
    protected static $supportedAlgos = null;

    public function __construct(HashEnum $algorithm)
    {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        $this->context = new \Crypto\Hash(static::$supportedAlgos["$algorithm"]);
    }

    public function __clone()
    {
        $this->context = clone $this->context;
    }

    protected static function checkSupport()
    {
        $supported  = array(
            (string) HashEnum::HASH_MD2()       => 'md2',
            (string) HashEnum::HASH_MD4()       => 'md4',
            (string) HashEnum::HASH_MD5()       => 'md5',
            (string) HashEnum::HASH_RIPEMD160() => 'ripemd160',
            (string) HashEnum::HASH_SHA1()      => 'sha1',
            (string) HashEnum::HASH_SHA224()    => 'sha224',
            (string) HashEnum::HASH_SHA256()    => 'sha256',
            (string) HashEnum::HASH_SHA384()    => 'sha384',
            (string) HashEnum::HASH_SHA512()    => 'sha512',
        );

        static::$supportedAlgos     = array_intersect($supported, \Crypto\Hash::getAlgorithms(false));
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
        foreach (static::$supportedAlgos as $algo => $algoConst) {
            $registry->addHash(
                __CLASS__,
                HashEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
