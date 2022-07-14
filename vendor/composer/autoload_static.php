<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitd555c71948048b0b00a423a0d2411fa7
{
    public static $prefixLengthsPsr4 = array (
        'P' => 
        array (
            'Psr\\Http\\Message\\' => 17,
            'Psr\\Http\\Client\\' => 16,
        ),
        'O' => 
        array (
            'OnebiotApp\\' => 11,
        ),
        'J' => 
        array (
            'Jose\\Easy\\' => 10,
            'Jose\\Component\\Signature\\Algorithm\\' => 35,
            'Jose\\Component\\Signature\\' => 25,
            'Jose\\Component\\KeyManagement\\' => 29,
            'Jose\\Component\\Encryption\\' => 26,
            'Jose\\Component\\Core\\' => 20,
            'Jose\\Component\\Checker\\' => 23,
        ),
        'F' => 
        array (
            'FG\\' => 3,
        ),
        'B' => 
        array (
            'Brick\\Math\\' => 11,
            'Base64Url\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Psr\\Http\\Message\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/http-message/src',
            1 => __DIR__ . '/..' . '/psr/http-factory/src',
        ),
        'Psr\\Http\\Client\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/http-client/src',
        ),
        'OnebiotApp\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'Jose\\Easy\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-easy',
        ),
        'Jose\\Component\\Signature\\Algorithm\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-signature-algorithm-rsa',
        ),
        'Jose\\Component\\Signature\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-signature',
        ),
        'Jose\\Component\\KeyManagement\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-key-mgmt',
        ),
        'Jose\\Component\\Encryption\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-encryption',
        ),
        'Jose\\Component\\Core\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-core',
        ),
        'Jose\\Component\\Checker\\' => 
        array (
            0 => __DIR__ . '/..' . '/web-token/jwt-checker',
        ),
        'FG\\' => 
        array (
            0 => __DIR__ . '/..' . '/fgrosse/phpasn1/lib',
        ),
        'Brick\\Math\\' => 
        array (
            0 => __DIR__ . '/..' . '/brick/math/src',
        ),
        'Base64Url\\' => 
        array (
            0 => __DIR__ . '/..' . '/spomky-labs/base64url/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitd555c71948048b0b00a423a0d2411fa7::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitd555c71948048b0b00a423a0d2411fa7::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitd555c71948048b0b00a423a0d2411fa7::$classMap;

        }, null, ClassLoader::class);
    }
}