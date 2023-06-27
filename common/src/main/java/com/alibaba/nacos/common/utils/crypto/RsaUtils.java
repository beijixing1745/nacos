/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.common.utils.crypto;

import com.alibaba.nacos.common.codec.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Padding type。【RSA/ECB/PKCS1Padding】 Padding（default）and【RSA/ECB/NoPadding】padding 2 select.
 *
 * @author beijixing1745
 */
public class RsaUtils {
    /**
     * 1024 117 128
     * 2048 245 256
     * 4096 512 501
     * RSA MAX ENCRYPT BLOCK.
     */
    private static final int MAX_ENCRYPT_BLOCK_1024 = 501;

    private static final int MAX_ENCRYPT_BLOCK_2048 = 245;

    /**
     * RSA MAX DECRYPT BLOCK.
     */
    private static final int MAX_DECRYPT_BLOCK_1024 = 512;

    private static final int MAX_DECRYPT_BLOCK_2048 = 256;

    /**
     * get Key Pair.
     *
     * @return KeyPair
     */
    public static KeyPair getKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(4096);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * get Private Key.
     *
     * @param privateKey private Key
     * @return PrivateKey
     */
    public static PrivateKey getPrivateKey(String privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[]     decodedKey = Base64.decodeBase64(privateKey.getBytes());
            PKCS8EncodedKeySpec keySpec    = new PKCS8EncodedKeySpec(decodedKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * get Public Key.
     *
     * @param publicKey publicKey
     * @return PublicKey
     */
    public static PublicKey getPublicKey(String publicKey) {
        try {
            KeyFactory         keyFactory = KeyFactory.getInstance("RSA");
            byte[]             decodedKey = Base64.decodeBase64(publicKey.getBytes());
            X509EncodedKeySpec keySpec    = new X509EncodedKeySpec(decodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * RSA encrypt.
     *
     * @param data      encrypt data
     * @param publicKey public Key
     * @return String
     */
    public static String encrypt(String data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int                   inputLen = data.getBytes().length;
            ByteArrayOutputStream out      = new ByteArrayOutputStream();
            int                   offset   = 0;
            byte[]                cache;
            int                   i        = 0;

            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_ENCRYPT_BLOCK_1024) {
                    cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK_1024);
                } else {
                    cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_ENCRYPT_BLOCK_1024;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();

            return new String(Base64.decodeBase64(encryptedData));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * RSA decrypt.
     *
     * @param data       decrypt data
     * @param privateKey private Key
     * @return String
     */
    public static String decrypt(String data, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[]                dataBytes = Base64.decodeBase64(data.getBytes());
            int                   inputLen  = dataBytes.length;
            ByteArrayOutputStream out       = new ByteArrayOutputStream();
            int                   offset    = 0;
            byte[]                cache;
            int                   i         = 0;

            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_DECRYPT_BLOCK_1024) {
                    cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK_1024);
                } else {
                    cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_DECRYPT_BLOCK_1024;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();

            return new String(decryptedData, "UTF-8");
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * sign.
     *
     * @param data       sign data
     * @param privateKey private Key
     * @return String
     */
    public static String sign(String data, PrivateKey privateKey) {
        try {
            byte[]              keyBytes   = privateKey.getEncoded();
            PKCS8EncodedKeySpec keySpec    = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory          keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey key       = keyFactory.generatePrivate(keySpec);
            Signature  signature = Signature.getInstance("MD5withRSA");
            signature.initSign(key);
            signature.update(data.getBytes());
            return new String(Base64.decodeBase64(signature.sign()));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * verify.
     *
     * @param srcData   src Data
     * @param publicKey public Key
     * @param sign      sign
     * @return boolean
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) {
        try {
            byte[]             keyBytes   = publicKey.getEncoded();
            X509EncodedKeySpec keySpec    = new X509EncodedKeySpec(keyBytes);
            KeyFactory         keyFactory = KeyFactory.getInstance("RSA");
            PublicKey          key        = keyFactory.generatePublic(keySpec);
            Signature          signature  = Signature.getInstance("MD5withRSA");
            signature.initVerify(key);
            signature.update(srcData.getBytes());
            return signature.verify(Base64.decodeBase64(sign.getBytes()));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }
}
