package com.security.smith.common;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import com.security.smith.log.SmithLogger;

public class RSAUtil {
    private static int decryLength = 256;
    private static String rsaPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0vhCohsfHoWzuEt+4aWdz38WXghq8VpjfEnAiiSjpr5uhJGSBkfJ6q6tuCct7mUku+penk5Rfh6X9prVQUzaG5YxPR8n3cfq3Vmy/ljlAxocrpabwroER1A3IdnjdjgqxQ1q+TEzGPVrsBl+qwyDmSO3En373DkJRXQTyTKs5sGhDplTxK+LV4K+y2TS6H5BHSDX2B4JRQZWb3LdSuxLT8tB6RrbQLmaRe83hOqFC3lX6I5Jw5msBOOcCRkuyNAtD79kiZVL1qNbUtBufrVsr+G4zDdvO0unmtGaewHc16O7HYFeQTHo+n3Juob0g0MfwIa0P7dsdIuvsZfl/+C3fAgMBAAECggEAE9wCdpIAp5W8I1idjmS+gkPnMSORjnoxZ+ldut25ShwKjKU0CeygaQwt1PRskFMicHAGc9pKZkjAW2OS7pWGG0JjrV5k+bRjaPutDUwTVGO7/HbCJhX2hp/3N7yUwTtXP2z4LoqxsOKS9/YnUtsH5WXEAmPIDptZfBktbvYvpjHle0Q3tKSFtHFOfYD8Sd1xgGzN38UkjT/DnuaFbDUzwbNJ4pzVAW5w9cmONGbdYM/7pdfCTlHNyhNIftVNXn9kgAHxrUxvW0SZOPRA70CLjl2j50+R4UepImD/uZ3OjspxHJPoVRBmSOfwKFDk+9GpNDWpO/q7nyCztXJbOU9xaQKBgQDEW1EnfLefTeR69SKzRfVXJjOqAjtxV2/nJKva8UAN8w7UIAKjGLJHnWDN4p8dP+yhnQ5oT75IzwGl+CYIHpjejmRhZXdv3bBWvoBYV50MImyN/naXfeiLyd7CA2mOFIXC60vVDq12NGp8HGYBTCxi70Atd44uq7c4InV66PoitQKBgQDrpJV9V5Q2IT5VImkwwlmrkkM2ycaUf8xRZ+9CK/19t+9FINOAdOsPexu/L/MDeNEx5ibBwAdRBUb7kctcpZptnEClF4s1+QH5lD9taKWFgQZowdEQvMra5NZr4bX3gdYTC27PwkL/lc5lep3zDQm/oGa58lFlfS0ssPHtoFGGwwKBgQCX6MXaNMSifFJ9RdT4uPDb4XQq3Ns8DpdGTbqfAfG6WQZp2fHwWBTlDr5ryh2rNV9OkQEqdjcSgQQXcOmLcpB17dd++k7yvqHEGlGVBwM69g7hs7Hv9brJGv45PwaUow/xArSCOn68akTPi/DmpBXa3JncExhuxu5SgWY+Fqwd2QKBgQDD9z2y3XCOi5rw5gsg16AHBT4MhEU3Hgjm8k6Rc0/+i0ba8G+z9oe9eh4bI18v1fvzSXmVy4LKKF9du2OqCragzT8djLTjD9BKpLUS4eI1YpXX7MdW6gqxe3mugij4SuujLvDaqq1ZLFZXIl/Uz1T6HgUQQqragf1dm1G20oq6TQKBgG9O5xOMuDC0gjDjJNvfKO+96Rp+aKDUTPjLlV/IvxQFIEmkY1bRWe9bLQ9Raiu4r22ccfYK169skteNqSqMmnUUejI5dwuMspY02Li9Jrqhkkx5u9urlLHZbGZB2Y1h8FgslOopevQusQj3uHNDKUw8kkQKjQPkwpxUcqujXQ0G";

    private static byte[] base64StrTobyte(String base64Str) {
        return Base64.getDecoder().decode(base64Str);
    }

    private static PrivateKey bytesToPrivateKey(byte[] privateKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    private static byte[] cipherDoFinal(Cipher cipher,byte[] input, int chunkSize) {
        if (input == null || input.length <= 0) {
            return null;
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int inputLength = input.length;
            int offset = 0;
            byte[] cache;
            while (offset < inputLength) {
                SmithLogger.logger.info("offset: "+ offset);
                int blockLength = Math.min(chunkSize, inputLength - offset);
                SmithLogger.logger.info("blockLength: "+ blockLength);
                cache = cipher.doFinal(input, offset, blockLength);
                if (out == null) {
                    SmithLogger.logger.info("output is null");
                    return null;
                }
                if (cache == null) {
                    SmithLogger.logger.info("cache is null");
                    return null;
                }
                out.write(cache);
                offset += blockLength;
            }
            byte[] output = out.toByteArray();
            out.close();
            return output;

        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return null;
    }

    private static byte[] decryptRSA(String base64PriKey, byte[] hashbytes) {
        try {
            if (hashbytes == null)  {
                SmithLogger.logger.info("hashbytes is null");
                return null;
            }
            byte[] encryptedData = base64StrTobyte(new String(hashbytes));
            byte[] bytePriKey = base64StrTobyte(rsaPrivateKey);
            PrivateKey privateKey = bytesToPrivateKey(bytePriKey);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes;
            if (encryptedData.length > decryLength) {
                decryptedBytes = cipherDoFinal(cipher, encryptedData, decryLength);
            } else {
                decryptedBytes = cipher.doFinal(encryptedData);
            }
            
            return decryptedBytes;
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return null;
    }

    public static byte[] decryptRSA(byte[] hashbytes) {
        return decryptRSA(rsaPrivateKey, hashbytes);
    }

}