package com.security.smithloader.common;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import com.security.smithloader.log.SmithAgentLogger;

public class JarUtil {
    private static String rsaPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0vhCohsfHoWzuEt+4aWdz38WXghq8VpjfEnAiiSjpr5uhJGSBkfJ6q6tuCct7mUku+penk5Rfh6X9prVQUzaG5YxPR8n3cfq3Vmy/ljlAxocrpabwroER1A3IdnjdjgqxQ1q+TEzGPVrsBl+qwyDmSO3En373DkJRXQTyTKs5sGhDplTxK+LV4K+y2TS6H5BHSDX2B4JRQZWb3LdSuxLT8tB6RrbQLmaRe83hOqFC3lX6I5Jw5msBOOcCRkuyNAtD79kiZVL1qNbUtBufrVsr+G4zDdvO0unmtGaewHc16O7HYFeQTHo+n3Juob0g0MfwIa0P7dsdIuvsZfl/+C3fAgMBAAECggEAE9wCdpIAp5W8I1idjmS+gkPnMSORjnoxZ+ldut25ShwKjKU0CeygaQwt1PRskFMicHAGc9pKZkjAW2OS7pWGG0JjrV5k+bRjaPutDUwTVGO7/HbCJhX2hp/3N7yUwTtXP2z4LoqxsOKS9/YnUtsH5WXEAmPIDptZfBktbvYvpjHle0Q3tKSFtHFOfYD8Sd1xgGzN38UkjT/DnuaFbDUzwbNJ4pzVAW5w9cmONGbdYM/7pdfCTlHNyhNIftVNXn9kgAHxrUxvW0SZOPRA70CLjl2j50+R4UepImD/uZ3OjspxHJPoVRBmSOfwKFDk+9GpNDWpO/q7nyCztXJbOU9xaQKBgQDEW1EnfLefTeR69SKzRfVXJjOqAjtxV2/nJKva8UAN8w7UIAKjGLJHnWDN4p8dP+yhnQ5oT75IzwGl+CYIHpjejmRhZXdv3bBWvoBYV50MImyN/naXfeiLyd7CA2mOFIXC60vVDq12NGp8HGYBTCxi70Atd44uq7c4InV66PoitQKBgQDrpJV9V5Q2IT5VImkwwlmrkkM2ycaUf8xRZ+9CK/19t+9FINOAdOsPexu/L/MDeNEx5ibBwAdRBUb7kctcpZptnEClF4s1+QH5lD9taKWFgQZowdEQvMra5NZr4bX3gdYTC27PwkL/lc5lep3zDQm/oGa58lFlfS0ssPHtoFGGwwKBgQCX6MXaNMSifFJ9RdT4uPDb4XQq3Ns8DpdGTbqfAfG6WQZp2fHwWBTlDr5ryh2rNV9OkQEqdjcSgQQXcOmLcpB17dd++k7yvqHEGlGVBwM69g7hs7Hv9brJGv45PwaUow/xArSCOn68akTPi/DmpBXa3JncExhuxu5SgWY+Fqwd2QKBgQDD9z2y3XCOi5rw5gsg16AHBT4MhEU3Hgjm8k6Rc0/+i0ba8G+z9oe9eh4bI18v1fvzSXmVy4LKKF9du2OqCragzT8djLTjD9BKpLUS4eI1YpXX7MdW6gqxe3mugij4SuujLvDaqq1ZLFZXIl/Uz1T6HgUQQqragf1dm1G20oq6TQKBgG9O5xOMuDC0gjDjJNvfKO+96Rp+aKDUTPjLlV/IvxQFIEmkY1bRWe9bLQ9Raiu4r22ccfYK169skteNqSqMmnUUejI5dwuMspY02Li9Jrqhkkx5u9urlLHZbGZB2Y1h8FgslOopevQusQj3uHNDKUw8kkQKjQPkwpxUcqujXQ0G";

    private static String readFileToString(String filePath) throws IOException {
        try {
            Path path = Paths.get(filePath);
            byte[] fileBytes = Files.readAllBytes(path);
            return new String(fileBytes, StandardCharsets.UTF_8);
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
        }

        return null;
    }

    private static byte[] base64StrTobyte(String base64Str) {
        return Base64.getDecoder().decode(base64Str);
    }

    // 将字节数组转换为私钥对象
    private static PrivateKey bytesToPrivateKey(byte[] privateKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] calculateMD5(String filePath) {
        try {
            // 创建MessageDigest对象，指定使用MD5算法
            MessageDigest md = MessageDigest.getInstance("MD5");

            Path path = Paths.get(filePath);
            byte[] fileBytes = Files.readAllBytes(path);

            byte[] hashBytes = md.digest(fileBytes);

            return hashBytes;
        } catch (NoSuchAlgorithmException | IOException e) {
            SmithAgentLogger.exception(e);
        }

        return null;
    }

   private static boolean checkSumisValid(byte[] checkhashbytes,String checksum) {
        try {
            byte[] hashbytes = base64StrTobyte(checksum);

            byte[] bytePriKey = base64StrTobyte(rsaPrivateKey);
            PrivateKey privateKey = bytesToPrivateKey(bytePriKey);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedHashBytes = cipher.doFinal(hashbytes);

            return Arrays.equals(checkhashbytes,decryptedHashBytes);
        }
        catch (Exception e) {
            SmithAgentLogger.exception(e);
        }

        return false;
    }

    public static boolean checkJarFile(String FilePath,String checksumStr) {
        try {
            byte[] hashbytes = calculateMD5(FilePath);
            if(hashbytes == null)  {
                return false;
            }

            return checkSumisValid(hashbytes,checksumStr);
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
        }

        return false;
    }
}