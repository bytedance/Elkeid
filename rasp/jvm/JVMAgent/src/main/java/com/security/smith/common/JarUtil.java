package com.security.smith.common;

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

import com.security.smith.log.SmithAgentLogger;

public class JarUtil {
//    private static String rsaPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC48UkRzxXAHvphn5OJSLnFSDyNy76JFiZXUIofqRfCpJ+FfepxSLsLGhFC024DGoObg0aDBmXjwKbqva2qHgNYCXqEMdRyRRN0uwa2UtA9i5QTUhWRBwdwDAVKxAK6wSIbKMSrxRi8nMpqgg4koNeqf1vnE3naMkF9G2T6hVsmAK4//tLQWcg6+LhIMl2UM/SGBa2jkCWPLSHOH3tSIK8MurAXB1eJ/HwIB2yhaZj5/QAecGSV7OUedOGgHm4WwJ+fwvP35joRZ3NJJfUViRGtHSqRiGlq4i2YoiOtTTYMVRyJYZ9LoPCgCQfOyg4ILj935wOxW6CGad6Ii1na6KivAgMBAAECggEASPi3NoYplFkEvPEsUu41knBaqC4ce1WYgjoejbh3zg6LfK3+i31Bg/NgnSf0T9gt1nX5I+ip2i/hDF0UATv/YMS4qSFKLF4x+4xx7Q2G6cnBftAT/1mxJxYvHl1xoENlFCdFVmsZxA3vVhADyZMHFVhUKDxIh33t1hGxiaGFodvVUZrAhPvpWpEdPR6jGu+sbo1xyGRIgO6rE+Ntk/O26k93HXsn08Jdaw/Pt0DMvZpeGuOt7HqEEpc+7/OsXYQARkRmmOjsz3W3+m7+D5vLGGWc+mz8evUYtzk90gO05yzNDedQozD+KbjZosNRGwuqMAauzlnou2x9LqesQpmU2QKBgQDwl4+BxVkAoReMkaOOcrsLapjWr6iZMpQFHkRgNUtH9OMSOXpZQVqnyg2wjniXpU/zgyNbpBNvpZFF978+qJQFUZDLnBIO0im/vy8dWgqQnzHrX8xxqJubkaMm6SHaOK/vxN7ru3cUZ6unW2QS9/XYVE200EfzaO8MJBnJD55B1wKBgQDEyV3Yw+B/Tmq5Rrz7Cqeo6wPlX698RaNiHEBUQb40CxoivoQ0NwmyzjJqIDZXE28GArvQLmsfXFWRKWXZjPg4A+jHqr3hvEh5IdYCYXg6/W2pRdJfXQClD9ofyP2MD5U7yfT1EQ+HEBsr9Gk+e+Pxgoqc+aveXVFk5EElN7ek6QKBgCMsNRmmrT1PT68IN54Cnd+sZM21/nLvFv6sjxh1khzh6zRl3MIhsMwo2Nl/6pdY3pheCpRCJ2lCDjvpXTce1Az3ALETjvxFsz7KB2xGFpdP/q9HYQ8YtC8JGo38tSs+8FGgOWrDDESaZ1jfHoE7aOCIapfNf0dRhukCehaPxvYfAoGABT1bW1cz1g/vdYl1pLWO60d+rg/TK1rrU8Ruzg+GEfqtsnkiKgXBI1qsKvk6mSzyStWtzIg/3/Dkcl4I0TcYsN0hyJc6QRVzVI5bFWsk+WUgE17BkDp4tuxqIWiHn8AWeCYTeKcAo9cA8jWqy7gexKJ2MGHRerU/YpFVTrliEWkCgYEApDGsFB/aeErv+0uz0I2OkQJUS8pJcH7sef8zM3DLeho+/gS/nvFF5aNrqlErdFaWq1bpY1ju45S2CW1m7NdNg7iYypSx0o+ORCwuZ+ahHVLkxfS2AO1rfZhFyladMfmq8uO+U8AwaQ+t4qRLUNgoFdFd3jBKDcfIkD3+Muh7EMc=";
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
                System.out.println("calc "+FilePath+" fail");
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