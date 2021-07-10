package com.security.example;

import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;

public class RaspExample {
    public static void main(String[] args) {
        for (int i = 0; i < 100; i++) {
            try {
                Thread.sleep(1000 * 10);

                processOperate();
                fileOperate();
                networkOperate();
                classLoaderOperate();
                // nativeOperate();

            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void processOperate() throws IOException {
        Process process = Runtime.getRuntime().exec("ls");

        InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);

        String line;

        while((line = bufferedReader.readLine()) != null){
            System.out.println(line);
        }
    }

    private static void classLoaderOperate() throws MalformedURLException {
        new URLClassLoader(new URL[]{
                new URL("https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/jackson-core-2.11.2.jar")},
                RaspExample.class.getClassLoader()
        );
    }

    private static void nativeOperate() {
        System.loadLibrary("instrument");
    }

    private static void networkOperate() throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.baidu.com"))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println(response.body());

        Socket socket = new Socket("www.baidu.com", 80);
        socket.close();

        DatagramPacket datagramPacket = new DatagramPacket(new byte[]{0}, 1, InetAddress.getByName("www.baidu.com"), 53);

        DatagramSocket datagramSocket = new DatagramSocket();

        datagramSocket.connect(InetAddress.getByName("www.baidu.com"), 53);
        datagramSocket.send(datagramPacket);

        datagramSocket.close();
    }

    private static void fileOperate() throws IOException {
        File file = new File("/tmp/test");

        if (!file.createNewFile()) {
            System.out.println("create failed");
        }

        FileOutputStream fileOutputStream = new FileOutputStream(file);

        fileOutputStream.write("hello".getBytes());
        fileOutputStream.close();

        FileInputStream fileInputStream = new FileInputStream(file);
        fileInputStream.close();

        File destFile = new File("/tmp/test_copy");

        if (!file.renameTo(destFile)) {
            System.out.println("rename failed");
        }

        if (!destFile.delete()) {
            System.out.println("delete failed");
        }

        System.out.println(Arrays.toString(new File("/tmp").list()));
    }
}
