package com.risid.cipherb.utils;

import android.content.Context;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static android.content.Context.MODE_PRIVATE;

public class FileUtil {

    public static void writeFile(String fileName, byte[] inputBytes, Context context) {
        try{

            FileOutputStream fout = context.openFileOutput(fileName, MODE_PRIVATE);

            fout.write(inputBytes);

            fout.close();
        }

        catch(Exception e){
            e.printStackTrace();
        }
    }

    public static File getFile(String filePath) {
        File dir = new File(filePath);
        if (!dir.getParentFile().exists()) {
            dir.getParentFile().mkdirs();
        }
        File file = new File(filePath);
        if (!file.exists()) {
            try {
                boolean flag = file.createNewFile();
                if (!flag) {
                    Log.e("创建文件失败","createNewFile 失败");
                }
            } catch (Exception e) {
                Log.e("创建文件失败",e.getMessage());
            }
        }
        return file;
    }




    public static void writeToFile(String filePath, byte[] buffer) throws IOException {
        File file = getFile(filePath);
        FileOutputStream fos;

        fos = new FileOutputStream(file);

        fos.write(buffer);
        fos.close();

    }
    public static byte[] readFile(String filePath) throws IOException {
        InputStream in;
        byte[] data = null;

        in = new FileInputStream(filePath);
        data = toByteArray(in);
        in.close();



        return data;
    }
    private static byte[] toByteArray(InputStream in) throws IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024 * 4];
        int n = 0;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }


}
