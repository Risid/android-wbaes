package com.risid.cipherb;

import android.content.Context;

import java.io.FileOutputStream;
import java.io.IOException;

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

}
