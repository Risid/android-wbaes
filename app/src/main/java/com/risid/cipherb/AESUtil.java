package com.risid.cipherb;

import android.content.Context;

import com.risid.wbaes.AES;
import com.risid.wbaes.State;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.Arrays;

import static android.content.Context.MODE_PRIVATE;
import static com.risid.wbaes.AESEncrypt.pkcs5PaddingBytes;
import static com.risid.wbaes.AESEncrypt.xor;

public class AESUtil {

    public static byte[] whiteBoxAESEncrypt(AES AESenc, byte[] content, byte[] iv){
        int diff = 16 - (content.length % 16);
        int cbcCounter = (content.length / 16 ) + 1;

        // 最后一组恰好16位
        if (content.length % 16 == 0){
            cbcCounter++;
        }
        byte paddingByte = pkcs5PaddingBytes[diff - 1];

        byte[] enc = new byte[cbcCounter * 16];

        // cbc分组
        byte[] enTemp;

        byte[] cbcTemp = iv.clone();
        for (int i = 0; i < cbcCounter; i++) {

            // 最后一组
            if (i == cbcCounter - 1){

                enTemp = new byte[16];
                for (int j = 0; j < 16; j++) {
                    if (j < 16-diff){
                        enTemp[j] = content[i*16+j];

                    }else {
                        enTemp[j] = paddingByte;
                    }
                }

            }else {
                enTemp = Arrays.copyOfRange(content, i*16, i*16 + 16);
            }


            byte[] ints = xor(enTemp, cbcTemp);

            State state  = new State(ints, true,  false);
            state.transpose();

            AESenc.crypt(state);

            cbcTemp = state.getStateCopy();


            System.arraycopy(cbcTemp, 0, enc, i * 16, 16);

        }
        return enc;
    }

    public static AES readAESTable(String fileName, Context context){
        FileInputStream is = null;

        AES AESenc = null;
        try {
            is = context.openFileInput(fileName);

            ObjectInputStream in = new ObjectInputStream(is);
            try {
                AESenc = (AES) in.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return AESenc;
    }


}
