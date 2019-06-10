package com.risid.cipherb;

import android.content.Context;

import com.risid.wbaes.AES;
import com.risid.wbaes.State;

import java.io.ByteArrayOutputStream;
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

    public static AES readAESTable(Context context){
        FileInputStream is = null;

        AES AESenc = null;
        try {
            is = context.openFileInput("aes-table");

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


    public static String toHexString(byte[] byteArray) {
        final StringBuilder hexString = new StringBuilder("");
        if (byteArray == null || byteArray.length <= 0)
            return null;
        for (int i = 0; i < byteArray.length; i++) {
            int v = byteArray[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                hexString.append(0);
            }
            hexString.append(hv);
//            hexString.append(" ");

        }
        return hexString.toString().toLowerCase();
    }

    public static byte[] toByteArray(String hexString) {
        hexString = hexString.toLowerCase();
        final byte[] byteArray = new byte[hexString.length() >> 1];
        int index = 0;
        for (int i = 0; i < hexString.length(); i++) {
            if (index  > hexString.length() - 1)
                return byteArray;
            byte highDit = (byte) (Character.digit(hexString.charAt(index), 16) & 0xFF);
            byte lowDit = (byte) (Character.digit(hexString.charAt(index + 1), 16) & 0xFF);
            byteArray[i] = (byte) (highDit << 4 | lowDit);
            index += 2;
        }
        return byteArray;
    }


}
