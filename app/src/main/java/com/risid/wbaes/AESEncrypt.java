package com.risid.wbaes;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;

public class AESEncrypt {
    public static byte[] pkcs5PaddingBytes = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    public static byte[] xor(byte[] a, byte[] b){

        byte[] tmp = new byte[16];
        for (int i = 0; i < 16; i++) {
            tmp[i] = (byte) (a[i] ^ b[i]);
        }
        return tmp;
    }

    public static byte[] encrypt(byte[] content, byte[] iv, String aesTablePath){
        AES AESenc;

        try
        {
            FileInputStream fileIn = new FileInputStream(aesTablePath);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            AESenc = (AES) in.readObject();
            in.close();
            fileIn.close();
        }catch(IOException i)
        {
            i.printStackTrace();
            return null;
        }catch(ClassNotFoundException c)
        {
            c.printStackTrace();
            return null;
        }
        int diff = 16 - content.length % 16;
        int cbcCounter = (content.length / 16 ) + 1;

        // 最后一组恰好16位
        if (diff == 0){
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


            for (int j = 0; j < 16; j++) {
                enc[i*16 + j] = cbcTemp[j];
            }

        }
        return enc;


    }

}
