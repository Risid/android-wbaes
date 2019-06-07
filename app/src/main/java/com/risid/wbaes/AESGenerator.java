package com.risid.wbaes;

import com.risid.wbaes.generator.ExternalBijections;
import com.risid.wbaes.generator.Generator;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class AESGenerator {

    public static void generate(byte[] key, String path){
        Generator gEnc = new Generator();

        ExternalBijections extc = new ExternalBijections();

        gEnc.generateExtEncoding(extc, Generator.WBAESGEN_EXTGEN_ID);
        gEnc.setUseIO04x04Identity(true);

        gEnc.setUseIO08x08Identity(true);
        gEnc.setUseMB08x08Identity(true);
        gEnc.setUseMB32x32Identity(true);


        gEnc.generate(true,  key, 16, extc);
        AES AESenc = gEnc.getAESi();

        try
        {
            FileOutputStream fileOut =
                    new FileOutputStream(path);
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(AESenc);
            out.close();
            fileOut.close();
        }catch(IOException i)
        {
            i.printStackTrace();
        }
    }
}
