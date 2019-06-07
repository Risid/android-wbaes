package com.risid.cipherb;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import com.risid.wbaes.AES;
import com.risid.wbaes.State;
import com.risid.wbaes.generator.ExternalBijections;
import com.risid.wbaes.generator.Generator;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.Arrays;

import butterknife.BindView;

import static com.risid.wbaes.AESEncrypt.pkcs5PaddingBytes;
import static com.risid.wbaes.AESEncrypt.xor;
import static org.bouncycastle.pqc.math.linearalgebra.ByteUtils.toHexString;

public class MainActivity extends AppCompatActivity {

    @BindView(R.id.tv_test)
    TextView tvTest;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        InputStream is = null;


        AES AESenc = null;
        try {
            is = this.getResources().getAssets().open("aes-table");
            ObjectInputStream in = new ObjectInputStream(is);
            try {
                AESenc = (AES) in.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            byte[] bytes = new byte[is.available()];
            is.read(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


        byte[] content = "asdfkljasdlf;jwerfojasdflkasjdf;asdf".getBytes();

        byte[] iv =  { 0x32, 0x30, 0x31, 0x35, 0x30, 0x30, 0x32, 0x30, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};




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
        Toast.makeText(this, toHexString(enc), Toast.LENGTH_SHORT).show();
    }
}
