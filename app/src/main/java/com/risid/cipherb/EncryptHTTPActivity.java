package com.risid.cipherb;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.trello.rxlifecycle3.components.RxActivity;

public class EncryptHTTPActivity extends RxActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt_http);

    }
}
