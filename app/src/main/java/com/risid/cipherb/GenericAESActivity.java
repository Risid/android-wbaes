package com.risid.cipherb;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.trello.rxlifecycle3.components.RxActivity;

public class GenericAESActivity extends RxActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_generic_aes);
    }
}
