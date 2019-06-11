package com.risid.cipherb;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import com.jakewharton.rxbinding2.view.RxView;
import com.journeyapps.barcodescanner.CaptureActivity;
import com.trello.rxlifecycle3.components.RxActivity;

import org.apache.commons.lang3.ArrayUtils;

import java.util.concurrent.TimeUnit;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observable;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;

import static com.google.zxing.integration.android.IntentIntegrator.REQUEST_CODE;
import static com.risid.cipherb.AESUtil.genericDecrypt;
import static com.risid.cipherb.AESUtil.genericEncrypt;
import static com.risid.cipherb.AESUtil.ivSetter;
import static com.risid.cipherb.AESUtil.toByteArray;
import static com.risid.cipherb.AESUtil.toHexString;

public class GenericAESActivity extends RxActivity {

    SpUtil spUtil;


    byte[] cipher;


    byte[] plain;
    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.bt_encrypt)
    MaterialButton btEncrypt;
    @BindView(R.id.bt_decrypt)
    MaterialButton btDecrypt;
    @BindView(R.id.et_plain_text)
    EditText etPlainText;
    @BindView(R.id.cb_byte_string)
    CheckBox cbByteString;
    @BindView(R.id.et_key)
    TextInputEditText etKey;
    @BindView(R.id.cb_key_string)
    CheckBox cbKeyString;
    @BindView(R.id.et_iv)
    TextInputEditText etIv;
    @BindView(R.id.cb_iv_padding)
    CheckBox cbIvPadding;
    @BindView(R.id.et_cipher_text)
    EditText etCipherText;
    @BindView(R.id.cb_to_base64)
    CheckBox cbToBase64;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;
    @BindView(R.id.pb_decrypt)
    ProgressBar pbDecrypt;
    @BindView(R.id.tv_qrcode)
    TextView tvQrcode;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_generic_aes);
        ButterKnife.bind(this);
        init();
        initView();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE) {
            String scanResult = "";
            if (resultCode == RESULT_OK) {
                // 扫描得到二维码链接
                IntentResult intentResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
                if (intentResult != null) {
                    if (intentResult.getContents() != null) {
                        // ScanResult 为获取到的字符串
                        scanResult = intentResult.getContents();

                    }
                }
            }
            if (!scanResult.equals("")) {
                Toast.makeText(this, scanResult, Toast.LENGTH_SHORT).show();
                Log.d("qrcode", scanResult);
                etCipherText.setText(scanResult);
                cbToBase64.setChecked(false);
                decrypt();
            }

        }
    }
    private void initView() {



        toolbar.setNavigationOnClickListener(v -> finish());


        RxView.clicks(tvQrcode)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {

                        if (ContextCompat.checkSelfPermission(GenericAESActivity.this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                            ActivityCompat.requestPermissions(GenericAESActivity.this, new String[]{Manifest.permission.CAMERA}, 1);
                        } else {
                            Intent intent = new Intent(GenericAESActivity.this, CaptureActivity.class);


                            startActivityForResult(intent, 0);
                        }

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });
        RxView.clicks(btEncrypt)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {

                        Observable<Byte[]> encryptObservable = Observable.create((ObservableOnSubscribe<Byte[]>) emitter -> {

                            if (etPlainText.getText() == null || TextUtils.isEmpty(etPlainText.getText())) {
                                emitter.onError(new Exception("请填写明文"));
                                return;
                            }
                            if (etKey.getText() == null || TextUtils.isEmpty(etKey.getText())) {
                                emitter.onError(new Exception("请填写密钥"));
                                return;
                            }
                            Byte[] bytes = encrypt();
                            if(bytes == null){
                                emitter.onError(new Exception("加密错误"));
                            }else {
                                emitter.onNext(bytes);
                            }
                            emitter.onComplete();


                        }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread());
                        encryptObservable.subscribe(new Observer<Byte[]>() {
                            @Override
                            public void onSubscribe(Disposable d) {

                                btEncrypt.setVisibility(View.INVISIBLE);
                            }

                            @Override
                            public void onNext(Byte[] bytes) {

                                cipher = ArrayUtils.toPrimitive(bytes);
                                Log.d("encrypted", toHexString(cipher));
                                if (cbToBase64.isChecked()) {
                                    etCipherText.setText(Base64.encodeToString(cipher, Base64.DEFAULT));
                                } else {
                                    etCipherText.setText(toHexString(cipher));
                                }

                            }

                            @Override
                            public void onError(Throwable e) {

                                btEncrypt.setVisibility(View.VISIBLE);
                                Snackbar.make(slEncryptString, e.getMessage(), Snackbar.LENGTH_SHORT).show();

                            }

                            @Override
                            public void onComplete() {

                                btEncrypt.setVisibility(View.VISIBLE);
                            }
                        });


                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });
        RxView.clicks(btDecrypt)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {

                        Observable<Byte[]> encryptObservable = Observable.create((ObservableOnSubscribe<Byte[]>) emitter -> {

                            if (etCipherText.getText() == null || TextUtils.isEmpty(etCipherText.getText())) {
                                emitter.onError(new Exception("请填写密文"));
                                return;
                            }
                            if (etKey.getText() == null || TextUtils.isEmpty(etKey.getText())) {
                                emitter.onError(new Exception("请填写密钥"));
                                return;
                            }
                            Byte[] bytes = decrypt();
                            if(bytes == null){
                                emitter.onError(new Exception("解密错误"));
                            }else {
                                emitter.onNext(bytes);
                            }
                            emitter.onComplete();


                        }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread());
                        encryptObservable.subscribe(new Observer<Byte[]>() {
                            @Override
                            public void onSubscribe(Disposable d) {

                                btDecrypt.setVisibility(View.INVISIBLE);
                            }

                            @Override
                            public void onNext(Byte[] bytes) {

                                plain = ArrayUtils.toPrimitive(bytes);
                                Log.d("decrypted", toHexString(plain));
                                if (!cbByteString.isChecked()) {
                                    etPlainText.setText(new String(plain));
                                } else {
                                    etPlainText.setText(toHexString(plain));
                                }
                            }

                            @Override
                            public void onError(Throwable e) {
                                btDecrypt.setVisibility(View.VISIBLE);

                                Snackbar.make(slEncryptString, e.getMessage(), Snackbar.LENGTH_SHORT).show();
                            }

                            @Override
                            public void onComplete() {

                                btDecrypt.setVisibility(View.VISIBLE);
                            }
                        });


                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });


        RxView.clicks(cbToBase64)
                .compose(bindToLifecycle())
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {
                        cbToBase64.setEnabled(false);
                        if (cbToBase64.isChecked() && cipher != null){

                            etCipherText.setText(Base64.encodeToString(cipher, Base64.DEFAULT));
                        }else {
                            etCipherText.setText(toHexString(cipher));

                        }

                        cbToBase64.setEnabled(true);
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });

    }

    private Byte[] encrypt() {



        byte[] plainBytes;

        if (cbByteString.isChecked()) {
            plainBytes = Base64.decode(etPlainText.getText().toString(), Base64.DEFAULT);
        } else {
            plainBytes = etPlainText.getText().toString().getBytes();
        }

        if (etIv.getText() != null) {


            byte[] iv = ivSetter(etIv.getText().toString(), cbIvPadding.isChecked());
            if (etKey.getText() != null) {
                byte[] key;
                if (cbKeyString.isChecked()) {
                    key = ivSetter(new String(toByteArray(etKey.getText().toString().trim())), false);
                } else {
                    key = ivSetter(etKey.getText().toString().trim(), false);
                }

                return ArrayUtils.toObject(genericEncrypt(plainBytes, key, iv));
            }

        }

        return null;
    }

    private Byte[] decrypt() {

        byte[] cipherBytes;

        if (cbToBase64.isChecked()) {
            cipherBytes = Base64.decode(etCipherText.getText().toString(), Base64.DEFAULT);
        } else {
            cipherBytes = toByteArray(etCipherText.getText().toString());
        }

        if (etIv.getText() != null && !etIv.getText().toString().trim().equals("")) {


            byte[] iv = ivSetter(etIv.getText().toString(), cbIvPadding.isChecked());
            if (etKey.getText() != null) {
                byte[] key;
                if (cbKeyString.isChecked()) {
                    key = ivSetter(new String(toByteArray(etKey.getText().toString().trim())), false);
                } else {
                    key = ivSetter(etKey.getText().toString().trim(), false);
                }

                return ArrayUtils.toObject(genericDecrypt(cipherBytes, key, iv));
            }

        }

        return null;

    }

    private void init() {

        spUtil = new SpUtil(this);

        if (spUtil.getIV() != null && !spUtil.getIV().equals("")) {
            etIv.setText(spUtil.getIV());
        }

    }
}
