package com.risid.cipherb;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Message;
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

import cn.bertsir.zbar.QrConfig;
import cn.bertsir.zbar.QrManager;

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


    private QrConfig qrConfig;
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


    private void scan(QrConfig qrConfig) {

        QrManager.getInstance().init(qrConfig).startScan(GenericAESActivity.this, new QrManager.OnScanResultCallback() {
            @Override
            public void onScanSuccess(String scanResult) {

                Toast.makeText(GenericAESActivity.this, scanResult, Toast.LENGTH_SHORT).show();
                etCipherText.setText(scanResult);
                cbToBase64.setChecked(false);
                Byte[] bytes = decrypt();
                if (bytes != null){
                    plain = ArrayUtils.toPrimitive(bytes);
                    Log.d("decrypted", toHexString(plain));
                    if (!cbByteString.isChecked()) {
                        etPlainText.setText(new String(plain));
                    } else {
                        etPlainText.setText(toHexString(plain));
                    }
                }else {

                    Snackbar.make(slEncryptString, "解密错误", Snackbar.LENGTH_SHORT).show();
                }

            }
        });


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

                        if (etKey.getText() == null || TextUtils.isEmpty(etKey.getText())) {
                            Snackbar.make(slEncryptString, "请填写密钥", Snackbar.LENGTH_SHORT).show();
                            return;
                        }

                        // TODO 二维码
                        qrConfig = new QrConfig.Builder()
                                .setDesText("扫描白盒AES产生的密文二维码")//扫描框下文字
                                .setShowDes(true)//是否显示扫描框下面文字
                                .setShowLight(true)//显示手电筒按钮
                                .setShowTitle(true)//显示Title
                                .setCornerColor(Color.parseColor("#E57373"))//设置扫描框颜色
                                .setLineColor(Color.parseColor("#90CAF9"))//设置扫描线颜色
                                .setLineSpeed(QrConfig.LINE_MEDIUM)//设置扫描线速度
                                .setScanType(QrConfig.TYPE_QRCODE)//设置扫码类型（二维码，条形码，全部，自定义，默认为二维码）
                                .setScanViewType(QrConfig.SCANVIEW_TYPE_QRCODE)//设置扫描框类型（二维码还是条形码，默认为二维码）
                                .setCustombarcodeformat(QrConfig.BARCODE_EAN13)//此项只有在扫码类型为TYPE_CUSTOM时才有效
                                .setPlaySound(true)//是否扫描成功后bi~的声音
                                .setDingPath(R.raw.qrcode)//设置提示音(不设置为默认的Ding~)
                                .setIsOnlyCenter(true)//是否只识别框中内容(默认为全屏识别)
                                .setTitleText("扫描")//设置Tilte文字
                                .setTitleBackgroudColor(Color.parseColor("#FFFFFF"))//设置状态栏颜色
                                .setTitleTextColor(Color.parseColor("#E57373"))//设置Title文字颜色
                                .create();
                        scan(qrConfig);


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
