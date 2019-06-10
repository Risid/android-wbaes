package com.risid.cipherb;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Toast;

import androidx.appcompat.widget.Toolbar;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.jakewharton.rxbinding2.view.RxView;
import com.risid.wbaes.AES;
import com.trello.rxlifecycle3.components.RxActivity;

import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observable;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;
import okhttp3.ResponseBody;

import static com.risid.cipherb.AESUtil.readAESTable;
import static com.risid.cipherb.AESUtil.toHexString;
import static com.risid.cipherb.AESUtil.whiteBoxAESEncrypt;

public class EncryptStringActivity extends RxActivity {
    SpUtil spUtil;
    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.et_iv)
    TextInputEditText etIv;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;
    @BindView(R.id.et_plain_text)
    EditText etPlainText;
    @BindView(R.id.et_cipher_text)
    EditText etCipherText;
    @BindView(R.id.bt_check_key)
    MaterialButton btCheckKey;
    @BindView(R.id.bt_encrypt)
    MaterialButton btEncrypt;
    AES aes;
    @BindView(R.id.cb_byte_string)
    CheckBox cbByteString;
    @BindView(R.id.cb_iv_padding)
    CheckBox cbIvPadding;
    @BindView(R.id.cb_set_ascii)
    CheckBox cbSetAscii;
    @BindView(R.id.cb_to_base64)
    CheckBox cbToBase64;
    @BindView(R.id.bt_copy_cipher)
    MaterialButton btCopyCipher;

    byte[] result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt_string);
        ButterKnife.bind(this);


        init();
        initView();

    }

    private void initView() {
        RxView.clicks(btCheckKey)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                        btCheckKey.setEnabled(false);

                    }

                    @Override
                    public void onNext(Object o) {
                        checkKey();

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                        btCheckKey.setEnabled(true);
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

                            emitter.onNext(encrypt());
                            emitter.onComplete();


                        }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread());


                        encryptObservable.subscribe(new Observer<Byte[]>() {
                            @Override
                            public void onSubscribe(Disposable d) {

                                btEncrypt.setVisibility(View.INVISIBLE);
                            }

                            @Override
                            public void onNext(Byte[] bytes) {
                                if (bytes == null){
                                    Snackbar.make(slEncryptString, "请输入明文", Snackbar.LENGTH_SHORT).show();
                                }
                                result = ArrayUtils.toPrimitive(bytes);
                                Log.d("encrypted", toHexString(result));
                                etCipherText.setText(toHexString(result));

                            }

                            @Override
                            public void onError(Throwable e) {

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


        RxView.clicks(cbSetAscii)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {
                        if (cbSetAscii.isChecked()){
                            etCipherText.setText(new String(result));
                        }else {
                            etCipherText.setText(toHexString(result));
                        }


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
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {
                        if (cbToBase64.isChecked()){
                            cbSetAscii.setEnabled(false);
                            etCipherText.setText(Base64.encodeToString(result, Base64.DEFAULT));
                        }else {
                            cbSetAscii.setEnabled(true);
                            if (cbSetAscii.isChecked()){
                                etCipherText.setText(new String(result));
                            }else {
                                etCipherText.setText(toHexString(result));
                            }
                        }

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });

        RxView.clicks(btCopyCipher)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {

                        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                        String content;
                        if (cbToBase64.isChecked()){
                            content = Base64.encodeToString(result,Base64.DEFAULT);
                        }else {
                            if (cbSetAscii.isChecked()){
                                content = new String(result);
                            }else{
                                content = toHexString(result);
                            }
                        }

                        ClipData mClipData = ClipData.newPlainText("Cipher Text", content);
                        cm.setPrimaryClip(mClipData);

                        Snackbar.make(slEncryptString, "已将密文复制到剪贴板", Snackbar.LENGTH_SHORT).show();


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

        if (etPlainText.getText().length() == 0) {
            return null;
        }

        Calendar calendar = Calendar.getInstance(Locale.CHINA);

        if (aes == null) {

            aes = readAESTable(getApplicationContext());
        }

        SimpleDateFormat ivTime = new SimpleDateFormat("yyyyMMddHH", Locale.CHINA);
        byte[] plainBytes;

        if (cbByteString.isChecked()){
            plainBytes = Base64.decode(etPlainText.getText().toString(), Base64.DEFAULT);
        }else {
            plainBytes = etPlainText.getText().toString().getBytes();
        }



        byte[] iv = new byte[16];

        if (etIv.getText() != null) {
            String ivStr = etIv.getText().toString();

            if (etIv.length() == 16) {
                iv = ivStr.getBytes();
            } else {
                iv = new byte[16];
                if (ivStr.length() > 16) {
                    for (int i = 0; i < 16; i++) {
                        iv[i] = ivStr.getBytes()[i];
                    }
                } else {
                    for (int i = 0; i < ivStr.length(); i++) {
                        iv[i] = ivStr.getBytes()[i];
                    }
                    if(cbIvPadding.isChecked()){
                        String time = String.valueOf(ivTime.format(calendar.getTime()));

                        // 缺多少补多少
                        for (int i = 0; i < time.length() - ivStr.length(); i++) {
                            // 逆置
                            iv[ivStr.length() + i] = time.getBytes()[time.length() - 1 - i];
                        }
                    }

                }


            }


        }


        return ArrayUtils.toObject(whiteBoxAESEncrypt(aes, plainBytes, iv));



    }


    private void init() {
        spUtil = new SpUtil(this);

        if (spUtil.getURL() == null || spUtil.getURL().equals("")) {
            Toast.makeText(this, this.getString(R.string.need_url_and_id), Toast.LENGTH_SHORT).show();
            Intent intent = new Intent();
            intent.setClass(getApplicationContext(), SettingsActivity.class);
            startActivity(intent);
            finish();
            return;
        }

        if (spUtil.getIV() != null && !spUtil.getIV().equals("")) {
            etIv.setText(spUtil.getIV());
        }

        checkKey();

    }

    private void checkKey() {

        ApiManager.getInstence().getOrderApi(spUtil.getURL())
                .getTableMsg(spUtil.getID())
                .subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .compose(bindToLifecycle())
                .subscribe(new Observer<ResultBean>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                        Snackbar.make(slEncryptString, "检查密钥更新...", Snackbar.LENGTH_INDEFINITE)
                                .setAction("取消", v -> d.dispose()).show();
                        btCheckKey.setEnabled(false);
                    }

                    @Override
                    public void onNext(ResultBean resultBean) {

                        if (resultBean.getCode() == 0) {
                            if (spUtil.getToken().equals(resultBean.getToken())) {
                                Snackbar.make(slEncryptString, "密钥无需更新~", Snackbar.LENGTH_SHORT).show();
                            } else {
                                ApiManager.getInstence().getOrderApi(spUtil.getURL())
                                        .downloadAESTable(spUtil.getID())
                                        .subscribeOn(Schedulers.io())
                                        .observeOn(Schedulers.io())
                                        .compose(bindToLifecycle())
                                        .subscribe(new Observer<ResponseBody>() {
                                            @Override
                                            public void onSubscribe(Disposable d) {
                                                Snackbar.make(slEncryptString, "正在更新密钥", Snackbar.LENGTH_INDEFINITE)
                                                        .setAction("取消", v -> d.dispose()).show();
                                            }

                                            @Override
                                            public void onNext(ResponseBody responseBody) {
                                                try {

                                                    FileUtil.writeFile("aes-table", responseBody.bytes(), getApplicationContext());
                                                    aes = null;

                                                    Snackbar.make(slEncryptString, "更新完成！", Snackbar.LENGTH_SHORT).show();
                                                    spUtil.setToken(resultBean.getToken());
                                                } catch (IOException e) {
                                                    e.printStackTrace();
                                                    Snackbar.make(slEncryptString, e.toString(), Snackbar.LENGTH_SHORT).show();
                                                }

                                            }

                                            @Override
                                            public void onError(Throwable e) {

                                                Snackbar.make(slEncryptString, e.toString(), Snackbar.LENGTH_SHORT).show();

                                                btCheckKey.setEnabled(true);
                                            }

                                            @Override
                                            public void onComplete() {
                                                btCheckKey.setEnabled(true);
                                            }
                                        });


                            }

                        }

                    }

                    @Override
                    public void onError(Throwable e) {

                        Snackbar.make(slEncryptString, e.toString(), Snackbar.LENGTH_SHORT).show();
                    }

                    @Override
                    public void onComplete() {

                        btCheckKey.setEnabled(true);

                    }
                });
    }


}
