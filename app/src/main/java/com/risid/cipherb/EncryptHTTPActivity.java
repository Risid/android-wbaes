package com.risid.cipherb;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Toast;

import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.jakewharton.rxbinding2.view.RxView;
import com.risid.wbaes.AES;
import com.trello.rxlifecycle3.components.RxActivity;

import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
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

import static com.risid.cipherb.AESUtil.ivSetter;
import static com.risid.cipherb.AESUtil.readAESTable;
import static com.risid.cipherb.AESUtil.toHexString;
import static com.risid.cipherb.AESUtil.whiteBoxAESEncrypt;

public class EncryptHTTPActivity extends RxActivity {

    SpUtil spUtil;
    AES aes;
    byte[] result;

    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.bt_check_key)
    MaterialButton btCheckKey;
    @BindView(R.id.bt_encrypt)
    MaterialButton btEncrypt;
    @BindView(R.id.et_plain_text)
    EditText etPlainText;
    @BindView(R.id.et_iv)
    TextInputEditText etIv;
    @BindView(R.id.cb_iv_padding)
    CheckBox cbIvPadding;
    @BindView(R.id.et_cipher_text)
    EditText etCipherText;
    @BindView(R.id.et_response)
    EditText etResponse;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt_http);
        ButterKnife.bind(this);
        init();
        initView();

    }

    private void initView() {

        toolbar.setNavigationOnClickListener(v -> finish());
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

                            if (etPlainText.getText() == null || TextUtils.isEmpty(etPlainText.getText())) {
                                emitter.onError(new Exception("请填写明文"));
                                return;
                            }

                            Byte[] bytes = encrypt();
                            if (bytes == null) {
                                emitter.onError(new Exception("加密错误"));
                            } else {
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
                                if (bytes == null) {
                                    Snackbar.make(slEncryptString, "请输入明文", Snackbar.LENGTH_SHORT).show();
                                }
                                result = ArrayUtils.toPrimitive(bytes);
                                Log.d("encrypted", toHexString(result));

                                String data = Base64.encodeToString(result, Base64.URL_SAFE);

                                etCipherText.setText(data);

                                ApiManager.getInstence().getOrderApi(spUtil.getURL())
                                        .encryptRequest(spUtil.getID(), data)
                                        .subscribeOn(Schedulers.io())
                                        .observeOn(AndroidSchedulers.mainThread())
                                        .compose(bindToLifecycle())
                                        .subscribe(new Observer<ResultBean>() {
                                            @Override
                                            public void onSubscribe(Disposable d) {

                                                Snackbar.make(slEncryptString, "加密请求中...", Snackbar.LENGTH_SHORT).show();
                                            }

                                            @Override
                                            public void onNext(ResultBean resultBean) {
                                                if (resultBean.getCode() != 0){
                                                    Snackbar.make(slEncryptString, resultBean.getMsg(), Snackbar.LENGTH_SHORT).show();
                                                }else {
                                                    etResponse.setText(resultBean.getMsg());
                                                    Snackbar.make(slEncryptString, "请求完成", Snackbar.LENGTH_SHORT).show();
                                                }
                                            }

                                            @Override
                                            public void onError(Throwable e) {
                                                Snackbar.make(slEncryptString, e.getMessage(), Snackbar.LENGTH_SHORT).show();

                                                btEncrypt.setVisibility(View.VISIBLE);
                                            }

                                            @Override
                                            public void onComplete() {
                                                btEncrypt.setVisibility(View.VISIBLE);
                                            }
                                        });



                            }

                            @Override
                            public void onError(Throwable e) {
                                btEncrypt.setVisibility(View.VISIBLE);
                                Snackbar.make(slEncryptString, e.getMessage(), Snackbar.LENGTH_SHORT).show();

                            }

                            @Override
                            public void onComplete() {

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
    }

    private Byte[] encrypt() {

        if (TextUtils.isEmpty(etPlainText.getText())) {
            return null;
        }

        if (aes == null) {

            aes = readAESTable(getApplicationContext());
        }

        byte[] plainBytes;

        plainBytes = etPlainText.getText().toString().getBytes();

        if (etIv.getText() != null) {


            byte[] iv = ivSetter(etIv.getText().toString(), cbIvPadding.isChecked());

            return ArrayUtils.toObject(whiteBoxAESEncrypt(aes, plainBytes, iv));


        } else {
            return null;
        }


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
                        btCheckKey.setEnabled(true);
                        Snackbar.make(slEncryptString, e.toString(), Snackbar.LENGTH_SHORT).show();
                    }

                    @Override
                    public void onComplete() {

                        btCheckKey.setEnabled(true);

                    }
                });
    }


}
