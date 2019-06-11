package com.risid.cipherb.activity;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Toast;

import androidx.appcompat.widget.Toolbar;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.jakewharton.rxbinding2.view.RxView;
import com.risid.cipherb.conf.ApiManager;
import com.risid.cipherb.R;
import com.risid.cipherb.bean.ResultBean;
import com.risid.cipherb.utils.SpUtil;
import com.trello.rxlifecycle3.components.RxActivity;

import java.util.concurrent.TimeUnit;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;

public class KeyManageActivity extends RxActivity {
    SpUtil spUtil;

    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.et_key)
    TextInputEditText etKey;
    @BindView(R.id.et_dev_key)
    TextInputEditText etDevKey;
    @BindView(R.id.et_token)
    EditText etToken;
    @BindView(R.id.bt_update_id)
    MaterialButton btUpdateId;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_key_manage);
        ButterKnife.bind(this);
        init();
        initView();
    }

    private void initView() {
        toolbar.setNavigationOnClickListener(v -> finish());
        toolbar.setTitleTextColor(Color.parseColor("#757575"));

        toolbar.setTitle(R.string.key_management);

        RxView.clicks(btUpdateId)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {

                        if (TextUtils.isEmpty(etKey.getText())){
                            Snackbar.make(slEncryptString, "请输入密钥", Snackbar.LENGTH_SHORT).show();
                            return;
                        }
                        if (TextUtils.isEmpty(etDevKey.getText())){
                            Snackbar.make(slEncryptString, "请输入开发者密钥", Snackbar.LENGTH_SHORT).show();
                            return;
                        }

                        if (etKey.getText() != null && etDevKey.getText() != null){

                            ApiManager.getInstence().getOrderApi(spUtil.getURL())
                                    .generateAES(spUtil.getID(), etKey.getText().toString(), etDevKey.getText().toString())
                                    .subscribeOn(Schedulers.io())
                                    .observeOn(AndroidSchedulers.mainThread())
                                    .compose(bindToLifecycle())
                                    .subscribe(new Observer<ResultBean>() {
                                        @Override
                                        public void onSubscribe(Disposable d) {
                                            btUpdateId.setVisibility(View.INVISIBLE);

                                        }

                                        @Override
                                        public void onNext(ResultBean resultBean) {
                                            if (resultBean.getCode() == 0){
                                                etToken.setText(resultBean.getToken());
                                                Snackbar.make(slEncryptString, "更新密钥成功", Snackbar.LENGTH_SHORT).show();

                                            }

                                        }

                                        @Override
                                        public void onError(Throwable e) {
                                            Snackbar.make(slEncryptString, e.getMessage(), Snackbar.LENGTH_SHORT).show();

                                            btUpdateId.setVisibility(View.VISIBLE);
                                        }

                                        @Override
                                        public void onComplete() {

                                            btUpdateId.setVisibility(View.VISIBLE);

                                        }
                                    });

                        }



                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });
    }

    private void init() {
        spUtil = new SpUtil(this);

        if (spUtil.getURL() == null || spUtil.getURL().equals("")) {
            Toast.makeText(this, this.getString(R.string.need_url_and_id), Toast.LENGTH_SHORT).show();
            Intent intent = new Intent();
            intent.setClass(getApplicationContext(), SettingsActivity.class);
            startActivity(intent);
            finish();
        }

    }
}
