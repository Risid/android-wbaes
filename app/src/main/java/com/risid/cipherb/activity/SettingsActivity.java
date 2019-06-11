package com.risid.cipherb.activity;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.LinearLayout;

import androidx.appcompat.widget.Toolbar;

import com.google.android.material.textfield.TextInputEditText;
import com.jakewharton.rxbinding2.widget.RxTextView;
import com.risid.cipherb.R;
import com.risid.cipherb.utils.SpUtil;
import com.trello.rxlifecycle3.components.RxActivity;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observer;
import io.reactivex.disposables.Disposable;

public class SettingsActivity extends RxActivity {

    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.et_url)
    TextInputEditText etUrl;
    @BindView(R.id.et_id)
    TextInputEditText etId;
    @BindView(R.id.et_token)
    TextInputEditText etToken;
    @BindView(R.id.et_iv)
    TextInputEditText etIv;
    @BindView(R.id.ll_settings_main)
    LinearLayout llSettingsMain;

    SpUtil spUtil;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        ButterKnife.bind(this);
        init();
        initView();
    }

    private void initView() {
        toolbar.setNavigationOnClickListener(v -> finish());


        toolbar.setTitleTextColor(Color.parseColor("#757575"));

        toolbar.setTitle(R.string.advanced_settings);
        getDataFromSp();

        RxTextView.textChanges(etUrl)
                .compose(bindToLifecycle())
                .subscribe(new Observer<CharSequence>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(CharSequence charSequence) {
                        spUtil.setURL(charSequence.toString());
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });

        RxTextView.textChanges(etId)
                .compose(bindToLifecycle())
                .subscribe(new Observer<CharSequence>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(CharSequence charSequence) {
                        spUtil.setID(charSequence.toString());
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });


        RxTextView.textChanges(etIv)
                .compose(bindToLifecycle())
                .subscribe(new Observer<CharSequence>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(CharSequence charSequence) {
                        spUtil.setIV(charSequence.toString());
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });

        RxTextView.textChanges(etToken)
                .compose(bindToLifecycle())
                .subscribe(new Observer<CharSequence>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(CharSequence charSequence) {
                        spUtil.setToken(charSequence.toString());
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });
    }

    private void getDataFromSp() {

        if (spUtil !=null) {
            etId.setText(spUtil.getID());

            etUrl.setText(spUtil.getURL());

            etToken.setText(spUtil.getToken());

            etIv.setText(spUtil.getIV());
        }

    }






    private void init() {
        spUtil = new SpUtil(this);

    }
}
