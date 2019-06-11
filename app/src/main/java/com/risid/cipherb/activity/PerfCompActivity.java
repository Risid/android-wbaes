package com.risid.cipherb.activity;

import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.widget.Toolbar;

import com.google.android.material.button.MaterialButton;
import com.jakewharton.rxbinding2.view.RxView;
import com.risid.cipherb.utils.AESUtil;
import com.risid.cipherb.R;
import com.risid.cipherb.bean.TestBean;
import com.risid.wbaes.AES;
import com.trello.rxlifecycle3.components.RxActivity;

import java.text.DecimalFormat;
import java.util.concurrent.TimeUnit;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observable;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;

import static com.risid.cipherb.utils.AESUtil.readAESTable;

public class PerfCompActivity extends RxActivity {

    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.tv_generic_1)
    TextView tvGeneric1;
    @BindView(R.id.tv_generic_10)
    TextView tvGeneric10;
    @BindView(R.id.tv_generic_100)
    TextView tvGeneric100;
    @BindView(R.id.tv_wb_load)
    TextView tvWbLoad;
    @BindView(R.id.tv_wb_1)
    TextView tvWb1;
    @BindView(R.id.tv_wb_10)
    TextView tvWb10;
    @BindView(R.id.tv_wb_100)
    TextView tvWb100;
    @BindView(R.id.bt_encrypt)
    MaterialButton btEncrypt;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;

    private byte[] defaultIV = { 0x32, 0x30, 0x31, 0x35, 0x30, 0x30, 0x32, 0x30, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    private byte[] plainText = { 0x32, 0x30, 0x31, 0x35, 0x30, 0x30, 0x32, 0x30, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    private byte[] defaultKey = { 0x74, 0x79, 0x75, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DecimalFormat decimalFormat = new DecimalFormat("#.##");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_perf_comp);
        ButterKnife.bind(this);
        initView();
    }


    private long encryptTest(boolean isGeneric, int times){


        if (isGeneric){
            long begintime = System.nanoTime();
            for (int i = 0; i < times; i++) {
                AESUtil.genericEncrypt(plainText, defaultKey, defaultIV);
            }
            long endtime = System.nanoTime();;
            return endtime - begintime;
        }else {

            long begintime = System.nanoTime();
            AES aes = readAESTable(this);
            if (times == 0){

                long endtime = System.nanoTime();;
                return endtime - begintime;
            }
            for (int i = 0; i < times; i++) {
                AESUtil.whiteBoxAESEncrypt(aes, plainText, defaultIV);
            }

            long endtime = System.nanoTime();
            return endtime - begintime;
        }
    }

    private TestBean avgTest(boolean isGeneric, int times){
        TestBean testBean = new TestBean();
        testBean.setType(times);
        testBean.setId(isGeneric?0:1);
        long avgTime = 0;
        int avgCount;
        if (isGeneric){
            avgCount = 50;
        }else {
            avgCount = 5;
        }

        for (int i = 0; i < avgCount; i++) {
            avgTime += encryptTest(isGeneric, times);
        }
        testBean.setTime((float) (avgTime / avgCount)/1000000f);
        return testBean;

    }


    private void initView() {

        toolbar.setNavigationOnClickListener(v -> finish());
        toolbar.setTitleTextColor(Color.parseColor("#757575"));

        toolbar.setTitle(R.string.performance_comparison);

        RxView.clicks(btEncrypt)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {
                        Observable<TestBean> encryptObservable = Observable.create((ObservableOnSubscribe<TestBean>) emitter -> {
                            emitter.onNext(avgTest(true, 1));
                            emitter.onNext(avgTest(true, 10));
                            emitter.onNext(avgTest(true, 100));

                            emitter.onNext(avgTest(false, 0));
                            emitter.onNext(avgTest(false, 1));
                            emitter.onNext(avgTest(false, 10));
                            emitter.onNext(avgTest(false, 100));
                            emitter.onComplete();

                        }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread());
                        encryptObservable.subscribe(new Observer<TestBean>() {
                            @Override
                            public void onSubscribe(Disposable d) {
                                btEncrypt.setVisibility(View.INVISIBLE);
                            }

                            @Override
                            public void onNext(TestBean testBean) {
                                if (testBean.getId() == 0){

                                    switch (testBean.getType()){
                                        case 1:
                                            tvGeneric1.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_1), testBean.getTime()));
                                            break;
                                        case 10:

                                            tvGeneric10.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_10), testBean.getTime()));
                                            break;
                                        case 100:

                                            tvGeneric100.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_100), testBean.getTime()));
                                            break;
                                    }
                                }else if(testBean.getId() == 1){
                                    switch (testBean.getType()){
                                        case 0:
                                            tvWbLoad.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.load_aes_table), testBean.getTime()));
                                            break;
                                        case 1:
                                            tvWb1.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_1), testBean.getTime()));
                                            break;
                                        case 10:

                                            tvWb10.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_10), testBean.getTime()));
                                            break;
                                        case 100:
                                            tvWb100.setText(String.format(getApplication().getString(R.string.test_time_format), getString(R.string.times_100), testBean.getTime()));
                                            break;
                                    }
                                }

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


    }
}
