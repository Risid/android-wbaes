package com.risid.cipherb;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.trello.rxlifecycle3.components.RxActivity;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends RxActivity {


    @BindView(R.id.main_toolbar)
    Toolbar toolbar;
    @BindView(R.id.ll_encrypt_string)
    LinearLayout llEncryptString;
    @BindView(R.id.ll_encrypt_file)
    LinearLayout llEncryptFile;
    @BindView(R.id.ll_encrypt_http)
    LinearLayout llEncryptHttp;
    @BindView(R.id.ll_encrypt_qrcode)
    LinearLayout llEncryptQrcode;
    @BindView(R.id.ll_key_distribution)
    LinearLayout llKeyDistribution;
    @BindView(R.id.ll_key_management)
    LinearLayout llKeyManagement;
    @BindView(R.id.ll_generic_aes)
    LinearLayout llGenericAes;
    @BindView(R.id.ll_performance_comparison)
    LinearLayout llPerformanceComparison;
    @BindView(R.id.ll_advanced_settings)
    LinearLayout llAdvancedSettings;
    @BindView(R.id.ll_info)
    LinearLayout llInfo;
    @BindView(R.id.gl_main)
    GridLayout glMain;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);

        toolbar.setTitleTextColor(getResources().getColor(R.color.colorAccent));

        toolbar.setTitle(R.string.wbaes_test);





    }


    @OnClick({R.id.ll_encrypt_string, R.id.ll_encrypt_file, R.id.ll_encrypt_http, R.id.ll_encrypt_qrcode, R.id.ll_key_distribution, R.id.ll_key_management, R.id.ll_generic_aes,
            R.id.ll_performance_comparison, R.id.ll_advanced_settings, R.id.ll_info})
    public void onViewClicked(View view) {
        Intent intent = new Intent();
        switch (view.getId()) {
            case R.id.ll_advanced_settings:
                intent.setClass(getApplicationContext(), SettingsActivity.class);
                break;
            case R.id.ll_performance_comparison:
                intent.setClass(getApplicationContext(), PerfCompActivity.class);
                break;
            case R.id.ll_encrypt_string:
                intent.setClass(getApplicationContext(), EncryptStringActivity.class);
                break;
            case R.id.ll_generic_aes:
                intent.setClass(getApplicationContext(), GenericAESActivity.class);
                break;
            case R.id.ll_encrypt_http:
                intent.setClass(getApplicationContext(), EncryptHTTPActivity.class);
                break;
            case R.id.ll_encrypt_file:
                intent.setClass(getApplicationContext(), EncryptedFileActivity.class);
                break;
            case R.id.ll_encrypt_qrcode:
                intent.setClass(getApplicationContext(), QrCodeActivity.class);
                break;
            default:
                Toast.makeText(this, "未实现！", Toast.LENGTH_SHORT).show();
                return;
        }
        startActivity(intent);
    }
}
