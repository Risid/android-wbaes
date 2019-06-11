package com.risid.cipherb;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ContentUris;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.ScrollView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.jakewharton.rxbinding2.view.RxView;
import com.risid.wbaes.AES;
import com.trello.rxlifecycle3.components.RxActivity;

import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
import java.util.Objects;
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
import static com.risid.cipherb.FileUtil.readFile;
import static com.risid.cipherb.FileUtil.writeToFile;

public class EncryptFileActivity extends RxActivity {

    @BindView(R.id.toolbar)
    Toolbar toolbar;
    @BindView(R.id.bt_check_key)
    MaterialButton btCheckKey;
    @BindView(R.id.bt_encrypt)
    MaterialButton btEncrypt;
    @BindView(R.id.et_file_path)
    TextInputEditText etFilePath;
    @BindView(R.id.bt_choose_file)
    MaterialButton btChooseFile;
    @BindView(R.id.et_save_file)
    TextInputEditText etSaveFile;
    @BindView(R.id.et_iv)
    TextInputEditText etIv;
    @BindView(R.id.cb_iv_padding)
    CheckBox cbIvPadding;
    @BindView(R.id.sl_encrypt_string)
    ScrollView slEncryptString;

    SpUtil spUtil;
    AES aes;

    String path;

    int READ_WRITE_GRANT = 3;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypted_file);
        ButterKnife.bind(this);
        init();
        initView();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == Activity.RESULT_OK) {
            Uri uri = data.getData();
            if (uri != null && "file".equalsIgnoreCase(uri.getScheme())) {//使用第三方应用打开
                path = uri.getPath();
                etFilePath.setText(path);
                etSaveFile.setText(path+".enc");
                return;
            }
            path = getPath(this, uri);
            etFilePath.setText(path);

            etSaveFile.setText(path+".enc");
        }
    }

    private void initView() {

        toolbar.setNavigationOnClickListener(v -> finish());

        RxView.clicks(btChooseFile)
                .compose(bindToLifecycle())
                .throttleFirst(500, TimeUnit.MILLISECONDS)
                .subscribe(new Observer<Object>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(Object o) {
                        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                        //intent.setType(“image/*”);//选择图片
                        //intent.setType(“audio/*”); //选择音频
                        //intent.setType(“video/*”); //选择视频 （mp4 3gp 是android支持的视频格式）
                        //intent.setType(“video/*;image/*”);//同时选择视频和图片
                        intent.setType("*/*");//无类型限制
                        intent.addCategory(Intent.CATEGORY_OPENABLE);
                        startActivityForResult(intent, 1);
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });
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
                        Observable<String> encryptObservable = Observable.create((ObservableOnSubscribe<String>) emitter -> {


                            if (etFilePath.getText() == null || TextUtils.isEmpty(etFilePath.getText())){
                                emitter.onError(new Exception("请选择文件！"));
                                return;
                            }

                            emitter.onNext(encrypt());
                            emitter.onComplete();


                        }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread());


                        encryptObservable.subscribe(new Observer<String>() {
                            @Override
                            public void onSubscribe(Disposable d) {

                                btEncrypt.setVisibility(View.INVISIBLE);
                            }

                            @Override
                            public void onNext(String s) {

                                Snackbar.make(slEncryptString, s, Snackbar.LENGTH_LONG).show();

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

    }

    private String encrypt() {



        if (aes == null) {

            aes = readAESTable(getApplicationContext());
        }
        byte[] plainBytes;

        try {
            plainBytes = readFile(Objects.requireNonNull(etFilePath.getText()).toString().trim());
        } catch (IOException e) {

            e.printStackTrace();

            return "读文件失败";
        }






        if (etIv.getText() != null) {



            byte[] iv = ivSetter(etIv.getText().toString(), cbIvPadding.isChecked());

            byte[] cipherBytes = whiteBoxAESEncrypt(aes, plainBytes, iv);

            if (etSaveFile.getText() != null && !TextUtils.isEmpty(etSaveFile.getText())){
                try {
                    writeToFile(etSaveFile.getText().toString().trim(), cipherBytes);
                } catch (IOException e) {
                    e.printStackTrace();

                    return "写文件失败";
                }
                return "加密完成";
            }else {

                return "请填写保存目录";
            }

        }
        return "未知错误";




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


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED || ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {

                ActivityCompat.requestPermissions(this, new String[] {Manifest.permission.WRITE_EXTERNAL_STORAGE,Manifest.permission.READ_EXTERNAL_STORAGE}, READ_WRITE_GRANT);
            }
        }

        checkKey();



    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean readGranted = true, writeGranted = true;
        for (int i = 0, j = permissions.length; i < j; i++) {
            if (grantResults[i] != PackageManager.PERMISSION_GRANTED) {
                if (Manifest.permission.WRITE_EXTERNAL_STORAGE.equals(permissions[i])) {
                    writeGranted = false;
                } else if (Manifest.permission.READ_EXTERNAL_STORAGE.equals(permissions[i])) {
                    readGranted = false;
                }
            }
        }
        //权限回调
        if (requestCode == READ_WRITE_GRANT) {
            if (!writeGranted || !readGranted) {
                Snackbar.make(slEncryptString, "读写文件权限被拒绝!", Snackbar.LENGTH_SHORT).show();
            }
        }

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







    public String getRealPathFromURI(Uri contentUri) {
        String res = null;
        String[] proj = {MediaStore.Images.Media.DATA};
        Cursor cursor = getContentResolver().query(contentUri, proj, null, null, null);
        if (null != cursor && cursor.moveToFirst()) {
            ;
            int column_index = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
            res = cursor.getString(column_index);
            cursor.close();
        }
        return res;
    }


    public String getDataColumn(Context context, Uri uri, String selection,
                                String[] selectionArgs) {

        Cursor cursor = null;
        final String column = "_data";
        final String[] projection = {column};

        try {
            cursor = context.getContentResolver().query(uri, projection, selection, selectionArgs,
                    null);
            if (cursor != null && cursor.moveToFirst()) {
                final int column_index = cursor.getColumnIndexOrThrow(column);
                return cursor.getString(column_index);
            }
        } finally {
            if (cursor != null)
                cursor.close();
        }
        return null;
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is ExternalStorageProvider.
     */
    public boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is DownloadsProvider.
     */
    public boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is MediaProvider.
     */
    public boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    @SuppressLint("NewApi")
    public String getPath(final Context context, final Uri uri) {

        final boolean isKitKat = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;

        // DocumentProvider
        if (isKitKat && DocumentsContract.isDocumentUri(context, uri)) {
            // ExternalStorageProvider
            if (isExternalStorageDocument(uri)) {
                final String docId = DocumentsContract.getDocumentId(uri);
                final String[] split = docId.split(":");
                final String type = split[0];

                if ("primary".equalsIgnoreCase(type)) {
                    return Environment.getExternalStorageDirectory() + "/" + split[1];
                }
            }
            // DownloadsProvider
            else if (isDownloadsDocument(uri)) {

                final String id = DocumentsContract.getDocumentId(uri);
                final Uri contentUri = ContentUris.withAppendedId(
                        Uri.parse("content://downloads/public_downloads"), Long.valueOf(id));

                return getDataColumn(context, contentUri, null, null);
            }
            // MediaProvider
            else if (isMediaDocument(uri)) {
                final String docId = DocumentsContract.getDocumentId(uri);
                final String[] split = docId.split(":");
                final String type = split[0];

                Uri contentUri = null;
                if ("image".equals(type)) {
                    contentUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                } else if ("video".equals(type)) {
                    contentUri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                } else if ("audio".equals(type)) {
                    contentUri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
                }

                final String selection = "_id=?";
                final String[] selectionArgs = new String[]{split[1]};

                return getDataColumn(context, contentUri, selection, selectionArgs);
            }
        }
        // MediaStore (and general)
        else if ("content".equalsIgnoreCase(uri.getScheme())) {
            return getDataColumn(context, uri, null, null);
        }
        // File
        else if ("file".equalsIgnoreCase(uri.getScheme())) {
            return uri.getPath();
        }
        return null;
    }
}
