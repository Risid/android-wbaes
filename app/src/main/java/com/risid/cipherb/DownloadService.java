package com.risid.cipherb;

import io.reactivex.Observable;
import okhttp3.ResponseBody;
import retrofit2.Response;
import retrofit2.http.GET;
import retrofit2.http.Query;
import retrofit2.http.Streaming;

public interface DownloadService {


    /** 下载密钥 */
    @GET("downloadAESTable")
    @Streaming
    Observable<Response<ResponseBody>> downloadAESTable(@Query("id") String id);
}
