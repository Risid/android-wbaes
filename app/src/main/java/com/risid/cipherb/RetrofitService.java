package com.risid.cipherb;



import io.reactivex.Observable;
import okhttp3.ResponseBody;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;
import retrofit2.http.Streaming;


public interface RetrofitService {



    /** 更新密钥 */
    @GET("tableMsg")
    Observable<ResultBean> getTableMsg(@Query("id") String id);

    /** 生成密钥 */
    @GET("generateAES")
    Observable<ResultBean> generateAES(@Query("id") String id, @Query("key") String key);

    /** 下载密钥 */
    @GET("downloadAESTable")
    @Streaming
    Observable<ResponseBody> downloadAESTable(@Query("id") String id);

}
